"""Minimal LSP client: JSON-RPC 2.0 over a server's stdio (Content-Length framing), stdlib only.

Mirrors git-agent3's Go client: initialize (rootUri + workspaceFolders), initialized, didOpen before
any request, documentSymbol / definition / references, shutdown → exit → kill. Server notifications
are skipped; server→client requests get a null/empty reply so the server does not stall.
"""

from __future__ import annotations

import json
import logging
import os
import select
import shutil
import subprocess
import threading
import time
from pathlib import Path

log = logging.getLogger("scanner.lsp")


class LspError(Exception):
    """Server error response, protocol violation, timeout, or dead process."""


class LspClient:
    def __init__(self, cmd: list[str], root: Path, lang_id: str, timeout: float = 30):
        self.cmd, self.root, self.lang_id, self.timeout = cmd, Path(root).resolve(), lang_id, timeout
        self.proc: subprocess.Popen | None = None
        self._next_id = 1
        self._closed = False
        # one stdio pipe, many threads: ADK runs sync tools in a ThreadPoolExecutor while ParallelAgent fans out
        self._lock = threading.RLock()

    # --- process -----------------------------------------------------------------
    def start(self) -> None:
        if shutil.which(self.cmd[0]) is None:
            raise LspError(f"{self.cmd[0]} not installed")
        env = {**os.environ, "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOFLAGS": "-mod=mod"}  # never fetch/execute a go.mod toolchain
        self.proc = subprocess.Popen(
            self.cmd, cwd=self.root, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            bufsize=0, env=env,  # raw pipe: select() must see exactly what Python has not consumed yet
        )

    def close(self) -> None:
        """shutdown → exit → kill, best-effort; idempotent. `proc` stays inspectable after close."""
        with self._lock:
            p = self.proc
            if p is None or self._closed:
                return
            try:
                if p.poll() is None:
                    self._write({"jsonrpc": "2.0", "id": self._take_id(), "method": "shutdown"})
                    self._write({"jsonrpc": "2.0", "method": "exit"})
                    p.wait(timeout=2)
            except Exception as e:  # noqa: BLE001 — a hung server must not block the scan
                log.debug("lsp close: %s", e)
            finally:
                self._closed = True
                if p.poll() is None:
                    p.kill()
                    try:
                        p.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        log.warning("lsp close: %s did not die after kill", self.cmd[0])

    # --- protocol ----------------------------------------------------------------
    def initialize(self) -> dict:
        root = self.root.as_uri()
        result = self.request("initialize", {
            "processId": None, "rootUri": root, "rootPath": str(self.root),
            "workspaceFolders": [{"uri": root, "name": "target"}],
            "capabilities": {"textDocument": {"documentSymbol": {"hierarchicalDocumentSymbolSupport": True}}},
        })
        self.notify("initialized", {})
        return result if isinstance(result, dict) else {}

    def did_open(self, path: Path) -> None:
        path = Path(path)
        self.notify("textDocument/didOpen", {"textDocument": {
            "uri": path.as_uri(), "languageId": self.lang_id, "version": 1, "text": path.read_text(errors="replace")}})

    def document_symbols(self, path: Path) -> list[dict]:
        res = self.request("textDocument/documentSymbol", {"textDocument": {"uri": Path(path).as_uri()}})
        return res if isinstance(res, list) else []

    def definition(self, path: Path, line0: int, char0: int) -> list[dict]:
        return _locations(self.request("textDocument/definition", _pos(path, line0, char0)))

    def references(self, path: Path, line0: int, char0: int, include_declaration: bool = False) -> list[dict]:
        params = _pos(path, line0, char0) | {"context": {"includeDeclaration": include_declaration}}
        return _locations(self.request("textDocument/references", params))

    # --- rpc ---------------------------------------------------------------------
    def request(self, method: str, params: dict) -> object:
        with self._lock:  # write + read of one exchange is atomic across threads
            rid = self._take_id()
            self._write({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
            deadline = time.monotonic() + self.timeout
            while True:
                msg = self._read(deadline)
                if msg.get("id") == rid and "method" not in msg:
                    if "error" in msg:
                        raise LspError(f"{method}: {msg['error'].get('message', msg['error'])}")
                    return msg.get("result")
                if "method" in msg and "id" in msg:  # server → client request: answer so it does not stall
                    self._write({"jsonrpc": "2.0", "id": msg["id"], "result": _server_request_reply(msg)})
                # notifications (window/logMessage, publishDiagnostics…) and stale replies are skipped

    def notify(self, method: str, params: dict) -> None:
        with self._lock:
            self._write({"jsonrpc": "2.0", "method": method, "params": params})

    def _take_id(self) -> int:
        rid, self._next_id = self._next_id, self._next_id + 1
        return rid

    def _write(self, obj: dict) -> None:
        if self.proc is None or self.proc.stdin is None or self._closed:
            raise LspError("server not started")
        body = json.dumps(obj).encode()
        data = b"Content-Length: %d\r\n\r\n" % len(body) + body
        fd, deadline = self.proc.stdin.fileno(), time.monotonic() + self.timeout
        try:
            while data:  # bounded write: a server that stops reading must not hang the scan
                left = deadline - time.monotonic()
                if left <= 0 or not select.select([], [fd], [], left)[1]:
                    raise LspError("write timeout: server stopped reading")
                n = os.write(fd, data[:65536])
                data = data[n:]
        except (BrokenPipeError, OSError) as e:
            raise LspError(f"server died: {e}") from e

    def _read(self, deadline: float) -> dict:
        out = self.proc.stdout if self.proc and not self._closed else None
        if out is None:
            raise LspError("server not started")
        length = None
        while True:  # headers
            self._wait_readable(out, deadline)
            line = out.readline()
            if not line:
                raise LspError("server closed the stream")
            if line in (b"\r\n", b"\n"):
                break
            k, _, v = line.decode(errors="replace").partition(":")
            if k.strip().lower() == "content-length":
                length = int(v.strip())
        if length is None:
            raise LspError("missing Content-Length")
        body = b""
        while len(body) < length:  # raw reads may return short chunks
            self._wait_readable(out, deadline)
            chunk = out.read(length - len(body))
            if not chunk:
                raise LspError("truncated message")
            body += chunk
        return json.loads(body)

    def _wait_readable(self, out, deadline: float) -> None:
        # ponytail: select on the pipe bounds every read by the deadline; a partial line can still block briefly
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([out], [], [], remaining)[0]:
            raise LspError(f"timeout after {self.timeout}s waiting for {self.cmd[0]}")


def _pos(path: Path, line0: int, char0: int) -> dict:
    return {"textDocument": {"uri": Path(path).as_uri()}, "position": {"line": line0, "character": char0}}


def _locations(res: object) -> list[dict]:
    """Location | Location[] | LocationLink[] | null → [{uri, range}]."""
    items = res if isinstance(res, list) else [res] if isinstance(res, dict) else []
    out = []
    for it in items:
        if "targetUri" in it:  # LocationLink
            out.append({"uri": it["targetUri"], "range": it.get("targetSelectionRange") or it["targetRange"]})
        elif "uri" in it:
            out.append({"uri": it["uri"], "range": it["range"]})
    return out


def _server_request_reply(msg: dict) -> object:
    if msg["method"] == "workspace/configuration":
        return [None] * len(msg.get("params", {}).get("items", []))
    return None
