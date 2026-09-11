"""LspIndex: the Index port for ONE language, backed by a language server (lazy start on first call).

Symbol table from textDocument/documentSymbol (hierarchical); definition = the symbol's range,
references = textDocument/references at its selection position. Any failure (missing binary, server
error, flat SymbolInformation) marks the index failed and every method returns the "unknown" value —
the caller (MultiIndex) then falls back to grep.
"""

from __future__ import annotations

import logging
import os
import shutil
import threading
import time
from pathlib import Path
from urllib.parse import unquote, urlparse

from scanner.adapter.index.languages import Language
from scanner.adapter.index.rpc import LspClient, LspError
from scanner.core.ports import Symbol

log = logging.getLogger("scanner.lsp")

_KINDS = {5: "class", 6: "method", 12: "function", 23: "struct", 13: "variable", 14: "constant",
          11: "interface", 9: "constructor", 8: "field", 7: "property", 10: "enum", 2: "module"}
_CONTAINERS = {"class", "struct", "interface", "module", "enum"}


MAX_FILES = int(os.environ.get("INDEX_MAX_FILES", "3000"))
MAX_BYTES = int(os.environ.get("INDEX_MAX_BYTES", str(30 * 1024 * 1024)))


def _locked(fn):
    def wrapper(self, *a, **k):
        with self._lock:
            return fn(self, *a, **k)

    wrapper.__name__, wrapper.__doc__ = fn.__name__, fn.__doc__
    return wrapper


class LspIndex:
    def __init__(self, target: Path, language: Language, client_factory=LspClient, timeout: float = 60):
        self.target, self.language, self.timeout = Path(target).resolve(), language, timeout
        self._factory = client_factory
        self._client = None
        self.failed = False
        self._built = False
        self._by_key: dict[str, list[Symbol]] = {}
        self._by_file: dict[str, list[Symbol]] = {}
        self._pos: dict[int, tuple[int, int, int]] = {}  # id(sym) → (range start line, sel line0, sel char0)
        self._lines: dict[str, list[str]] = {}
        self._lock = threading.RLock()  # verifiers run tools in parallel threads; one server per language

    # --- port ------------------------------------------------------------------
    @_locked
    def find_symbol(self, fqn: str) -> tuple[str, int] | None:
        s = self._resolve(fqn)
        return (s.file, s.line) if s else None

    @_locked
    def has_symbol(self, fqn: str) -> bool:
        return self._resolve(fqn) is not None

    @_locked
    def definition_range(self, fqn: str) -> tuple[str, int, int] | None:
        s = self._resolve(fqn)
        return (s.file, self._pos[id(s)][0], s.end_line) if s else None

    @_locked
    def references(self, fqn: str) -> list[tuple[str, int, str]]:
        s = self._resolve(fqn)
        if s is None or self._client is None:
            return []
        _, line0, char0 = self._pos[id(s)]
        try:
            locs = self._client.references(self.target / s.file, line0, char0)
        except (LspError, OSError, ValueError) as e:  # ValueError: a desynced stream fails JSON decoding
            self._fail(f"references: {e}")
            return []
        out = []
        for loc in locs:
            rel = self._rel(loc["uri"])
            if rel is None:
                continue
            line = loc["range"]["start"]["line"] + 1
            out.append((rel, line, self._line(rel, line)))
        return sorted(set(out))

    @_locked
    def symbols(self, file: str) -> list[Symbol]:
        self._ensure()
        return list(self._by_file.get(file, []))

    @_locked
    def close(self) -> None:
        c, self._client = self._client, None
        if c is not None:
            c.close()

    # --- build -----------------------------------------------------------------
    def _ensure(self) -> None:
        if self._built or self.failed:
            return
        self._built = True
        missing = [b for b in (self.language.command[0], *self.language.requires) if shutil.which(b) is None]
        if missing:
            self._fail(f"{', '.join(missing)} not installed")
            return
        if self.language.preflight and (why := self.language.preflight(self.target)):
            self._fail(f"refused: {why}")
            return
        try:
            self._client = self._factory(list(self.language.command), self.target, self.language.lang_id, self.timeout)
            self._client.start()
            self._client.initialize()
            n = total = 0
            deadline = time.monotonic() + self.timeout * 4
            for f in self._files():
                n, total = n + 1, total + f.stat().st_size
                if n > MAX_FILES or total > MAX_BYTES or time.monotonic() > deadline:
                    raise RuntimeError(f"index budget exceeded ({n} files, {total} bytes) — grep fallback")
                self._client.did_open(f)
                rel = str(f.relative_to(self.target))
                self._collect(self._client.document_symbols(f), rel, "")
        except (LspError, OSError, RuntimeError, ValueError, KeyError, TypeError) as e:
            self._fail(str(e))

    def _fail(self, why: str) -> None:
        if not self.failed:
            log.warning("lsp %s: %s — falling back to grep", self.language.name, why)
        self.failed = True
        self.close()

    def _files(self):
        for root, dirs, files in os.walk(self.target):
            dirs[:] = [d for d in dirs if d not in self.language.skip_dirs]
            for f in sorted(files):
                if f.endswith(self.language.extensions):
                    yield Path(root) / f

    def _collect(self, syms: list[dict], rel: str, container: str) -> None:
        for d in syms:
            if "selectionRange" not in d:  # flat SymbolInformation: not enough to place definitions
                raise LspError("server returned flat SymbolInformation")
            raw = d.get("name", "")
            cont, name = _split(raw, container)
            kind = _KINDS.get(d.get("kind", 0), "symbol")
            rng, sel = d["range"], d["selectionRange"]["start"]
            sym = Symbol(name=name, kind=kind, file=rel, line=sel["line"] + 1, end_line=rng["end"]["line"] + 1, container=cont)
            self._pos[id(sym)] = (rng["start"]["line"] + 1, sel["line"], sel["character"])
            self._by_file.setdefault(rel, []).append(sym)
            for key in {name, f"{cont}.{name}" if cont else name}:
                self._by_key.setdefault(key, []).append(sym)
            self._collect(d.get("children") or [], rel, name if kind in _CONTAINERS else cont)

    def _resolve(self, fqn: str) -> Symbol | None:
        self._ensure()
        if self.failed:
            return None
        for key in self.language.normalize(fqn):
            if hits := self._by_key.get(key):
                return min(hits, key=lambda s: (s.file, s.line))  # ponytail: ambiguity → first by path
        return None

    def _rel(self, uri: str) -> str | None:
        p = Path(unquote(urlparse(uri).path)).resolve()
        try:
            return str(p.relative_to(self.target))
        except ValueError:
            return None  # stdlib / dependency location

    def _line(self, rel: str, line: int) -> str:
        if rel not in self._lines:
            try:
                self._lines[rel] = (self.target / rel).read_text(errors="replace").splitlines()
            except OSError:
                self._lines[rel] = []
        ls = self._lines[rel]
        return ls[line - 1] if 0 < line <= len(ls) else ""


def _split(raw: str, container: str) -> tuple[str, str]:
    """gopls spells methods "(*Server).login" / "Server.login"; nested symbols carry their parent."""
    s = raw.replace("(*", "").replace("(", "").replace(")", "")
    if "." in s:
        cont, name = s.rsplit(".", 1)
        return cont, name
    return container, s
