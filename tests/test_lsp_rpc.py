"""LspClient: JSON-RPC framing over stdio against a fake server (no network, no real language server)."""

import sys

import pytest

from scanner.adapter.index.rpc import LspClient, LspError

# A minimal LSP-ish server: Content-Length frames on stdin/stdout, canned answers, one notification
# and one server→client request thrown in to prove the client skips/answers them.
FAKE_SERVER = r'''
import json, sys
def read():
    n = 0
    while True:
        line = sys.stdin.buffer.readline()
        if not line: return None
        if line.strip() == b"": break
        k, v = line.decode().split(":", 1)
        if k.strip().lower() == "content-length": n = int(v)
    return json.loads(sys.stdin.buffer.read(n))
def send(obj):
    b = json.dumps(obj).encode()
    sys.stdout.buffer.write(b"Content-Length: %d\r\n\r\n" % len(b) + b); sys.stdout.buffer.flush()
seen = []
while True:
    m = read()
    if m is None: break
    seen.append(m.get("method"))
    if m.get("method") == "initialize":
        send({"jsonrpc": "2.0", "method": "window/logMessage", "params": {"type": 3, "message": "hi"}})
        send({"jsonrpc": "2.0", "id": "srv-1", "method": "client/registerCapability", "params": {}})
        send({"jsonrpc": "2.0", "id": m["id"], "result": {"capabilities": {"definitionProvider": True}, "rootUri": m["params"]["rootUri"]}})
    elif m.get("method") == "textDocument/documentSymbol":
        send({"jsonrpc": "2.0", "id": m["id"], "result": [{"name": "Server", "kind": 23, "range": {"start": {"line": 0, "character": 0}, "end": {"line": 9, "character": 1}},
              "selectionRange": {"start": {"line": 0, "character": 5}, "end": {"line": 0, "character": 11}},
              "children": [{"name": "login", "kind": 6, "range": {"start": {"line": 2, "character": 0}, "end": {"line": 8, "character": 1}},
                            "selectionRange": {"start": {"line": 2, "character": 5}, "end": {"line": 2, "character": 10}}}]}]})
    elif m.get("method") == "textDocument/definition":
        send({"jsonrpc": "2.0", "id": m["id"], "result": {"uri": m["params"]["textDocument"]["uri"], "range": {"start": {"line": 2, "character": 5}, "end": {"line": 2, "character": 10}}}})
    elif m.get("method") == "textDocument/references":
        send({"jsonrpc": "2.0", "id": m["id"], "result": [{"uri": m["params"]["textDocument"]["uri"], "range": {"start": {"line": 12, "character": 4}, "end": {"line": 12, "character": 9}}}]})
    elif m.get("method") == "boom":
        send({"jsonrpc": "2.0", "id": m["id"], "error": {"code": -32601, "message": "no such method"}})
    elif m.get("method") == "shutdown":
        send({"jsonrpc": "2.0", "id": m["id"], "result": None})
    elif m.get("method") == "exit":
        send({"jsonrpc": "2.0", "method": "seen", "params": seen}); break
    elif "id" in m and "result" in m:
        pass  # our reply to the server→client request
'''


@pytest.fixture
def client(tmp_path):
    (tmp_path / "a.go").write_text("type Server struct{}\n\nfunc (s *Server) login() {}\n")
    c = LspClient([sys.executable, "-c", FAKE_SERVER], tmp_path, "go", timeout=10)
    c.start()
    yield c
    c.close()


def test_initialize_roundtrip_skips_notifications_and_answers_server_requests(client, tmp_path):
    res = client.initialize()
    assert res["capabilities"]["definitionProvider"] is True
    assert res["rootUri"].endswith(tmp_path.name)  # rootUri sent as a file URI of the target
    assert client._next_id == 2  # initialize took id 1; initialized/didOpen are notifications without ids


def test_document_symbols_definition_references(client, tmp_path):
    client.initialize()
    f = tmp_path / "a.go"
    client.did_open(f)
    syms = client.document_symbols(f)
    assert syms[0]["name"] == "Server" and syms[0]["children"][0]["name"] == "login"
    d = client.definition(f, 2, 5)
    assert d[0]["uri"].endswith("a.go") and d[0]["range"]["start"]["line"] == 2  # single Location normalised to a list
    r = client.references(f, 2, 5)
    assert r[0]["range"]["start"]["line"] == 12


def test_error_response_raises_and_close_kills(client):
    client.initialize()
    with pytest.raises(LspError):
        client.request("boom", {})
    client.close()
    assert client.proc.poll() is not None
    client.close()  # idempotent


def test_timeout_is_bounded(tmp_path):
    c = LspClient([sys.executable, "-c", "import time; time.sleep(30)"], tmp_path, "go", timeout=0.3)
    c.start()
    with pytest.raises(LspError):
        c.initialize()
    c.close()
