"""Call hierarchy on the Index port: callers / callees / path_to_entry — fake client, grep fallback, tools,
closure containers, and real servers (skipped when missing)."""

import shutil
from pathlib import Path

import pytest

from scanner.adapter.index import GrepIndex, build_index
from scanner.adapter.index.languages import LANGUAGES
from scanner.adapter.index.lsp import LspIndex
from scanner.adapter.index.rpc import LspError
from tests.test_lsp_index import GO_SRC, FakeClient, _sym

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "03-govulnlab"


def _loc(root, line0, char0=0):
    return {"uri": (root / "main.go").as_uri(), "range": {"start": {"line": line0, "character": char0}, "end": {"line": line0, "character": char0 + 5}}}


class CallHierarchyClient(FakeClient):
    """login (line0 4) is called from pingHandler (line0 10); pingHandler calls login."""

    def initialize(self):
        self.calls.append("initialize")
        return {"capabilities": {"callHierarchyProvider": True}}

    def prepare_call_hierarchy(self, path, line0, char0):
        name = {4: "(*Server).login", 8: "pingHandler"}.get(line0)
        if name is None:
            return []
        return [{"name": name, "kind": 12, "uri": Path(path).as_uri(), "range": _loc(self.root, line0)["range"],
                 "selectionRange": _loc(self.root, line0, 5)["range"]}]

    def incoming_calls(self, item):
        if item["name"] == "(*Server).login":
            return [{"from": {"name": "pingHandler", "kind": 12, "uri": (self.root / "main.go").as_uri(),
                              "range": _loc(self.root, 8)["range"], "selectionRange": _loc(self.root, 8, 5)["range"]},
                     "fromRanges": [_loc(self.root, 10, 3)["range"]]}]
        return []

    def outgoing_calls(self, item):
        if item["name"] == "pingHandler":
            return [{"to": {"name": "(*Server).login", "kind": 6, "uri": (self.root / "main.go").as_uri(),
                            "range": _loc(self.root, 4)["range"], "selectionRange": _loc(self.root, 4, 17)["range"]},
                     "fromRanges": [_loc(self.root, 10, 3)["range"]]}]
        return []


class NoHierarchyClient(FakeClient):
    """A server that advertises nothing and rejects the method: must degrade to the references approximation."""

    def prepare_call_hierarchy(self, path, line0, char0):
        raise LspError("textDocument/prepareCallHierarchy: Unhandled method")


def _target(tmp_path):
    (tmp_path / "main.go").write_text(GO_SRC)
    (tmp_path / "go.mod").write_text("module x\n\ngo 1.22\n")
    return tmp_path


def test_lsp_callers_callees_path(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda *_: "/bin/true")
    ix = LspIndex(_target(tmp_path), LANGUAGES["go"], client_factory=CallHierarchyClient)
    assert ix.callers("login") == [("main.go", 11, "pingHandler")]
    assert ix.callees("pingHandler") == [("main.go", 5, "login")]
    assert ix.callers("nowhere") == [] and ix.callees("nowhere") == []
    assert ix.path_to_entry("login", ["pingHandler"]) == ["pingHandler", "login"]
    assert ix.path_to_entry("login", ["main"]) is None
    assert ix.path_to_entry("pingHandler", ["pingHandler"]) == ["pingHandler"]
    assert ix.failed is False
    ix.close()


def test_lsp_unsupported_call_hierarchy_falls_back_to_references(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda *_: "/bin/true")
    ix = LspIndex(_target(tmp_path), LANGUAGES["go"], client_factory=NoHierarchyClient)
    # references say line 11 is inside pingHandler (range 9..12) → caller resolved by enclosing symbol
    assert ix.callers("login") == [("main.go", 11, "pingHandler")]
    assert ix.failed is False  # an unsupported method never fails the language
    assert ix.callees("pingHandler") == [("main.go", 5, "login")]  # identifiers called in the body that are known symbols
    ix.close()


def test_grep_index_callers_callees(tmp_path):
    ix = GrepIndex(_target(tmp_path), (".go",))
    assert ix.callers("login") == [("main.go", 11, "pingHandler")]
    assert ix.callees("pingHandler") == [("main.go", 5, "login")]
    assert ix.path_to_entry("login", ["pingHandler"]) == ["pingHandler", "login"]
    assert ix.callers("nowhere") == [] and ix.path_to_entry("nowhere", ["main"]) is None


def test_multi_index_routes_call_hierarchy(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda *_: "/bin/true")
    ix = build_index(_target(tmp_path), client_factory=CallHierarchyClient)
    assert ix.callers("login") == [("main.go", 11, "pingHandler")]
    assert ix.callees("pingHandler") == [("main.go", 5, "login")]
    assert ix.path_to_entry("login", ["pingHandler"]) == ["pingHandler", "login"]
    ix.close()


def test_nested_function_container_is_the_enclosing_function(tmp_path, monkeypatch):
    class NestedClient(FakeClient):
        def document_symbols(self, path):
            closure = _sym("cb", 12, 5, 6)
            method = _sym("login", 6, 4, 7, children=[closure])
            return [_sym("Server", 5, 2, 8, children=[method])]

    monkeypatch.setattr("shutil.which", lambda *_: "/bin/true")
    ix = LspIndex(_target(tmp_path), LANGUAGES["go"], client_factory=NestedClient)
    by_name = {s.name: s for s in ix.symbols("main.go")}
    assert by_name["login"].container == "Server"
    assert by_name["cb"].container == "login"  # closure inside a method belongs to the method, not the class
    assert ix.find_symbol("login.cb") == ("main.go", 6)
    ix.close()


def test_lsp_tools_expose_call_hierarchy(tmp_path):
    from scanner.adapter import tools

    class Idx:
        def callers(self, fqn): return [("main.go", 11, "pingHandler")] if fqn == "login" else []
        def callees(self, fqn): return [("main.go", 5, "login")] if fqn == "pingHandler" else []
        def path_to_entry(self, fqn, entries, max_depth=6): return ["main", "pingHandler", "login"] if fqn == "login" else None
        def symbols(self, file): return []
        def definition_range(self, fqn): return None
        def references(self, fqn): return []
        def find_symbol(self, fqn): return None
        def has_symbol(self, fqn): return False
        def close(self): return None

    (tmp_path / "main.go").write_text("package main\n")
    t = {f.__name__: f for f in tools._lsp_tools(tmp_path, Idx(), entries_fn=lambda: ["main"])}
    assert {"lsp_callers", "lsp_callees", "lsp_path_to_entry"} <= set(t)
    assert t["lsp_callers"]("login")["callers"] == [{"file": "main.go", "line": 11, "symbol": "pingHandler"}]
    assert t["lsp_callees"]("pingHandler")["callees"] == [{"file": "main.go", "line": 5, "symbol": "login"}]
    assert t["lsp_path_to_entry"]("login") == {"symbol": "login", "entries": ["main"], "path": ["main", "pingHandler", "login"]}
    assert t["lsp_path_to_entry"]("nowhere")["path"] is None and "unreachable" in t["lsp_path_to_entry"].__doc__
    for name in ("verifier_tools", "critic_tools", "architect_tools"):
        names = {f.__name__ for f in getattr(tools, name)(None, tmp_path, index=Idx())}
        assert {"lsp_callers", "lsp_callees", "lsp_path_to_entry"} <= names, name


@pytest.mark.skipif(not (shutil.which("gopls") and shutil.which("go")), reason="gopls/go not installed")
def test_gopls_call_hierarchy():
    ix = build_index(SAMPLE)
    try:
        callers = ix.callers("searchHandler")
        assert any(f == "main.go" and 27 <= line <= 35 and name == "main" for f, line, name in callers), callers
        assert ix.path_to_entry("searchHandler", ["main"]) == ["main", "searchHandler"]
        assert any(name == "Query" for _, _, name in ix.callees("searchHandler")) or ix.callees("searchHandler") == []
        assert ix.indexes["go"].primary.failed is False
    finally:
        ix.close()


@pytest.mark.skipif(shutil.which("pyright-langserver") is None, reason="pyright not installed")
def test_pyright_callers_smoke(tmp_path):
    (tmp_path / "app.py").write_text("def login(user):\n    return user\n\n\ndef main():\n    login('x')\n")
    ix = build_index(tmp_path)
    try:
        assert ("app.py", 6, "main") in ix.callers("login")
        assert ix.path_to_entry("login", ["main"]) == ["main", "login"]
    finally:
        ix.close()


@pytest.mark.skipif(shutil.which("typescript-language-server") is None, reason="typescript-language-server not installed")
def test_tsserver_callers_smoke(tmp_path):
    (tmp_path / "a.ts").write_text("export function login(x: string) {\n  return x;\n}\n\nexport function main() {\n  login('a');\n}\n")
    ix = build_index(tmp_path)
    try:
        assert ("a.ts", 6, "main") in ix.callers("login")
        assert ix.path_to_entry("login", ["main"]) == ["main", "login"]
    finally:
        ix.close()
