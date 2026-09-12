"""LspIndex / GrepIndex / MultiIndex against the Index port, with a fake LSP client (no servers)."""


from scanner.adapter.index import GrepIndex, MultiIndex, build_index
from scanner.adapter.index.languages import LANGUAGES
from scanner.adapter.index.lsp import LspIndex as _LspIndex
from scanner.core.ports import Index, Symbol
from tests.fakes import GO_SRC, BrokenClient, FakeClient, _sym  # noqa: F401


def _target(tmp_path):
    (tmp_path / "main.go").write_text(GO_SRC)
    (tmp_path / "go.mod").write_text("module x\n\ngo 1.22\n")
    return tmp_path


def test_lsp_index_resolves_methods_in_every_spelling(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda *_: "/bin/true")
    ix = _LspIndex(_target(tmp_path), LANGUAGES["go"], client_factory=FakeClient)
    assert isinstance(ix, Index)
    for spelling in ("login", "Server.login", "(*Server).login", "s.login", "main.Server.login"):
        assert ix.find_symbol(spelling) == ("main.go", 5), spelling
    assert ix.has_symbol("nowhere") is False and ix.find_symbol("pkg.nowhere") is None
    assert ix.definition_range("login") == ("main.go", 5, 7)
    assert ix.references("login") == [("main.go", 11, "\ts.login()")]
    assert [s.name for s in ix.symbols("main.go")] == ["Server", "login", "pingHandler"]
    login = ix.symbols("main.go")[1]
    assert (login.kind, login.container, login.line, login.end_line) == ("method", "Server", 5, 7)
    client = ix._client
    ix.close(); ix.close()
    assert client.calls[0] == "start" and client.calls[-1] == "close" and ("open", "main.go") in client.calls


def test_lsp_index_marks_failed_and_returns_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda *_: "/bin/true")
    ix = _LspIndex(_target(tmp_path), LANGUAGES["go"], client_factory=BrokenClient)
    assert ix.find_symbol("login") is None and ix.references("login") == [] and ix.symbols("main.go") == []
    assert ix.failed is True


def test_lsp_index_missing_binary_fails_without_starting(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda *_: None)
    ix = _LspIndex(_target(tmp_path), LANGUAGES["go"], client_factory=FakeClient)
    assert ix.has_symbol("login") is False and ix.failed is True


def test_grep_index(tmp_path):
    ix = GrepIndex(_target(tmp_path))
    assert ix.find_symbol("Server.login") == ("main.go", 5) and ix.has_symbol("pingHandler")
    assert ix.definition_range("login") == ("main.go", 5, 8)  # up to the line before the next top-level def
    assert ("main.go", 11, "\ts.login()") in ix.references("login")
    assert [s.name for s in ix.symbols("main.go")] == ["Server", "login", "pingHandler"]
    ix.close()


def test_multi_index_routes_and_falls_back(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda *_: "/bin/true")
    (tmp_path / "app.py").write_text("def handler():\n    pass\n")
    target = _target(tmp_path)
    ix = build_index(target, client_factory=BrokenClient)  # every LSP adapter fails → grep for both languages
    assert isinstance(ix, MultiIndex) and set(ix.indexes) == {"go", "python"}
    assert ix.find_symbol("pingHandler") == ("main.go", 9) and ix.find_symbol("handler") == ("app.py", 1)
    assert [s.name for s in ix.symbols("app.py")] == ["handler"]
    ix.close()
    ok = build_index(target, client_factory=FakeClient)
    assert ok.find_symbol("s.login") == ("main.go", 5) and ok.references("login")[0][1] == 11
    ok.close()


def test_languages_cover_required_set():
    assert {"go", "python", "typescript", "javascript"} <= set(LANGUAGES)
    assert LANGUAGES["javascript"].lang_id == "javascript" and LANGUAGES["typescript"].lang_id == "typescript"
    assert LANGUAGES["go"].normalize("(*Server).login")[0] == "Server.login"
    assert LANGUAGES["python"].normalize("pkg.mod.Class.method")[-1] == "method"
    assert Symbol(name="x", file="f", line=1).end_line == 0
