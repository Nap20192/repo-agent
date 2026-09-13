"""Untrusted-target guards of the index: symlink escapes, tsserver plugins, gopls toolchain env."""


from scanner.adapter import fs
from scanner.adapter.index.grep import GrepIndex
from scanner.adapter.index.languages import JAVASCRIPT, TYPESCRIPT, ts_plugins_declared
from scanner.adapter.index.lsp import LspIndex


def test_symlink_outside_target_is_invisible(tmp_path):
    (tmp_path / "secret.txt").write_text("root:x:0:0\n")
    t = tmp_path / "t"
    t.mkdir()
    (t / "ok.py").write_text("def root():\n    return 1\n")
    (t / "evil.py").symlink_to(tmp_path / "secret.txt")
    assert [p.name for p in fs.files(t)] == ["ok.py"]
    idx = GrepIndex(t)
    assert all(f == "ok.py" for f, _, _ in idx.references("root"))
    assert idx._lines("evil.py") == []  # even when asked directly


def test_tsserver_refused_when_tsconfig_declares_plugins(tmp_path):
    (tmp_path / "a.ts").write_text("export function f() {}\n")
    (tmp_path / "tsconfig.json").write_text('{"compilerOptions": {"plugins": [{"name": "./pwn"}]}}')
    assert "plugins" in (ts_plugins_declared(tmp_path) or "")

    def boom(*a, **k):
        raise AssertionError("server must not start")

    for lang in (TYPESCRIPT, JAVASCRIPT):
        idx = LspIndex(tmp_path, lang, client_factory=boom)
        assert idx.find_symbol("f") is None and idx.failed
