"""MultiIndex on a multi-language tree: per-language grep scope, LSP answers before grep-only languages."""

from pathlib import Path

from scanner.adapter.index import GrepIndex, MultiIndex, build_index
from scanner.adapter.index.languages import LANGUAGES
from tests.test_lsp_index import FakeClient


def _tree(tmp_path: Path) -> Path:
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / "main.go").write_text("package main\nfunc pingHandler() {}\n")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "index.php").write_text("<?php function pingHandler() {}\n")
    (tmp_path / "web" / "app.py").write_text("def ping():\n    pass\n")
    return tmp_path


def test_grep_fallback_is_scoped_to_its_language(tmp_path):
    t = _tree(tmp_path)
    php = GrepIndex(t, (".php",))
    assert php.find_symbol("pingHandler") == ("web/index.php", 1)
    assert php.find_symbol("ping") is None  # python symbol is not php's business
    assert all(f.endswith(".php") for f, _, _ in php.references("pingHandler"))


def test_lsp_language_answers_before_grep_only_language(tmp_path):
    t = _tree(tmp_path)
    idx = build_index(t, client_factory=FakeClient)  # FakeClient serves canned Go symbols incl. pingHandler
    assert isinstance(idx, MultiIndex) and set(idx.indexes) >= {"go", "php", "python"}
    assert idx.find_symbol("pingHandler")[0].endswith("main.go")  # go (LSP) before php (grep), despite sort order
    idx.close()


def test_unknown_language_only_grep(tmp_path):
    t = _tree(tmp_path)
    idx = build_index(t, languages={k: v for k, v in LANGUAGES.items() if k != "go"}, client_factory=FakeClient)
    assert isinstance(idx.indexes["go"], GrepIndex) and idx.indexes["go"].extensions == (".go",)
    idx.close()
