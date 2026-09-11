"""Smoke against real pyright / typescript-language-server on a tmp file (skipped when not installed)."""

import shutil

import pytest

from scanner.adapter.index import build_index


@pytest.mark.skipif(shutil.which("pyright-langserver") is None, reason="pyright not installed")
def test_pyright_on_tmp_file(tmp_path):
    (tmp_path / "app.py").write_text("class Api:\n    def login(self, user):\n        return user\n\n\ndef main():\n    Api().login('x')\n")
    ix = build_index(tmp_path)
    try:
        assert ix.find_symbol("Api.login") == ("app.py", 2)
        assert ix.definition_range("Api.login")[1:] == (2, 3)
        assert any(line == 7 for _, line, _ in ix.references("login"))
        assert ix.indexes["python"].primary.failed is False
    finally:
        ix.close()


@pytest.mark.skipif(shutil.which("typescript-language-server") is None, reason="typescript-language-server not installed")
def test_tsserver_on_tmp_files(tmp_path):
    (tmp_path / "a.ts").write_text("export function handler(x: string) {\n  return x;\n}\n\nhandler('a');\n")
    (tmp_path / "b.js").write_text("function ping(host) {\n  return host;\n}\nping('h');\n")
    ix = build_index(tmp_path)
    try:
        assert ix.find_symbol("handler") == ("a.ts", 1) and ix.find_symbol("ping") == ("b.js", 1)
        assert any(line == 5 for f, line, _ in ix.references("handler") if f == "a.ts")
        assert ix.indexes["typescript"].primary.failed is False and ix.indexes["javascript"].primary.failed is False
    finally:
        ix.close()
