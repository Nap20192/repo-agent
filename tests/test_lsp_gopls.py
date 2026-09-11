"""Real gopls on samples/02-vulnshop (skipped without gopls/go)."""

import shutil
from pathlib import Path

import pytest

from scanner.adapter.index import build_index

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "02-vulnshop"
pytestmark = pytest.mark.skipif(not (shutil.which("gopls") and shutil.which("go")), reason="gopls/go not installed")


@pytest.fixture
def ix():
    index = build_index(SAMPLE)
    yield index
    index.close()


def test_gopls_symbols_definition_references(ix):
    assert ix.find_symbol("searchHandler") == ("main.go", 20)
    file, start, end = ix.definition_range("searchHandler")
    assert file == "main.go" and start == 20 and end >= 20
    refs = ix.references("pingHandler")
    assert any(f == "main.go" and 12 <= line <= 16 and "pingHandler" in text for f, line, text in refs)
    assert ix.indexes["go"].primary.failed is False  # gopls really answered, no grep fallback
