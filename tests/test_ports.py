"""Ports are honoured structurally: the fakes satisfy them, every index adapter is a full Index."""

from scanner.adapter.index import FallbackIndex, GrepIndex, MultiIndex, build_index
from scanner.adapter.index.languages import LANGUAGES
from scanner.adapter.index.lsp import LspIndex
from scanner.adapter.store import Store
from scanner.core.ports import Index, RunStore
from tests.fakes import GO_SRC, FakeClient, FakeRun


def test_fake_and_real_store_satisfy_run_store(tmp_path):
    assert isinstance(FakeRun(), RunStore)
    assert isinstance(Store(str(tmp_path / "s.db")).start_run("t"), RunStore)


def test_every_index_adapter_is_a_full_index(tmp_path):
    (tmp_path / "main.go").write_text(GO_SRC)
    (tmp_path / "go.mod").write_text("module x\n\ngo 1.22\n")
    grep, lsp = GrepIndex(tmp_path), LspIndex(tmp_path, LANGUAGES["go"], client_factory=FakeClient)
    multi = build_index(tmp_path, client_factory=FakeClient)
    for ix in (grep, lsp, FallbackIndex(lsp, grep), multi):
        assert isinstance(ix, Index), type(ix).__name__
    assert lsp.failed is False and grep.failed is False and isinstance(multi, MultiIndex)  # the fallback reads `failed`
    multi.close()
