"""One server per language shared by parallel verifier threads: exchanges must not interleave."""

import threading

from scanner.adapter.index.languages import GO
from scanner.adapter.index.lsp import LspIndex
from tests.fakes import FakeClient


def test_parallel_lookups_share_one_client(tmp_path):
    (tmp_path / "main.go").write_text("package main\nfunc pingHandler() {}\n")
    started = []

    def factory(cmd, root, lang_id, timeout):
        c = FakeClient(cmd, root, lang_id, timeout)
        started.append(c)
        return c

    idx = LspIndex(tmp_path, GO, client_factory=factory)
    errors = []

    def worker():
        try:
            for _ in range(20):
                assert idx.has_symbol("pingHandler")
                idx.references("pingHandler")
                idx.symbols("main.go")
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    ts = [threading.Thread(target=worker) for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errors and len(started) == 1 and not idx.failed  # one server, never double-built or failed
    idx.close()
