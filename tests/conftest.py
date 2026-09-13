"""Shared fixtures; the doubles themselves live in tests/fakes.py (ADR-0005)."""

import pytest

from tests.fakes import FakeRun


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Every urllib opener is closed under pytest (urlopen and adapter.osv's own opener both go through
    OpenerDirector.open): nothing reaches osv.dev; tests that need `osv.fetch` monkeypatch it."""
    import urllib.request

    def _blocked(self, req, *a, **k):
        raise RuntimeError(f"network call under pytest: {getattr(req, 'full_url', req)}")

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", _blocked)


@pytest.fixture
def fake_run() -> FakeRun:
    return FakeRun()
