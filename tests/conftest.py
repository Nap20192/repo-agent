"""Shared fixtures; the doubles themselves live in tests/fakes.py (ADR-0005)."""

import pytest

from tests.fakes import FakeRun


@pytest.fixture(autouse=True)
def _no_network_enrichment(monkeypatch):
    """Knowledge enrichment is off for every test and urlopen is closed: a test that passes an explicit
    `KnowledgeConfig(enabled=True)` fails loudly instead of reaching osv.dev/GitHub/NVD (tests that need fetch
    monkeypatch it themselves, which overrides this)."""
    monkeypatch.setenv("KNOWLEDGE_ENRICH", "0")
    import urllib.request

    def _blocked(req, *a, **k):
        raise RuntimeError(f"network call under pytest: {getattr(req, 'full_url', req)}")

    monkeypatch.setattr(urllib.request, "urlopen", _blocked)


@pytest.fixture
def fake_run() -> FakeRun:
    return FakeRun()
