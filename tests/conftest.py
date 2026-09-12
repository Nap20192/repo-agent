"""Shared fixtures; the doubles themselves live in tests/fakes.py (ADR-0005)."""

import pytest

from tests.fakes import FakeRun


@pytest.fixture(autouse=True)
def _no_network_enrichment(monkeypatch):
    """Knowledge enrichment is off for every test: the pre-pass must never reach advisory databases from pytest."""
    monkeypatch.setenv("KNOWLEDGE_ENRICH", "0")


@pytest.fixture
def fake_run() -> FakeRun:
    return FakeRun()
