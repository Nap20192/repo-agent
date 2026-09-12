"""Shared fixtures; the doubles themselves live in tests/fakes.py (ADR-0005)."""

import pytest

from tests.fakes import FakeRun


@pytest.fixture
def fake_run() -> FakeRun:
    return FakeRun()
