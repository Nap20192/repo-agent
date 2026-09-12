---
status: accepted (2026-09-12)
---
# Test doubles live in `tests/fakes.py`; test modules are not libraries

## Context
Six test modules imported `FakeRun`, `FakeVerifier`, `Node`, `FakeClient` from other test modules; two different
`FakeRun` classes existed with different `notes()` shapes. A test module used as a library makes collection order
and fixtures fragile.

## Decision
One `tests/fakes.py` holds every double; `tests/conftest.py` exposes fixtures; `FakeRun` implements the full
`RunStore` port with `notes()` shaped like the real store and an opt-in `dedup` mirroring `Store.report`.

## Consequences
Assertions over notes go through `notes_of(run)`; adding a store method means updating one fake, checked by
`tests/test_ports.py`.
