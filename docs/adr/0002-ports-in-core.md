---
status: accepted (2026-09-12)
---
# Ports live in `scanner/core/ports.py`; app imports adapter concretes only in `runner.py`

## Context
`app` reached the outside world through concrete adapter modules (`store.Run`, `build_index`, `tools`), and the
graph typed its collaborators as `Any` — pydantic checked nothing, fakes drifted silently, and the hexagon had one
port (`Index`). Martin's dependency rule and Cockburn's ports & adapters both put the port on the inside.

## Decision
Every capability the graph/tools need from outside is a `runtime_checkable` Protocol in `core/ports.py`:
`RunStore`, `Router`, `Closeable`, `Degradable`, and the index parts. `_Graph.store: RunStore`,
`_Graph.router: Router | None`, `PipelineV2.index: Closeable | None`. Only `app/runner.py` (the configurator)
imports adapter implementations to wire a run.

## Consequences
Test doubles are checked at construction (`isinstance(fake, RunStore)`); a missing method fails immediately, not
deep inside a stage. New adapters must satisfy a named port. Protocols carry `Any` for domain payloads to keep
`core` free of adapter types; the concrete `Run` is the only implementation, which is fine for a port.


## Amendment (2026-09-12)

`RunStore` is typed with the core payload types (`Anchor`, `Hypothesis`, `Dossier`, `Finding`) — they live in the same
layer, so no adapter type leaks into core; `Any` had been a leftover, not a rule. Test fakes must conform structurally.
