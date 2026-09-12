---
status: accepted (2026-09-12)
---
# `Index` is split by consumer: `SymbolLocator`, `Definitions`, `CallGraph`, `Closeable`, `Degradable`

## Context
`Index` had nine methods; every adapter implemented all of them while consumers use disjoint subsets (the gate
and synthetic anchors need `find_symbol`/`has_symbol`; dominance needs `symbols`; reachability needs `callers`/
`path_to_entry`). A fat interface violates ISP and let a six-method stub in `tools.py` pass as an `Index`.

## Decision
`Index` becomes the union of four narrow Protocols plus `Degradable` (`failed: bool`) for adapters that can give
up; `FallbackIndex` is typed on `Degradable`. All adapters already satisfied every part, so no adapter code
changed; the dead grep stub in `tools.py` was deleted and `build_index` is the only default.

## Consequences
Call sites can declare the narrowest port they need. A partial adapter is now an `isinstance` failure in
`tests/test_ports.py` rather than an `AttributeError` at run time.
