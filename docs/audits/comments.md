# Comment & Docstring Audit — scanner/ and web/fullscan (ecc:comment-analyzer, 2026-09-12)

**Summary.** Module docstrings match current behavior (no stale "Lead"/"v1"/"FullScan" references); LLM-facing
tool docstrings are all under ~400 chars; no Russian in code comments (README is Russian by design).
Docstring coverage ≈ 80% (core 90%, adapter 79%, app 75%; public APIs ≈ 100%, private helpers light on purpose).

## ponytail / TODO inventory
| file:line | note | verdict |
|---|---|---|
| adapter/tools.py:62 | `_GrepIndex` "until scanner/adapter/index lands" | **delete** — the index package exists; fallback is emergency-only |
| adapter/tools.py:277 | host exec without sandbox | keep |
| adapter/tools.py:299 | grep fallback when the DomainModeler produced no map | keep |
| adapter/store.py:63 | one sqlite connection, tools run in threads | keep |
| adapter/knowledge.py:242 | ten-advisories heuristic | keep |
| adapter/domain.py:3, owasp.py:3, skills.py:13, static.py:31 | design rationale (no AST, curated tables, static map, no sandbox) | keep |
| adapter/index/rpc.py:175, lsp.py:243, grep.py:39 | select deadline edge, ambiguity tie-break, 40-line body heuristic | keep |
| app/graph.py:143 | ParallelAgent deprecated in ADK 2.9 | backlog — link to docs/adr/0001-parallel-fanout.md |

## Findings and fix list
1. **High** adapter/tools.py:62 — delete the stale `_GrepIndex` comment (or the dead fallback class itself, see architecture audit).
2. **High** adapter/tools.py:287–290 — `consult_domain` docstring must state the two paths: DomainModeler artifact first, grep heuristic when there is no map or the entity is unknown; cite `domain:<entity>`.
3. **Medium** app/pipeline_v2.py:1 — module docstring omits the DomainModeler stage between Architect and ThreatModeler.
4. **Medium** app/graph.py:143 — point the ParallelAgent note at the ADR instead of restating the deprecation.
No narrate-the-obvious comments or stale line-number references found; explanatory comments carry the *why*
(PEP 8 §Comments, Google Python Style Guide §3.8).
