# ADR-0010: the small graph — seven nodes, five agents

Status: accepted (2026-09-12). Supersedes ADR-0008 (the 24-node Shannon graph) and the specialist registry of
docs/archive/plans/specialists.md; ADR-0009 (feature folders) stays.

## Context

The 24-node graph reproduced Shannon's Capella stages faithfully: a file-batch triage sweep, a three-stage modelling
chain (architect ∥ recon → domain modeler → threat modeler), a verdict ladder (review → viability → confirm), eight
specialist agents behind a CWE router, four route maps, a dozen switches. Every finding cost three independent LLM
passes after the investigation; every file cost a triage call. The owner asked for it to be simple: "many things
have to go".

## Decision

```
START → scan → build_skeleton → direct_findings → model → plan ─(empty)→ export
                                                          └(default)→ audit → critique → export
```

| node | what | LLM |
|---|---|---|
| `scan` | the static scanners → anchors (in a worker thread) | no |
| `build_skeleton` | target + entry points | no |
| `direct_findings` | osv / gitleaks / semgrep-ERROR anchors → findings, no model, no gate (card 42) | no |
| `model` | ONE modelling stage: architecture + threats in one answer, grounded (`ground_artifacts`) | `model` |
| `plan` | anchors + grounded threats + entry-point baselines → the hypothesis queue; empty → export | no |
| `audit` | rounds: gate → `verify` fan-out; each activation carries its class section + language overlay | `verify` |
| `critique` | dedupe, then `critic` over every confirmed finding: disproof only through `disprove_finding`; its JSON is the `review` annotation | `critic` |
| `export` | deterministic calibration, timings, stop reason → SARIF + summary | no |

Agents: `model`, `verify`, `critic`, plus the two consultants `knowledge` and `domain` reached as sub-agents
(AgentTools) from `verify` and `critic`. The specialist agents are gone; their prompt sections live in
`agents/shared.py:SPECIALIST_SECTIONS` and `registry.overlay()` appends the right one (CWE → kind → class) to the
activation payload — same knowledge, no agent per class, no router, no per-class tool subsets.

Gone with them: the triage sweep and file coverage (card 44), the verdict ladder (card 45), the domain map stage
and its skeleton extractor, recon, dominance analysis, notes tools, web search, session compaction, `LLM_MODEL_SMALL`,
`CALIBRATE_LLM`, and 16 Settings knobs.

## Consequences

- One critic pass per finding instead of three; no per-file triage call: a run costs roughly a third of the 24-node
  graph on the same target. Precision on subtle false positives relies on one adversarial pass and the gate.
- No file-coverage guarantee: the queue comes from anchors, grounded threats and entry-point baselines only.
- The `domain` consultant answers from code (grep / lsp), not from a prebuilt domain map.
- `RunStore.annotate` keeps `review` / `viability` / `repro_status` / `calibration` fields; the small graph writes
  `review` (critic) and `calibration` (export) only — SARIF properties stay backward compatible.
- Adding an agent or a node still follows ADR-0009's template.
