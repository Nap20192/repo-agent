# Type Design Audit — scanner core/app/adapter (ecc:type-design-analyzer, 2026-09-12)

## Anchor, Candidate, Hypothesis, Dossier, Finding, Threat (core/types.py)
**Encapsulation**: weak — all `_Model(extra="ignore")` pydantic classes with mutable public fields and default
`""`/`0`. Cross-field invariants live in comments, not types: `Hypothesis` needs `anchor_id` OR `symbol`;
`Finding.confirmed` needs `anchor_id` + non-empty `evidence`; `Dossier.verdict` should be ∈ STATUSES but is a bare
`str`. Nothing stops `Hypothesis(kind="bogus", anchor_id="", symbol="")` at construction. PEP 484/589 cannot
express "one of two fields required" — that needs a pydantic `model_validator(mode="after")` or a tagged union
(PEP 604/586 `Literal` discriminant), per "Parse, don't validate" (Alexis King): make the illegal state
unconstructable rather than checked later.
**Usefulness**: `Anchor.cwe` is `""` for synthetic anchors — correct, but callers must remember truthiness checks
(`if a.cwe else {}` ×3 in owasp/knowledge). `Hypothesis.wstg_id`/`asvs_id` are set in reconcile but never copied
onto `Finding` (tools.py `Finding(...)` omits both; `Finding` has no `asvs_id`), so `asvs_id` is computed then
dropped. `Threat.priority`, `Anchor.tools`/`rule_ids` are read — useful.
**Enforcement**: `validate_finding`/`ground_hypothesis` (core/rules.py) are free functions called only at gate
points (tools.py report gate, graph.py `_gate`) — any other path that builds a `Finding`/`Hypothesis`
(`dossier_from_store`, `_owasp_fill`'s `model_copy`) bypasses validation. Trade-off: gate-as-function keeps the
refusal *reason* near the LLM boundary; a `@model_validator` makes violation impossible. Hybrid: structural
invariants (status ∈ STATUSES, confidence range, kind ∈ KINDS) as validators + the I/O-aware grounding gate as
a function.

## Stringly-typed fields → Literal/Enum
`Anchor.tool`, `Candidate.kind`/`Hypothesis.kind` (KINDS exists, untyped), `Finding.status`/`Dossier.verdict`
(STATUSES exists), severities (SEVERITY_RANK keys), `Specialist.role`, `ThreatModel.intent` (has a normalising
validator → `Literal["production","sample"]`). PEP 586 `Literal` + pydantic v2 gives parse-time validation and IDE
completion instead of ad-hoc membership checks (`ground_hypothesis` checks `h.kind not in KINDS` by hand).
```python
Status = Literal["confirmed", "rejected", "uncertain"]
class Finding(_Model):
    status: Status = "uncertain"
```

## Dicts flowing where a model should
`architecture_model`/`domain_map`/`threat_model` travel through pipeline_v2/reconcile as raw `dict`
(`arts: dict`, `store.artifact(stage) -> dict | None`) although `ArchitectureModel`/`ThreatModel`/`DomainMap`
exist — round-tripped via `.model_dump()`/`model_validate()` only at the edges (pipeline_v2.py) and handled as
untyped dicts in between (`exposure_for(finding, am: dict | None)`, `ground_artifacts`). Same for
`enrichment_for() -> dict` (PEP 589 `TypedDict` would name `kev`/`epss`/`cvss`/`functions` instead of `.get()`
scattered across calibrate.py and store.py). `_gate` returns `str | Finding` — a stringly-typed error channel
forcing `isinstance` checks at every caller.

## `Any` fields vs Protocols
`PipelineV2.index: Any`, `_Graph.store: Any` ("store.Run contract" in a comment) — pydantic
(`arbitrary_types_allowed`) does zero structural checking, so a fake missing `put_artifact` fails deep in a
stage. `ports.Index` is already a `@runtime_checkable Protocol` (PEP 544); `store` deserves a `StoreProtocol`
in core/ports.py listing the ~12 methods graph/tools actually call (`anchors`, `anchor`, `report`,
`put_artifact`, `artifact`, `add_note`, `put_hypotheses`, `put_dossiers`, `findings`, `save_anchors`,
`log_gate`), so test fakes can be checked with `isinstance(fake, StoreProtocol)`.

## Fat `Index` Protocol (ISP)
9 methods; every implementer (`GrepIndex`, `LspIndex`, `FallbackIndex`, `MultiIndex`) supplies all 9 while
callers use disjoint subsets (Architect: `symbols`/`references`; taint: `callers`/`callees`/`path_to_entry`;
`definition_range` only in dominance/tools). Martin's ISP: split into `SymbolIndex` (`find_symbol`, `has_symbol`,
`symbols`, `definition_range`), `CallGraph` (`callers`, `callees`, `references`, `path_to_entry`) and
`Closeable`; `Index` = their intersection (Protocols compose). Low risk: every implementer already satisfies
all three; only call sites narrow their declared dependency.

## Overlaps
**Symbol vs Candidate**: definition (index truth) vs proposal (entry/sink/external with `route`/`anchor_id`) —
a legitimate distinction, but `Candidate.symbol` duplicates `Symbol.name` with no shared base.
**Threat vs Hypothesis**: near-identical shape (cwe, claim, symbol, file, line, wstg_id, priority/reads);
`from_threats()` maps field by field. A shared `_ClaimBase` (cwe/claim/symbol/file/line/wstg_id/reads) removes
the copy-paste and the drift risk.

## Prioritized task_list (behavior-preserving)
1. core/types.py — `Finding.status`/`Dossier.verdict` → `Literal[...]`; `Anchor.tool`, `ThreatModel.intent`
   (drop validator) → `Literal`. Why: parse-time rejection of typos. Risk low. Tests: new tests/test_types.py,
   test_calibrate/test_store.
2. core/types.py — `model_validator(mode="after")` on `Hypothesis` (anchor_id-or-symbol) and `Finding`
   (confirmed ⇒ anchor_id + evidence); keep `ground_hypothesis`/`validate_finding` as the I/O-aware second gate.
   Risk medium (must not contradict existing gate messages). Tests: test_graph.py, test_rules.py.
3. core/types.py, adapter/tools.py — propagate `Hypothesis.wstg_id`/`asvs_id` into `Finding`; add
   `Finding.asvs_id` (currently computed then dropped). Risk low, additive. Tests: test_tools, test_store taxa.
4. core/ports.py — split `Index` into `SymbolIndex`/`CallGraph`/`Closeable`, keep `Index` as their union (ISP).
   Risk low, additive typing, no adapter changes. Tests: test_lsp_index.
5. app/graph.py, app/pipeline_v2.py — replace `store: Any` with a `StoreProtocol` in core/ports.py; catches fake
   drift at construction. Risk low. Tests: test_graph fakes.
6. core/calibrate.py, adapter/knowledge.py — `TypedDict` for enrichment/architecture_model dict shapes; type-checker
   only. Risk low.
