# ADR-0008: Shannon's Capella stages as a static ADK Workflow graph

Status: accepted (2026-09-12). Extends ADR-0007 (the Workflow root) — the four dynamic nodes of ADR-0007
become the 24-node static graph of `docs/plans/shannon-graph.md`.

## Context

ADR-0007 moved the pipeline onto the ADK 2.9 `Workflow` API but kept the shape of the old custom agent: four
dynamic nodes (`build_skeleton → plan → investigate → finish`) whose bodies were Python control flow. The
builder in `adk web` rendered a straight chain of five `f` nodes; fan-out, joins, routes and parallel workers
existed only inside the bodies. The user asked for the Shannon workflow «почти полностью» (Capella's stages
minus exploitation) and for the graph to use the ADK constructs — fan-out, fan-in, routes, dynamic nodes —
visibly, not as hidden control flow.

## Decision

The scan is one static `Workflow` (`scanner/app/pipeline.py`) whose edges are Shannon's Capella stages:

```
START → scan → build_skeleton → direct_findings ─┬→ architect ─┐
                                                 └→ recon ─────┴→ join_model → domain_modeler → threat_modeler
→ ground → plan → route_plan {empty → export | default → batches → triage_sweep} → fold_triage → audit
→ route_research {none|budget → export | default → dedupe} → review → route_survivors {none → export | default}
→ route_intent {sample → mark_sample | default → critic} ; mark_sample → calibrate ; critic → provisional → confirm
→ calibrate → export
```

Each construct is chosen by what the node is, verified by the spike in `tests/test_adk_spike.py`
(`docs/plans/shannon-graph.md` §6):

| Construct | Nodes | Why |
|---|---|---|
| `FunctionNode` | `scan`, `build_skeleton`, `direct_findings`, `recon`, `ground`, `batches`, `fold_triage`, `dedupe`, `mark_sample`, `provisional`, `calibrate`, `export`, the four `route_*` | deterministic work; routes emit `Event(route=…)` and the edge map picks the branch (`DEFAULT_ROUTE` otherwise) |
| `JoinNode` | `join_model` | the only real fan-in: Architect ∥ recon; output `{architect: …, recon: …}` |
| dynamic `@node(rerun_on_resume=True)` running an `LlmAgent` child | `architect`, `domain_modeler`, `threat_modeler`, `plan` | a bare agent on a static edge cannot degrade: its exception fails the whole Workflow (spike Q5), and a modelling stage must degrade to "no artifact" with a note; the wrapper adds `asyncio.wait_for(stage_timeout)` and the artifact-cache resume |
| `@node(parallel_worker=True, max_parallel_workers=N)` over an `LlmAgent` | `triage_sweep`, `review`, `critic` (viability), `confirm` | list in → list out, ADK fans the items out; per-item `try/except` inside the worker because ADK raises the first worker exception and cancels the batch |
| dynamic loop | `audit` | the only node whose shape depends on data: rounds until the queue is empty, the round limit or the budget; each round fans out through the `route_and_verify` parallel worker |
| plain multi-predecessor nodes | `export`, `calibrate` | a `JoinNode` waits for every predecessor and a route-skipped branch never completes (spike Q2); a plain node runs once per firing edge, and the route maps are mutually exclusive |

Verdicts still come only from the store through `report_finding` / `disprove_finding` (+ the direct lane);
the model's JSON adds notes and annotations. Shannon's verdict ladder maps onto our statuses: review VALID =
confirmed; FALSE_POSITIVE only through `disprove_finding` with a counter-quote; PROVISIONALLY_VALID /
NEEDS_RESEARCH and viability VIABLE / CONDITIONAL_VIABLE / NON_VIABLE / SAMPLE_OR_TEST are annotations written
through `RunStore.annotate`, which refuses `status`, `evidence`, `confidence`, `id`, `anchor_id`; promotion in
`confirm` is a second `report_finding` with a higher confidence (the store replaces the verdict). The SARIF gate
stays `status == confirmed`; annotations travel in `properties`.

Payloads between nodes are the pydantic schemas of `scanner/core/workflow.py`; findings, anchors, hypotheses,
dossiers and artifacts stay in the RunStore; the session state keeps the few keys `scan_full` reads.

## Consequences

- The `adk web` builder shows the real shape: fan-out, join, labelled routes, parallel workers, agents as agents.
- Every stage degrades instead of aborting; `RetryConfig` is not used on stage nodes because an exhausted retry
  fails the Workflow (spike Q5) — retries happen inside the wrapper where the failure can be noted.
- `Workflow.max_concurrency` (nodes) and `max_parallel_workers` (items of one worker) are independent (spike Q6);
  budgets remain per-agent callbacks.
- Resume within a session is ADK replay by `invocation_id` (spike Q7); a CLI re-run is a new session and relies on
  the artifact cache in the stage wrappers.
- The graph shape is constant regardless of Settings (`RECON=0`, `TRIAGE=0`, `CRITIC=0`, `THREAT_MODEL=0` make
  the corresponding node a pass-through), so diagrams and tests stay stable.
- Not ported from Shannon: exploitation, the enrichment/task-formation lanes that feed it, dynamic recon against a
  live target; `recon` is a deterministic sink/guard/config inventory (`scanner/adapter/recon.py`).

## Alternatives considered

- Keep the four dynamic nodes and only rename them: rejected, the diagram would stay a chain and the request was
  explicitly about using the ADK constructs.
- `JoinNode` as the terminal: rejected by the spike (never fires when a route skips a predecessor).
- Bare `LlmAgent` nodes on static edges with `RetryConfig`: rejected, a final failure aborts the run instead of
  degrading; kept as the shape for a future ADK version with per-node failure routing.
