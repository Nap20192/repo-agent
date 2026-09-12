---
status: accepted (2026-09-12)
---
# Migrate `PipelineV2` to the ADK 2.9 `Workflow` graph API

## Context

`docs/adr/0001-parallel-fanout.md` kept `ParallelAgent` in `_Graph._run_activations`
(`scanner/app/graph.py`) and named two conditions to revisit: ADK either "lets a `Workflow` run under an
agent … or documents `Runner(node=…)` + `adk web` for node roots". Both are now true in the installed
`google-adk` 2.9.0 (`.venv/lib/python3.13/site-packages/google/adk/`):

- `Runner.__init__(self, *, app: Optional[App] = None, agent: Optional[BaseAgent] = None, node: BaseNode |
  None = None)` (`runners.py:222-228`) — `node` is a first-class, documented root, mutually exclusive with
  `agent`.
- `App.root_agent: Union[BaseAgent, Any, None]` (`apps/app.py:75-78`), docstring: "Accepts either a
  `BaseAgent` or a `BaseNode` instance." The official samples set `root_agent = Workflow(...)` directly
  (`contributing/samples/workflows/*/agent.py`), and `cli/utils/agent_loader.py:67-73` loads whatever
  module-level `root_agent` it finds — no special-casing needed for `adk web`.
- `cli/utils/graph_serialization.py` renders `Workflow` edges, routes, `rerun_on_resume` and node types
  (`function|tool|join|workflow|agent`) natively.
- `agents/sequential_agent.py:78-82` (and `parallel_agent.py`, `loop_agent.py:61`) still carry
  `@deprecated('... in favor of Workflow ...')` — `ParallelAgent` is deprecated, not yet removed, but nothing
  blocks moving off it now that a `Workflow` root is documented and works.

Full API survey, video sources and sample code: `docs/rnd/adk-multi-agent-2026-09-12.md`.

## Decision

Replace `PipelineV2(Graph(BaseAgent))`'s hand-rolled `_run_async_impl` with a root `google.adk.workflow.
Workflow` (a `BaseNode`, wired in `scanner/app/runner.py::build_agent`, the composition root). The graph
stays small and mostly dynamic (`@node(rerun_on_resume=True)` bodies calling `ctx.run_node()`), not a long
chain of static edges, because `BaseNode.retry_config`'s own docstring is explicit that "a failure of any
node inside [a `Workflow`] is a failure of the workflow" — our stages/verify/critic must degrade on failure,
not abort the run, so anything that must "note and continue" runs as Python control flow inside a dynamic
node, not as a bare edge. Full node-by-node design, state schema, and the CWE→specialist router (staying in
code, unchanged) are in `docs/plans/workflow-migration.md`.

Implementation is BOARD card 43, done in the small, test-green steps §7 of that document lists — the old
`PipelineV2`/`Graph` and the new pipeline coexist until the last step, so `ParallelAgent` is not removed
until its replacement (`ctx.run_node` fan-out + `parallel_worker`) has passed the same tests.

## Consequences

- `ParallelAgent` (and the deprecation warning it carries) is deleted from `_run_activations`, along with
  `activation()`'s per-run `agent.clone()` + instruction-rewrite trick, `_retry_json`, `parse_json`, and
  `with_deadline` — `output_schema` + node-level `retry_config`/`timeout` take over (§5 of the blueprint).
- Branch names change: today's `verify_round_<r>_<c>.verify_r<r>_<i>` becomes whatever
  `_ParallelWorker`'s `use_sub_branch=True` produces (`workflow/_parallel_worker.py:108-112`). Tests that
  assert literal branch strings move to `event.node_info.path` or an explicit `override_branch` — ADR-0001
  already anticipated this cost ("changes the event stream, the branch naming").
- The `specialists: dict = Field(default_factory=dict, exclude=True)` workaround for the dev-UI builder
  (commit 66b1473) is removed: specialists become plain graph/dynamic nodes, which
  `graph_serialization.py` already knows how to render, instead of a hidden field on a `BaseAgent`.
- Resume moves from the hand-rolled `store.artifact(stage)` skip-check in `_stage` to
  `App(resumability_config=ResumabilityConfig(is_resumable=True))` (`apps/_configs.py:29-40`) plus
  `ctx.run_node()`'s own dedup-by-`(node_name, run_id)` against session events
  (`workflow/_dynamic_node_scheduler.py`). `RunStore`/SQLite keeps being the durable *product* of a run
  (findings, SARIF, summary), not a second, competing control-flow checkpoint.
- The `report_finding`/`disprove_finding` gates, `redact_secrets`, tool output caps and symlink hiding are
  untouched — they live in `scanner/adapter/tools/gates.py` and callbacks, neither of which changes shape;
  the deterministic CWE→specialist router (`scanner/app/specialists.py`) stays exactly as it is, only its
  caller moves from `_Graph._pick` to a node body (`route_and_verify`/`route_and_critique`).
- Hexagonal layering is preserved: ADK `Workflow`/node imports land only in `scanner/app/*` (the new
  `graph_nodes.py`/`pipeline.py`), never in `scanner/core` or `scanner/adapter`; `runner.py` remains the
  only place that wires adapter concretes into the graph.

## Alternatives considered

### A. Do nothing (stay on ADR-0001's decision)
`ParallelAgent` still works; not touching it costs nothing today. Rejected because it is deprecated (not
`removed`, but the direction is set) and BOARD card 43 exists precisely because the "revisit when" conditions
are now met — deferring further just means doing this migration later, against more code (card 42's
direct-findings lane is landing concurrently and is easier to slot into the new shape than to migrate twice).

### B. Partial migration: static `Workflow` for the stage chain only, keep `ParallelAgent` for verify/critic fan-out
Tried first while drafting this ADR. Rejected: `LlmAgent` stage nodes chained by static edges cannot degrade
on failure per the "Context" fact above (no failure-catching edge), so the chain would have to be a dynamic
node anyway to keep `_stage`'s "note and continue" behavior — at which point there is no static-edge value
left to keep, only two orchestration primitives to maintain instead of one.

### C. Fully dynamic workflow: one `@node` doing everything, no static edges, no `JoinNode`
Matches the "shape depends on the input" video guidance in spirit, but throws away the one place a real graph
adds value here: `build_skeleton` is genuinely fixed-shape, LLM-free, and worth a real `FunctionNode` the
dev-UI can show as a distinct step. Rejected in favor of the 4-node skeleton in
`docs/plans/workflow-migration.md` §2, which keeps that one static, pure step and puts only the
failure-prone, variable-shape parts (`plan`, `investigate`, `finish`) in dynamic bodies.

## Supersedes

Supersedes the "Revisit when" clause of `docs/adr/0001-parallel-fanout.md` — both named conditions hold (see
Context). ADR-0001's *decision* to keep `ParallelAgent` in `_run_activations` is superseded by this ADR once
migration step 8 (`docs/plans/workflow-migration.md` §7) lands and `scanner/app/graph.py` is deleted;
ADR-0001's *evidence* section (the `wf_fanout.py` experiment showing a `Workflow` cannot run under a
`BaseAgent` root) is unaffected and remains true — this ADR does not put a `Workflow` under an agent, it
replaces the agent root itself.

## Status

Accepted 2026-09-12. Card 43 merged: steps 1–9 of `docs/plans/workflow-migration.md` landed, `PipelineV2`,
`Graph`, `activation` and the `ParallelAgent` fan-out are deleted, the suite is green on the `Workflow` root,
`adk web` renders the four-node graph, a live smoke on ollama runs end to end.

## Resolved (what differed from the proposal)

- No `state_schema`: ADK rejects undeclared keys and the budget callback writes per-branch keys; the shared keys
  are documented in `scanner/core/workflow.py` only.
- Direct findings run before the Architect (card 42's review), not inside `plan` after the stages.
- Stage timeout is `asyncio.wait_for` around `ctx.run_node` (degrades to "no artifact"); the artifact-based
  resume short-circuit stays because a CLI re-run is a fresh ADK session.
- Every node reached through `ctx.run_node` needs `rerun_on_resume=True`; a child's exception arrives as
  `DynamicNodeFailError` with the cause in `.error`.
- A per-branch verifier budget surfaces as a soft "no Dossier JSON" dossier error, not the `budget` stop.
- `ScanWorkflow(Workflow)` carries the `index` so the runner closes LSP servers as before.
- The eval harness runs an agent as a dynamic node with the payload as the user turn (no `activation`).
