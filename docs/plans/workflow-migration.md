# PipelineV2 → ADK 2.9 Workflow graph — migration blueprint (card 43)

Sources: `docs/rnd/adk-multi-agent-2026-09-12.md` (API + samples), `docs/adr/0001-parallel-fanout.md`,
`docs/architecture.md`, `scanner/app/{pipeline_v2,graph,runner,specialists,callbacks,reconcile}.py`,
`web/fullscan/agent.py`, `tests/fakes.py`, `tests/test_stages.py`, and the installed ADK source
(`.venv/.../google/adk/workflow/*`, `agents/llm_agent.py`, `agents/context.py`, `apps/{app.py,_configs.py}`).
Companion: `docs/adr/0007-workflow-graph.md` (decision + evidence).

## 1. The decisive fact that shapes this design

`BaseNode.retry_config` docstring (`workflow/_base_node.py:84-93`): **"On a `Workflow`, a failure of any node
inside it is a failure of the workflow, so the whole sub-workflow is retried."** Static graph edges have no
"catch and continue with `None`" primitive — only `retry_config` (retry the *same* node) and routing
(`Event(route=...)`, decided *before* failure, not after). Our stages/verify/critic must **degrade**, not
abort (`_stage`'s `except Exception: add_note(...); out[stage] = None`; `_verify`/`_critic_pass` catch per
chunk and go on). Confirmed also for the bulk primitive: `_ParallelWorker._run_impl`
(`workflow/_parallel_worker.py:118-141`) awaits every item, and **the first item's exception is raised and
the rest are cancelled** ("if failure is not None: raise failure") — one failing hypothesis would otherwise
kill the whole batch. Conclusion: every place we need "keep going, note the failure" must be a **dynamic
node** (`@node(rerun_on_resume=True)` calling `ctx.run_node()` inside its own `try/except`), never a bare
static edge or a bare `parallel_worker` body. This is why the target graph below is a *small* static skeleton
(4 top-level nodes) whose bodies are Python control flow, not a long chain of LLM edges.

## 2. Target graph

```
Workflow(name="scan_v3", state_schema=WorkflowState, rerun_on_resume=True, edges=[
    (START, build_skeleton),
    (build_skeleton, plan),
    (plan, investigate),
    (investigate, finish),
])
```

| Node | ADK type | LLM cost | Purpose |
|---|---|---|---|
| `build_skeleton` | `FunctionNode` (pure) | 0 | anchors (already scanned by `runner.prepare`) + entry points → `Skeleton` |
| `plan` | `@node(rerun_on_resume=True)` (dynamic) | 0–3 calls | Architect → DomainModeler → ThreatModeler (each optional, each soft-fail), `ground_artifacts`, `direct_findings` (card 42), `_build_queue` → `QueueState` |
| `investigate` | `@node(rerun_on_resume=True)` (dynamic) | ≤ `max_rounds·max_hyps` calls | drains the queue in rounds via `route_and_verify` (`parallel_worker`) |
| `finish` | `@node(rerun_on_resume=True)` (dynamic) | ≤ `len(confirmed)` calls | critic pass via `route_and_critique` (`parallel_worker`), terminal report |

No `JoinNode`/routing map is needed at the top level: there is nothing to fan *out* to before `plan` (the
direct-findings/threat-model split happens **inside** `plan`, in code, because both must degrade
independently) and nothing to route on (the CWE→specialist choice is per-hypothesis, decided inside
`route_and_verify`, not a graph-level branch). This matches ADR-0001's own framing: "deterministic router
wins when the set is closed and the signal is in the data" — ours stays in Python, one level down.

`direct_findings` (card 42) is a **dynamic child** of `plan`, run as
`await ctx.run_node(direct_findings_node, anchors, run_id="direct_findings")` where `direct_findings_node`
is a plain `FunctionNode` around `reconcile.split_direct` + `gate_finding` per direct anchor (no LLM,
already gate-checked — see §5). It shows up in the `adk web` graph as a dynamic child node (per
`workflow/_dynamic_node_scheduler.py`) without being a static edge, exactly the "FunctionNode-equivalent
step before the queue" the card asks for; `plan` passes it only the anchors `split_direct` didn't claim.

`route_and_verify` / `route_and_critique` are declared with the decorator (verbatim signature,
`workflow/_node.py:46-58`):

```python
def node(*, name=None, rerun_on_resume=None, retry_config=None, timeout=None,
         parallel_worker: bool = False, max_parallel_workers: int | None = None,
         auth_config=None, parameter_binding: Literal['state', 'node_input'] = 'state') -> ...
```

```python
@node(parallel_worker=True, max_parallel_workers=self.max_parallel, parameter_binding="node_input")
async def route_and_verify(ctx: Context, node_input: dict) -> dict:      # one hypothesis payload in, one Dossier dict out
    ...
```

`investigate` calls it once per batch — `dossiers = await ctx.run_node(route_and_verify, batch_payloads)` —
and `_ParallelWorker` fans the list out with `max_parallel_workers` concurrency and `use_sub_branch=True`
per item (`_parallel_worker.py:108-112`); branch names become `route_and_verify@<run_id>.<sub-branch>`, not
today's `verify_round_<r>_<c>.verify_r<r>_<i>` — ADR-0001 already flagged this as an accepted cost of the
migration (§7 "what changes").

## 3. State schema vs RunStore

Only what a **later node must read outside its immediate predecessor's output** goes in `ctx.state`
(`state_schema=WorkflowState`); everything durable (findings, anchors, hypotheses/dossiers logs, grounded
artifacts) stays in `RunStore`/SQLite exactly as today — `plan` re-reads `store.artifact(stage)` the same
way `_run_stages` does now, instead of round-tripping large dicts through state (per
`https://adk.dev/graphs/data-handling/`: "do not use it to move large payloads between nodes").

```python
class WorkflowState(BaseModel):
    model_config = ConfigDict(extra="allow")   # tool/consultant scratch keys, budget flags keyed by branch
    round: int = 0                             # core.STATE_ROUND
    queue_len: int = 0
    stop_reason: str = ""                      # core.STATE_STOP_REASON
    budget_exhausted: bool = False             # core.STATE_BUDGET_EXHAUSTED
    grounding_dropped: int = 0
    json_retries: int = 0                      # kept only if output_schema retries are still counted (see §4)
```

`architecture_model`/`domain_map` are written to `ctx.state` too, but only transiently, via each stage
LlmAgent's `output_key` (so the *next* stage's instruction can template `{architecture_model}` per
`https://adk.dev/graphs/data-handling/` templating rules); `plan` persists the grounded version to
`RunStore.put_artifact` right after grounding, same as `_run_stages` today. `Workflow._validate_state_schema`
(`_workflow.py:180-208`) also checks `FunctionNode` parameter names against this schema — `build_skeleton`'s
signature must use the same field names.

## 4. Per-node signatures

```python
class Skeleton(BaseModel):
    target: str
    entry_points: list[Candidate]
    anchors: list[dict]          # trimmed anchor view, unchanged from today's _model_threats

def build_skeleton(node_input: RunInputs) -> Skeleton: ...     # FunctionNode, output_schema=Skeleton

class QueueState(BaseModel):
    queue: list[Hypothesis]
    done: list[str]              # set() isn't JSON-native; `key(h)` strings, `set(done)` on read

@node(rerun_on_resume=True)
async def plan(ctx: Context, node_input: Skeleton) -> QueueState:
    am = await _run_stage_safely(ctx, "architecture_model", architect, node_input) if architect else {}
    dm = await _run_stage_safely(ctx, "domain_map", domain_modeler, {"architecture_model": am, ...}) if domain_modeler else {}
    tm = await _run_stage_safely(ctx, "threat_model", threat_modeler, {"architecture_model": am, "domain_map": dm}) if threat_modeler else {}
    am, dm, tm, notes = ground_artifacts(am, dm, tm, grounded, KNOWN_WSTG)   # pure fn, unchanged (reconcile.py)
    for stage, art in (("architecture_model", am), ("domain_map", dm), ("threat_model", tm)):
        if art is not None: store.put_artifact(stage, art)
    remaining, reported = await ctx.run_node(direct_findings_node, node_input.anchors, run_id="direct_findings")
    queue, done = _build_queue(remaining, am, tm)     # unchanged pure logic from pipeline_v2._build_queue
    return QueueState(queue=queue, done=list(done))

@node(rerun_on_resume=True)
async def investigate(ctx: Context, node_input: QueueState) -> InvestigateResult:
    queue, done, rnd, stop = list(node_input.queue), set(node_input.done), 0, ""
    while queue:
        if rnd >= max_rounds: stop = "round limit"; break
        batch, queue = queue[:max_hyps], queue[max_hyps:]
        done |= {key(h) for h in batch}
        accepted = _gate(batch, rnd)                 # unchanged (scanner/app/graph.py logic, moved verbatim)
        if accepted:
            payloads = _verify_payloads(accepted)     # unchanged
            dossiers = await ctx.run_node(route_and_verify, payloads, run_id=f"verify_r{rnd}")
            store.put_dossiers(rnd, [Dossier.model_validate(d) for d in dossiers])
            if _budget_hit(ctx): stop = "budget"; break
            if rnd == 0 and all(d["error"] for d in dossiers): raise RuntimeError(...)   # same fail-fast as today
            queue = reconcile([h for d in dossiers for h in d["new_hypotheses"][:3]], queue, done)
        rnd += 1
    return InvestigateResult(rounds=rnd, stop=stop)

@node(rerun_on_resume=True)
async def finish(ctx: Context, node_input: InvestigateResult) -> Report:
    confirmed = [f for f in store.findings() if f.status == core.CONFIRMED]
    if confirmed and critic is not None:
        await ctx.run_node(route_and_critique, [_critique_payload(f) for f in confirmed], run_id="critic")
    return Report(rounds=node_input.rounds, stop_reason=node_input.stop, timings=timings)   # the one terminal output
```

`route_and_verify`/`route_and_critique` internally do exactly what `_pick` does today (unchanged, still in
code — CWE → kind → generic fallback), then `try: dossier = await ctx.run_node(agent, payload,
run_id=h["id"]) except Exception as e: return {"error": str(e), ...}` — **never re-raise**, so
`_ParallelWorker`'s "first exception kills the batch" rule (§1) never fires on a normal verifier miss; only
a truly fatal condition (e.g. `NodeTimeoutError` from a hung specialist, per `timeout=` on that agent) should
be allowed to propagate.

## 5. JSON parsing/retry → `output_schema`

- `parse_json`/`JSON_NUDGE`/`STATE_JSON_RETRIES` (`scanner/app/graph.py`) are **deleted**. Each stage/specialist
  `LlmAgent` gets `output_schema=ArchitectureModel|DomainMap|ThreatModel|Dossier`, `output_key="<stage>"`,
  `mode="single_turn"`.
- Invalid JSON: `LlmAgent.__maybe_save_output_to_state` calls `validate_schema(output_schema, text)`
  (`agents/llm_agent.py:1093-1100`) which raises (`pydantic.ValidationError` / `json.JSONDecodeError`,
  `utils/_schema_utils.py:202-224`) — **uncaught**, so it surfaces as the node's failure. `retry_config` on
  that `LlmAgent` node (`RetryConfig(max_attempts=2, exceptions=[ValidationError])`) replaces `_retry_json`'s
  one JSON-nudge retry — cheaper, since ADK's own structured-output path already re-prompts on schema
  mismatch before it ever raises for well-behaved models; the exhausted-retry case is what `_run_stage_safely`
  (`plan`'s `try/except`) converts into `add_note(f"stage {stage} failed: {e}")`, matching today's message
  format so `tests/test_stages.py`'s note-text assertions need only the stage name check kept, not rewritten.
- `stage_timeout` becomes each stage node's own `timeout=` field (native `NodeTimeoutError`, retryable) instead
  of the hand-rolled `with_deadline` wrapper (`graph.py:73-87`, deleted).
- `activation()`'s clone-and-rewrite-instruction trick (`graph.py:61-71`) is **deleted**: the specialist
  `LlmAgent`s built once per run (`specialists.build`, `agents.new_verifier/new_critic`) keep a *static*
  instruction; the per-hypothesis payload (`skill`/`skills`/`specialist` + the language-overlay suffix that
  used to be a clone-time instruction append) becomes the `node_input` text `route_and_verify` builds and
  passes to `ctx.run_node(agent, payload_text)` — `node_input` becomes the user turn content
  (`workflow/_llm_agent_wrapper.py:305-385` per the R&D report). No more per-activation `agent.clone()`.

## 6. Resume → ADK replay

`App(resumability_config=ResumabilityConfig(is_resumable=True))` (`apps/_configs.py:29-31`, verbatim:
`is_resumable: bool = False` / `"If enabled, the feature will be enabled for all agents in the app."`).
`ctx.run_node()` dedups by `(node_name, run_id)` against prior session events
(`workflow/_dynamic_node_scheduler.py` docstring: "Deduplication: Returning cached output if the node already
completed in a prior turn") — so a resumed run does not re-verify a hypothesis already verified, **provided**
`run_id` is stable across resume (`run_id=f"verify_r{rnd}"` for the batch, `run_id=h["id"]` inside
`route_and_verify` for the individual call). This supersedes the manual `if (cached := store.artifact(stage))
is not None: return` skip-check in `_stage` (`pipeline_v2.py:70-72`) — `plan`/`architect` etc. simply rerun on
resume and get the cached result back from `ctx.run_node`'s own dedup, not from `RunStore`. `RunStore` keeps
being the durable *product* of a run (findings, SARIF, summary) — not a second, competing resume mechanism.
Tools stay idempotent (`report_finding`/`disprove_finding` already dedup by anchor, `FakeRun.report`/`Store`)
so "at-least-once" replays are safe (docs: "tools may run twice").

## 7. Migration order (each step leaves `uv run pytest -q` green)

| Step | Files | Tests | Risk |
|---|---|---|---|
| 1 | `scanner/core/` : add `Skeleton`, `QueueState`, `InvestigateResult`, `Report`, `WorkflowState` (pydantic, no ADK import) | new `tests/test_workflow_types.py` (round-trip/model_validate) | low — pure types |
| 2 | `scanner/app/reconcile.py` : extract `_build_queue`'s body out of `PipelineV2` as a free function (already almost pure) so both the old and new graph can call it | existing `tests/test_reconcile.py`, `tests/test_stages.py` unchanged | low — behavior-preserving extraction |
| 3 | `scanner/app/graph_nodes.py` (new) : `build_skeleton`, `direct_findings_node` as plain functions/`FunctionNode`s, no wiring yet | new `tests/test_graph_nodes.py` with `tests/fakes.py` doubles, run via `Runner(node=build_skeleton)` | low — isolated, additive |
| 4 | `scanner/app/graph_nodes.py` : `route_and_verify`/`route_and_critique` (`@node(parallel_worker=True)`), reusing `_pick`/`_verify_payloads` moved from `graph.py` | new tests: swap a `FakeVerifierNode` (see §8) in place of a real specialist, assert dossier shape + per-item error containment | medium — first use of `parallel_worker` + `ctx.run_node` |
| 5 | `scanner/app/pipeline_v3.py` (new, alongside `pipeline_v2.py`) : `plan`, `investigate`, `finish` dynamic nodes + `Workflow(edges=[...])` factory `build_workflow(...)` mirroring `build_agent`'s signature | port `tests/test_stages.py` node-by-node onto `Runner(node=...)`; both old and new pipelines' tests green | high — the actual behavior port |
| 6 | `scanner/app/runner.py` : `build_agent` returns the `Workflow` (behind `PIPELINE=v3` env flag, mirroring the v1→v2 switch card 06 used), `run_session` unchanged (`App(root_agent=agent)` already accepts a `BaseNode`) | `tests/test_runner_wiring.py` parametrized over v2/v3 | medium — composition root |
| 7 | `web/fullscan/agent.py` : `prepare()` returns the v3 workflow when the flag is set | manual `adk web` smoke: graph renders, a run completes | low — thin wrapper |
| 8 | Delete `scanner/app/graph.py`'s `Graph`/`_run_activations`/`activation`/`_retry_json`/`parse_json`/`with_deadline`, delete `PipelineV2`, flip the default to v3, drop the flag | full suite green with only `pipeline_v3` | medium — the actual cutover |
| 9 | `docs/adr/0007-workflow-graph.md` → `status: accepted`; update `docs/architecture.md` §"Отображение на Google ADK"; retire `BOARD.md` card 43 | — | low — docs |

Steps 1–7 keep `PipelineV2` and `Graph` alive and green throughout (a parallel implementation, not an
in-place rewrite) — GATE 2 lands once per step per CLAUDE.md, GATE 1 (this document) covers the whole
sequence.

## 8. Fakes: how a test double plugs into a `parallel_worker` node

`tests/fakes.FakeVerifier(BaseAgent)` stays a `BaseAgent`-shaped double, but `route_and_verify` calls
`ctx.run_node(agent, ...)`, and `Context.run_node`'s `node: NodeLike` parameter accepts "a `BaseNode` instance
or a callable that can be built into a node" (`agents/context.py:420-436`, `utils/_workflow_graph_utils.build_node`)
— a plain `BaseAgent` is not directly a `NodeLike`. Two options, in order of preference:

1. Keep `FakeVerifier`/`FakeCritic`/`FakeStage` as-is and wrap them the same way real specialists are wrapped
   for use as nodes (whatever `build_node`/the LLM-agent-as-node adapter does for a real `LlmAgent` — the
   fakes already satisfy the same "async generator yielding events, reads a JSON payload out of an
   attribute" contract `activation()` relied on; only the payload delivery channel changes from
   `self.instruction` to `node_input`). Update the fakes to read `ctx` / the injected payload instead of
   parsing `self.instruction.split("(JSON):\n", 1)[1]` — a small, mechanical change to every fake in
   `tests/fakes.py`, still one file (ADR-0005).
2. New thin doubles in `tests/fakes.py` — `FakeVerifierNode`/`FakeCriticNode` as `FunctionNode`s (or
   `@node`-decorated functions) that take `node_input: dict` directly and return a `Dossier`/verdict dict —
   closer to the target shape, less translation per test.

Recommend (2): the whole point of the migration is that specialists become plain nodes with `node_input`
payloads: node-shaped fakes are more honest doubles and let `tests/test_graph_nodes.py` (step 4) assert
`route_and_verify`'s own routing/error-containment logic without a `BaseAgent`-to-node adapter in the loop.
`_run` in `tests/fakes.py` (currently `Runner(agent=agent, ...)`) gains a `_run_node(node, node_input)`
sibling using `Runner(node=node, ...)` (verbatim signature, `runners.py:222-228`:
`def __init__(self, *, app: Optional[App] = None, agent: Optional[BaseAgent] = None, node: BaseNode | None = None)`).

## 9. What gets deleted

- `scanner/app/graph.py`: `Graph` base class, `_run_activations` (and its `ParallelAgent` import),
  `activation`, `_retry_json`, `parse_json`, `with_deadline`, `_ActivationSpec`, the deprecated aliases block.
- `scanner/app/pipeline_v2.py`: `PipelineV2` itself, `_RoundResult` (async-generator return workaround —
  a plain `async def` returning `InvestigateResult` doesn't need it).
- `web/fullscan/agent.py`'s and `scanner/app/graph.py`'s `specialists: dict = Field(..., exclude=True)`
  workaround (commit 66b1473) — specialists become graph nodes `graph_serialization.py` already knows how
  to render, not a hidden pydantic field on a `BaseAgent`.
- `ParallelAgent` import, and with it the last reason `docs/adr/0001-parallel-fanout.md`'s "Decision" section
  was pinned to `_run_activations`.

## 10. Open questions

1. **`ResumabilityConfig` scope**: it applies "to all agents in the app" (`_configs.py:39-40`) — need to
   confirm it does not change *non-workflow* behavior we still depend on elsewhere (there is none today
   besides the pipeline itself, but the Knowledge `AgentTool` consultant is a nested invocation worth
   re-checking under resume).
2. **Branch-name assertions**: `tests/test_stages.py` asserts literal branch strings
   (`"verify_round_0_0.verify_r0_0"`); `parallel_worker`'s `use_sub_branch=True` produces a different, ADK-
   chosen shape. Decide once step 4 lands whether to assert on `event.node_info.path` (idiomatic) or force
   branch names via a manual `asyncio.gather` + `override_branch` (loses the `parallel_worker` primitive,
   keeps exact names) — leaning idiomatic per ADR-0001's own acceptance of this cost.
3. **`state_schema` strictness**: `Workflow._validate_state_schema` also checks `FunctionNode` parameter
   names (`_workflow.py:180-208`) — need to confirm this doesn't fight `parameter_binding="node_input"` nodes,
   which bind from `node_input`, not `ctx.state`, by name.
4. **Parallel-branch state-merge semantics are undocumented** (already flagged in the R&D report,
   `docs/graphs/data-handling/` notes the gap): `route_and_verify`/`route_and_critique` workers must write
   *only* through `report_finding`/`disprove_finding`/`RunStore`, never through `ctx.state`, to sidestep it
   entirely — call this out in the node's docstring, not just here.
5. **Knowledge `AgentTool` consultant** (`scanner/app/knowledge_agent.py`) is invoked as a tool of a
   specialist `LlmAgent`; specialists are now themselves invoked via `ctx.run_node`, one level deeper than
   before — confirm `AgentTool`'s own budget/branch bookkeeping is unaffected (nothing in the R&D report
   suggests it isn't, but it wasn't exercised under `ctx.run_node` in any sample).

## Resolved (steps 1–4, 2026-09-12)

- **Names**: the skeleton type is `ScanSkeleton` (`scanner/core/workflow.py`) — `Skeleton` is already the
  DomainModeler's pre-pass in `scanner/core/domain.py`.
- **Open question 2 (branch names)**: `parallel_worker` items run as `<parent>@<run_id>/<node>@<n>` paths
  (observed: `drive@1/route_and_verify@b0/route_and_verify@1`); tests assert on outputs and the store, not on
  branch strings. `event.node_info.path` is the idiomatic handle when a test needs the shape.
- **Open question 3 (`state_schema` strictness)**: `Workflow._validate_state_schema` exempts the parameter
  names `ctx`, `node_input`, `self`, so nodes written as `(ctx, node_input)` under the default `'state'`
  binding coexist with `state_schema=WorkflowState`; `ctx.state["round"] = 1` inside a dynamic node persists
  (spike under `Runner(node=Workflow(...))`).
- **API facts that differed from §4**: every node run through `ctx.run_node` — the inner FunctionNode *and*
  the `@node(parallel_worker=True)` wrapper — must be built with `rerun_on_resume=True`, or ADK refuses it
  ("A node must have rerun_on_resume=True…"); a plain `BaseAgent` (our fakes) runs fine but `run_node`
  returns `None` for it (no `message_as_output`), while an `LlmAgent` returns its text / validated schema —
  `graph_nodes._model_json` accepts dict, str or None. A dynamic child's exception surfaces as
  `DynamicNodeFailError("Dynamic node <name> failed")` with the original in `.error` (`graph_nodes._why`).
  A root node's `node_input` is the user `Content` of the turn, so `tests/fakes._run_node` drives non-root
  inputs through a driver node, the way the graph will.
- **Extracted for both graphs**: `reconcile.build_queue`, `graph_nodes.report_direct`, `graph.pick_agent`.
