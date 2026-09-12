# ADK 2.9 multi-agent workflows — R&D report (2026-09-12)

Scope: how Google ADK (Python 2.9.0, `.venv/lib/python3.13/site-packages/google/adk/version.py`) wants
multi-agent workflows structured, and what that means for the staged SAST pipeline
(`Architect → ThreatModeler → Reconciler → Investigator loop → Critic → Reporter`, `scanner/app/pipeline_v2.py`).
Sources: the video and four sibling videos (auto-subtitles via yt-dlp), adk.dev docs, and the installed source.
`$ADK` below = `.venv/lib/python3.13/site-packages/google/adk`.

## 1. What the videos teach

**"Graph Engineering with ADK"** — Google Cloud Tech, 2026-09-10, 6:09, https://www.youtube.com/watch?v=Mzr7byMFy_4
(companion codelab: https://codelabs.developers.google.com/adk2/instructions).

- 00:47–01:22 — the "attempt #1" anti-pattern: one agent, one giant prompt that "promises everything" (fetch weather,
  analyse course, check fitness, build strategy). It answers confidently but "every one of those numbers is invented …
  when every step lives inside one model call, nothing can be fetched, nothing can be tested and nothing can be trusted."
  "The fix is not a better prompt. The fix is structure."
- 01:28–01:46 — layering: prompt engineering → context engineering → loop engineering (plan/act/check) → graph
  engineering ("many pieces of work wired together; the pieces are nodes, the wiring is edges").
- 01:50–02:42 — minimal 2-node graph: node 1 is a plain Python function ("no model, no cost"), node 2 an agent that
  reads the function's output. "The function and the agent appear the same: same list, same wiring." Principle:
  **"predictable work goes in functions and reasoning goes in the model."**
- 02:46–03:23 — **fan-out**: three independent fetches leave START at once. ADK 2 also has *dynamic* fan-out "if you
  have parallel processes but you don't know how many of them will run" — the shape is created at runtime.
- 03:24–03:47 — **join node**: "waits for the slowest process and bundles their outputs into one dictionary keyed by
  node name … you never wrote a merger, you never wrote an aggregator agent."
- 03:48–04:58 — **router**: an LLM router "works but costs tokens and can misread"; a deterministic router (fixed rules
  in a node) "wins when the set is closed and the signal is in the data"; use an LLM router only for free-text/open sets.
- 05:00–05:16 — cost accounting: three fetches + join + one strategist = **exactly one LLM call**.
- 05:20–05:49 — when to use which: "Can you draw the workflow before the input arrives? If yes, use a graph workflow.
  If the shape itself depends on the input (deep research), use a dynamic workflow — your code decides the shape at runtime."

Sibling videos (same channel; found with `yt-dlp --flat-playlist` over https://www.youtube.com/@googlecloudtech/videos):

- **Graph Engineering 101** (2026-09-03, https://www.youtube.com/watch?v=IrW0_f-w4kA): 00:36–01:06 harness = tools,
  memory, guardrails around the model; loop = the agent's plan/act cycle inside it; graph = the org-chart of agent and
  function nodes. 01:35–03:05 PR-review example: fan-out of five fetches → join → router ("if the code fails → fixer
  agent; if it passes → human approval"). 04:22–04:49 graph vs swarm: in a graph "the agent at a node doesn't need to
  know what happened before … predictability, debuggability and control for problems that can be strictly defined."
- **How to design a multi-agent system that skips the LLM** (2026-06-06, https://www.youtube.com/watch?v=Fzd0BWMH65s):
  06:30–06:58 route building is Dijkstra/serpentine math — "deterministic and, very importantly, unit-testable";
  12:36–13:49 the *pre-race* and *tick* agents are `LlmAgent`s whose model "is never actually called because the
  `before_model_callback` intercepts every invocation and returns deterministic tool calls" — keeps lifecycle, callbacks
  and telemetry at zero LLM cost; 18:11–18:48 "autopilot" runners subclass the agent and decide by heuristics.
- **Intro to multi-agent systems with ADK** (2026-06-08, https://www.youtube.com/watch?v=0Z0GUDakR_A): 08:27–10:45
  LLM-as-judge: a `search` agent and a `url_verifier` agent used *as tools* of an orchestrator; 10:58–11:37 one narrow
  task per agent, cheaper model for the simple ones.
- **Building long-running AI agents with ADK** (2026-06-16, https://www.youtube.com/watch?v=JsNbFnT0QCw): 02:07–02:27,
  04:27–04:54 durable state "is an enum in a database, not raw chat logs"; the agent is dormant between pause gates and
  resumes on an external event.

## 2. ADK 2.9 orchestration primitives

### 2.1 The picture in 2.x

`class BaseAgent(BaseNode)` (`$ADK/agents/base_agent.py:112`): every agent is a graph node. `SequentialAgent`,
`ParallelAgent`, `LoopAgent` are `@deprecated('... in favor of Workflow ... Workflow cannot yet be used as an LlmAgent
sub-agent')` (`$ADK/agents/sequential_agent.py:78-82`; same note in `parallel_agent.py`, `loop_agent.py:61`).
Docs: "Starting in ADK 2.0 for Python and Go, template workflows have been superseded by … graph-based workflows and
dynamic workflows" (https://adk.dev/agents/workflow-agents/). Migration page https://adk.dev/2.0/ : Python 2.0 GA
2026-05-19; `_run_async_impl` overrides "are bypassed" — use callbacks; exceptions must propagate for framework
retries; manual `append_event` is no longer safe.

Four documented styles (https://adk.dev/workflows/):

| Style | Construct | Use when (docs / video) |
|---|---|---|
| Graph | `Workflow(name, edges=[...])` | "you can draw the flow before input arrives" (video 05:27; https://adk.dev/graphs/) |
| Dynamic | `@node(rerun_on_resume=True)` function calling `ctx.run_node(...)`; `parallel_worker=True` | shape depends on input; loops as ordinary `while` (https://adk.dev/graphs/dynamic/) |
| Collaborative | `LlmAgent(sub_agents=[...])`, modes `chat`/`task`/`single_turn` | "you know the team but the request picks the subset" (codelab L3; https://adk.dev/workflows/collaboration/) |
| Template | `SequentialAgent`/`ParallelAgent`/`LoopAgent` | legacy; deprecated in 2.9 |

### 2.2 Graph API (installed source)

Exports (`$ADK/workflow/__init__.py`): `Workflow, START, Edge, DEFAULT_ROUTE, FunctionNode, JoinNode, Node, node,
RetryConfig, NodeTimeoutError, BaseNode`.

- `BaseNode` fields (`$ADK/workflow/_base_node.py:43-135`): `name` (must be an identifier), `description`,
  `rerun_on_resume=False` ("If True, the node reruns from scratch. If False, it completes immediately using the user's
  resuming input as the node's output"), `wait_for_output`, `retry_config: RetryConfig` (`max_attempts` default 5,
  exponential backoff, `exceptions` filter — `_retry_config.py`), `timeout` (→ `NodeTimeoutError`, retryable),
  `input_schema`/`output_schema` (Pydantic, validated per edge), `state_schema` (validates `ctx.state` writes;
  `Workflow._validate_state_schema` also checks FunctionNode parameter names, `_workflow.py:180-208`). `run()`
  normalises yields: `None` skipped, `Event` passthrough, `RequestInput` → interrupt, anything else → `Event(output=value)`
  (`_base_node.py:150-180`).
- `FunctionNode` (`_function_node.py:99`): wraps a sync/async function or generator. Parameters bind **from `ctx.state`
  by name** (`parameter_binding='state'`, default) — a param named `topic` receives `ctx.state['topic']`; `node_input`
  receives the predecessor's output; `ctx: Context` is injected. `parameter_binding='node_input'` makes the node usable
  as an agent's tool. Return value → `Event(output=...)`; `Event(state={...})` writes state; `Event(message=...)` is
  user-facing and **not** forwarded; `Event(route=...)` selects edges (https://adk.dev/graphs/data-handling/).
- Edge DSL (`_graph.py`): `edges=[("START", a, b, c)]` is a chain; a tuple element `(x, y, z)` fans out; a dict
  `{route: node | (nodes...)}` is a routing map; `DEFAULT_ROUTE` catches the rest; `Edge(from_node, to_node, route)` is
  the explicit form. Validation (`utils/_graph_validation.py`): unconditional cycles rejected ("Cycles must include at
  least one conditional (routed) edge"), START edges cannot carry routes, one `DEFAULT_ROUTE` per node, output/input
  schemas must match across an edge, a `mode='chat'` agent may only follow START.
- `JoinNode` (`_join_node.py`): `_requires_all_predecessors=True`; the scheduler fires it once every predecessor is
  `COMPLETED`, with `input = {pred_name: output}` (`_workflow.py`, `_buffer_barrier_trigger`).
- `Workflow` (`_workflow.py:145`): `edges`, `max_concurrency` (graph-scheduled nodes only), `rerun_on_resume=True`;
  `_run_impl` is the loop SETUP → schedule ready triggers → `asyncio.wait(FIRST_COMPLETED)` → `_handle_completion` →
  FINALIZE; at most one terminal node may produce output (`_finalize`). On a resumable app it emits
  `EventActions(agent_state={"nodes": {...status, interrupts}})` checkpoints and an `end_of_agent` marker.
- `LlmAgent` as a node (`_llm_agent_wrapper.py:305-385`): `node_input` becomes the user content; the final text (or the
  `output_schema` object) becomes `ctx.output`; `output_key` is also written to `state_delta`. `mode` defaults to
  `single_turn` inside a workflow and `chat` as a sub-agent (`llm_agent.py:400-409`).
- Dynamic: `Context.run_node(node, node_input, *, use_as_output, run_id, use_sub_branch, override_branch,
  override_isolation_scope, raise_on_wait)` (`$ADK/agents/context.py:420-477`; "Always `await` this method directly").
  `@node(parallel_worker=True, max_parallel_workers=N)` / `LlmAgent(parallel_worker=True)` runs the node once per item
  of a list input with bounded concurrency and yields the list of outputs (`_parallel_worker.py`).
- Roots: `App(root_agent=<BaseAgent | BaseNode>)` (`$ADK/apps/app.py:74-78`), `Runner(app=… | agent=… | node=…)`
  (`$ADK/runners.py:222-245`); `adk web` loads a module-level `root_agent` (`cli/utils/agent_loader.py:67-73`) — the
  official samples set `root_agent = Workflow(...)`. `cli/utils/graph_serialization.py` renders `edges`, `graph.nodes`,
  `route`, `rerun_on_resume` and node types `function|tool|join|workflow|agent` in the dev UI.

Minimal examples (verbatim, trimmed, from https://github.com/google/adk-python/tree/main/contributing/samples/workflows):

```python
# fan_out_fan_in/agent.py
def make_uppercase(node_input: str): return node_input.upper()
def count_characters(node_input: str): return len(node_input)
def reverse_string(node_input: str): return node_input[::-1]
join_node = JoinNode(name="join_for_results")
async def aggregate(node_input: dict[str, Any]):
  yield Event(message=f"Uppercase: {node_input['make_uppercase']} ... Reversed: {node_input['reverse_string']}")
root_agent = Workflow(name="root_agent",
    edges=[("START", (make_uppercase, count_characters, reverse_string), join_node, aggregate)])
```
```python
# route/agent.py — deterministic router after a structured-output agent
classify_input = Agent(name="classify_input", instruction="... {input}", output_schema=InputCategory, output_key="category")
def route_on_category(category: InputCategory):   # `category` is bound from ctx.state["category"]
  yield Event(route=category.category)
root_agent = Workflow(name="root_agent", edges=[
    ("START", process_input, classify_input, route_on_category),
    (route_on_category, {"question": answer_question, "statement": comment_on_statement, "other": handle_other})])
```
```python
# dynamic_nodes/agent.py — the loop is code, not a back-edge
@node(rerun_on_resume=True)
async def orchestrate(ctx: Context, node_input: str):
  yield Event(state={"topic": node_input})
  while True:
    headline = await ctx.run_node(generate_headline)
    feedback = Feedback.model_validate(await ctx.run_node(evaluate_headline, node_input=headline))
    if feedback.grade == "tech-related": yield headline; break
root_agent = Workflow(name="root_agent", edges=[("START", orchestrate)])
```
`loop/agent.py` does the same with a back-edge `(route_headline, {"unrelated": generate_headline})`;
`parallel_worker/agent.py` chains `find_related_topics` (`output_schema=list[str]`) → `@node(parallel_worker=True)` →
`Agent(parallel_worker=True, output_schema=TopicExplanation)` → `aggregate(node_input: list[TopicExplanation])`;
`agent_in_workflow/agent.py` puts a `mode="task"` intake agent in a graph with a `{"retry": intake_agent, DEFAULT_ROUTE: next}` loop.

### 2.3 Collaboration, tools, state, callbacks, resume

- **`sub_agents` + modes** (https://adk.dev/workflows/collaboration/): `chat` (transfer, manual handoff), `task`
  (auto-return via `finish_task`, may clarify with the user, must be a leaf), `single_turn` (no user interaction, may run
  in parallel, isolated session branch). `AgentTool` docstring: "prefer setting `mode='single_turn'` on the sub-agent …
  Direct usage of `AgentTool` is discouraged" (`$ADK/tools/agent_tool.py:116-127`).
- **Function tools** (https://adk.dev/tools-custom/function-tools/): signature → schema; `ToolContext` exposes `state`,
  `actions.escalate/transfer_to_agent`; `FunctionTool(fn, require_confirmation=True)` pauses for approval;
  `LongRunningFunctionTool` for external completion.
- **State** (https://adk.dev/sessions/state/, https://adk.dev/graphs/data-handling/): prefixes `app:`/`user:`/`temp:`;
  write via `output_key`, `Event(state=…)`, `ctx.state[...]` / `ToolContext.state` — never mutate `session.state`
  directly. Rule: "When only the next node needs a value, pass it along the edge as node output. Use state when a value
  must outlive the run, or be read by a tool, a callback, or `{key}` instruction templating." "Do not use it to move
  large payloads between nodes; use artifacts or a database tool instead." Templating: `{key}`, `{key?}`,
  `<Class.field from node_name>`.
- **Callbacks** (https://adk.dev/callbacks/): before/after agent, model, tool; returning a value short-circuits
  (`before_model` → `LlmResponse` skips the LLM — the "skip the LLM" trick; `before_tool` → dict skips the tool).
- **Resumability** (https://adk.dev/runtime/resume/, `$ADK/apps/_configs.py:29-46`):
  `App(resumability_config=ResumabilityConfig(is_resumable=True))`, resume with `runner.run_async(..., invocation_id=…)`;
  "at-least-once" — tools may run twice, keep them idempotent. Completed graph nodes are replayed from session events
  (`workflow/utils/_replay_interceptor.py`); `rerun_on_resume=True` reruns the body with cached child results; HITL via
  `yield RequestInput(message=…, payload=…, response_schema=…)` (https://adk.dev/graphs/human-input/). "An orchestrator
  that calls `ctx.run_node()` must set `rerun_on_resume: true`" (https://adk.dev/graphs/dynamic/).

## 3. Recommendations for the SAST pipeline

Today `PipelineV2(Graph(BaseAgent))` hand-rolls the graph in `_run_async_impl` and fans out with `ParallelAgent`
(`scanner/app/graph.py:143`, `docs/adr/0001-parallel-fanout.md`). ADK 2.9 deprecates every primitive this rests on, and
the migration page says `_run_async_impl` overrides are bypassed by the node engine. The target shape is a **root
`Workflow`** (a `BaseNode`, not a `BaseAgent`) — exactly the "revisit" condition ADR-0001 names: `Runner(node=…)` /
`App(root_agent=Workflow)` exist and `adk web` loads `root_agent = Workflow(...)` (the samples do this).

| Stage | ADK construct | Why |
|---|---|---|
| Static pre-pass (semgrep/gosec/…, entry points, index) | `FunctionNode` right after START with `retry_config` + `timeout`; returns a typed `Skeleton` (Pydantic) and writes `Event(state={"anchor_ids": …})` | "predictable work goes in functions" (video 02:38); zero LLM cost; typed edge checked by `output_schema` |
| Architect, DomainModeler, ThreatModeler | `LlmAgent(mode='single_turn', input_schema=…, output_schema=ArchitectureModel/…, output_key=…)` chained by edges | structured output replaces `parse_json` + JSON-nudge retry (`pipeline_v2.py:_stage`); node `retry_config` replaces `_retry_json`; `{architecture_model}` templating replaces payload stuffing |
| Grounding of artifacts (`ground_artifacts`) | `FunctionNode` | deterministic, unit-testable; already pure in `scanner/app/reconcile.py` |
| Reconciler | `FunctionNode` fed by a `JoinNode` over `{static_prepass, threat_model}` | join "bundles outputs into one dictionary keyed by node name" — no aggregator agent (video 03:40) |
| Investigator loop (queue drains in rounds; new hypotheses re-enter) | `@node(rerun_on_resume=True) async def investigate(ctx, node_input: Queue)` with `while queue:` and `await ctx.run_node(worker, batch)` where `worker = Agent(parallel_worker=True, max_parallel_workers=k, mode='single_turn')` | shape depends on data → dynamic workflow (video 05:38); `parallel_worker` = bounded dynamic fan-out; each item runs in its own sub-branch; resume replays finished workers |
| Specialist routing (CWE → kind → generic) | choose the worker node in code inside `investigate`, or a router `FunctionNode` yielding `Event(route=kind, output=batch)` with a `{kind: specialist}` map | "deterministic router wins when the set is closed and the signal is in the data" (video 04:43) — ours already is |
| `report_finding` gate, `dispatch` grounding | stay as tools on the investigator agents; gate checks in `before_tool_callback`, redaction inside the tool | callbacks are the sanctioned interception point (https://adk.dev/callbacks/) |
| Critic (adversarial pass over confirmed findings) | `LlmAgent(parallel_worker=True, output_schema=Verdict)` after the loop; a `FunctionNode` folds verdicts | generate-and-review pattern (https://adk.dev/workflows/patterns/) |
| Reporter | terminal `FunctionNode` rendering from State; an optional `single_turn` summariser before it | the workflow's single terminal output is the report; formatting needs no LLM |

Cross-cutting:

1. **Parallel investigations** = `parallel_worker` over a list input, not `ParallelAgent`. Concurrency cap via
   `max_parallel_workers`; per-branch budgets map onto per-worker `timeout`/`retry_config`. If exact branch names matter
   for tests, `ctx.run_node(..., override_branch=…)` exists (`context.py:457`), but the idiomatic assertion target is
   `event.node_info.path` (`name@run_id`, `$ADK/events/_branch_path.py`).
2. **Deterministic pre-pass feeding the graph**: START → `run_static_scanners` (FunctionNode, no LLM) → typed
   `Skeleton` output. Large payloads (anchor lists, index) stay in the SQLite State/artifacts; only ids and the skeleton
   flow along edges (docs: state is not for large payloads). `THREAT_MODEL=0` becomes a route: a tiny router node emits
   `route="skip_tm"` to bypass the modelling chain (`DEFAULT_ROUTE` → ThreatModeler).
3. **Resume**: enable `ResumabilityConfig(is_resumable=True)`; the graph replays completed stages from session events,
   which supersedes the hand-written `store.artifact(stage)` resume in `_stage`. Keep the artifacts table as the durable
   *product* store (long-running-agents video: "state is an enum in a database, not chat logs"), stop using it as the
   control-flow checkpoint. Tools must be idempotent (at-least-once).
4. **Cost discipline** (video 05:05): a scan with no anchors and `THREAT_MODEL=0` is zero LLM calls; the modelling
   chain is three; investigations are `len(queue)` bounded calls. An `LlmAgent` that must exist for lifecycle reasons but
   needs no reasoning can short-circuit via `before_model_callback` (Fzd0BWMH65s 12:56).
5. **Dev UI**: `graph_serialization.py` draws `Workflow` edges, routes and node types natively, so the specialists-dict
   `exclude=True` workaround (commit 66b1473) disappears once specialists are plain nodes.
6. **Do not** nest a `Workflow` under an `LlmAgent` or inside a `BaseAgent` (`sequential_agent.py:80-81`; ADR-0001
   experiment). Migrate top-down: root `Workflow` first, stages as nodes, tests through `Runner(node=…)` / `App`.

Open questions: a chat "lead" over the scan is not available yet (`Workflow` cannot be an `LlmAgent` sub-agent);
parallel-branch state-merge semantics are undocumented (https://adk.dev/graphs/data-handling/ notes the gap) — keep
workers writing only through `report_finding`/State, never through `ctx.state`.
