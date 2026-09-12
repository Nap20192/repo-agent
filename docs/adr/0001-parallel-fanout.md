---
status: superseded by 0007 (2026-09-12)
---

> Superseded by `docs/adr/0007-workflow-graph.md`: the graph root is now an ADK `Workflow`; `ParallelAgent` and
> `_Graph._run_activations` are gone. The evidence below (a `Workflow` cannot run under a `BaseAgent` root) still holds.
# Fan-out of Investigators/Critics stays on `ParallelAgent`; ADK `Workflow` is not usable inside our graph agent

## Context

`_Graph._run_activations` (scanner/app/graph.py) runs N runtime-created clones of one `LlmAgent`
in parallel on isolated branches (`verify_round_<r>_<chunk>.verify_r<r>_<i>`) and yields their events
to the Runner, which is how `adk web` and the tests (`event.branch` assertions) observe the fan-out.
ADK 2.9.0 deprecates `ParallelAgent` "in favor of Workflow" and warns: "Workflow cannot yet be used as
an LlmAgent sub-agent" (`google/adk/agents/parallel_agent.py:235-238`).

## Evidence (google-adk 2.9.0, paths under `.venv/lib/python3.13/site-packages/google/adk/`)

- Dynamic fan-out itself exists: `agents/context.py:420` `Context.run_node(node, node_input, *, run_id,
  use_sub_branch, override_branch, …)`; `workflow/_node_runner.py:214-226` honours `override_branch`, so
  exact branch names are reachable; `workflow/_parallel_worker.py` runs a node per input item with
  `max_parallel_workers`.
- But node events never pass through the agent's generator: `workflow/_node_runner.py:349-364`
  `_enqueue_event` → `ctx._invocation_context._enqueue_event(event)`, and `Workflow._run_impl`
  yields nothing (`workflow/_workflow.py:216-280`, ends with `return; yield`). The queue is created only
  when the Runner runs a **root node** (`runners.py:561` "Events flow through ic._event_queue via
  NodeRunner", `runners.py:761 _consume_event_queue`); the live-stream interleaver (`runners.py:1633`)
  is the `run_live` path.
- Experiment (scratchpad `wf_fanout.py`): a `BaseAgent` that builds `Workflow(edges=[(START,
  node(fanout))])` and fans out three clones via `ctx.run_node(..., override_branch=...)` under
  `Runner(agent=…).run_async` fails at the first child event with
  `RuntimeError: _enqueue_event called but _event_queue is not set. Ensure the Runner initialises
  _event_queue on InvocationContext.` (`agents/invocation_context.py:284`).

## Decision

Keep `ParallelAgent` in `_run_activations`. Migrating means turning `PipelineV2` itself into a
`Workflow` root run with `Runner(node=…)`, which changes the event stream, the branch naming
(`name@run_id`, `_branch_path.py:170-184`) and the `adk web` entrypoint (agent loader expects
`root_agent`, `cli/utils/agent_loader.py:67-73`). That is a rewrite of the graph, not a swap of the
fan-out primitive, and buys nothing today.

## Revisit when

- ADK lets a `Workflow` run under an agent (event queue initialised for agent roots, or Workflow
  yields child events), or documents `Runner(node=…)` + `adk web` for node roots; or
- `ParallelAgent` is actually removed. Then port `PipelineV2` as a whole: stages as nodes, the
  Investigator loop as a `FunctionNode` calling `ctx.run_node` per hypothesis with
  `override_branch` to keep today's branch names.
