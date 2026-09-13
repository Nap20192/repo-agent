# ADR-0009: one folder per agent, one file per tool and per graph node, one template to add either

Status: accepted (2026-09-12). Refines ADR-0002 (ports in core) and ADR-0008 (the static graph); the layer rule
`core ← adapter ← app` (docs/architecture.md) is unchanged.

## Context

Adding an agent touched six files: `app/instructions.py` (one 460-line prompt file), `app/agents.py` (all factories),
`adapter/tools/rosters.py` (tool sets per role), `app/specialists.py` (registry + router), `app/graph_nodes.py` +
`app/pipeline.py` (node wrappers and a 250-line `build_workflow` of closures), `app/runner.py` (wiring). Tools were
grouped by accident of history (code / lsp / gates / common), scanners lived in one 270-line module. The owner asked for
"everything by one template: create an agent, register it as a node, folder style".

## Decision

- **Tools**: `scanner/adapter/tools/<group>/<tool>.py`, each exposing `make(ctx: ToolContext) -> tool`; the tool's
  docstring is the model-visible description. `registry.TOOLS` maps the name the model sees to the factory, in the
  order the model sees them; `make(names, ctx)` builds a roster. `ToolContext` carries what a run has (target, store
  run, index, reader, in-target check, entry points, settings) with lazy defaults. No roster functions per role.
- **Agents**: `scanner/app/agents/<name>/{__init__,agent,instruction,tools}.py`. `agent.py` declares one frozen
  `AgentSpec` (name, description, instruction, tool roster as registry names, budget = a Settings field or a literal,
  node kind, router axes: role / kinds / cwes, skills, callbacks flags, feature flag, web folder). `base.new_agent` stays
  the only LlmAgent factory; `base.build(spec, model, ctx, settings)` is the only way a spec becomes an agent.
  `registry.AGENTS` is an explicit list (no import magic); the router (`route`, `route_name`), the specialist subset
  (`REGISTRY`), the fallbacks (`verify` / `critic`) and the overlays live next to it. `shared.py` holds prompt
  sections several agents share.
- **Graph**: `scanner/app/graph/nodes/<node>.py`, each exposing one factory `<node>_node(...)` that takes exactly what
  the node needs and returns the ADK node; `stage.py` (document stage: timeout, degrade, resume) and `workers.py`
  (annotating parallel worker) are the two wrappers that turn an agent into a node; `workflow.py` holds `NODES` and
  the edge list only; `helpers.py`, `planning.py`, `reconcile.py` are the pure functions the nodes call.
- **Scanners**: `scanner/adapter/scanners/<scanner>.py` with `run(target) -> list[Anchor]`; `process.run_cmd` is the
  one subprocess point; `scan.py` runs them concurrently.
- **Runner**: `build_agents()` is one loop over `AGENTS` (a spec's `flag` off → `None`, the node stays as a no-op of
  the same name). `standalone()` (adk web per agent) uses the same loop.
- **Guards**: `tests/test_layers.py` — `agents/` never imports `graph/` or `runner`; `graph/` never imports `runner`;
  every agent folder has the four files; every tool file has `make(ctx)`; every node file has a `_node` factory.
  `tests/test_contracts.py` runs the same contract over every spec (roster ⊆ registry, tools named in the instruction
  exist on the agent, budget field exists, node kind valid).

## The template

```
scanner/app/agents/<name>/
  __init__.py      from .agent import SPEC
  agent.py         SPEC = AgentSpec(name, description, instruction=INSTRUCTION, tools=ROSTER, budget="<name>_max_calls", node="worker", ...)
  instruction.py   INSTRUCTION = OPERATING_PRINCIPLES + """..."""   (shared sections from ..shared)
  tools.py         ROSTER = ("read_file", "grep", ..., "report_finding")   (registry names, model-visible order)
```
1. add the folder; 2. one line in `registry.AGENTS`; 3. `<name>_max_calls` in `core/settings.py` (or a literal budget);
4. if it runs in the graph: `nodes/<name>.py` with `stage_node(...)` or `annotating_worker(...)` and one edge in
`workflow.py`; 5. `tests/test_contracts.py` picks the spec up by itself. A new tool: `tools/<group>/<tool>.py` with
`make(ctx)` + one line in `registry.TOOLS`.

## Consequences

- Prompt texts moved verbatim (the generator lifted them from the old modules); rosters are the same name sets; the
  edge list is byte-for-byte the one of ADR-0008 — `tests/test_graph_spec.py` passes unchanged.
- Two pre-existing instruction/roster gaps surfaced by the template test are allowlisted in `tests/test_contracts.py`
  (`viability` names `lsp_references`; `confirm` mentions `disprove_finding` to forbid it) — a follow-up card.
- The tool order the model sees is now the registry order for every roster (before: per-role assembler order). The
  sets are identical; only the Architect's `list_anchors` moved after the lsp tools.
- `docs/workflow-nodes.md` cites the old `pipeline.py:<line>` / `graph_nodes.py:<line>` locations; the node names are
  the file names now (`scanner/app/graph/nodes/<node>.py`), the line citations are historical.
