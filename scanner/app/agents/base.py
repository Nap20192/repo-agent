"""AgentSpec — the one shape every agent of the project is declared in — and `new_agent`, the one LlmAgent factory
carrying the house conventions (fresh context per activation, per-branch budget with a forced-JSON last call,
tool-window digest, tool-call logging). `build()` turns a spec into a wired LlmAgent for one run."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from google.adk.agents import LlmAgent

from scanner.adapter.tools import ToolContext, make
from scanner.app.callbacks import budget_callback, log_tools_callback, tool_window_callback
from scanner.core.settings import Settings


@dataclass(frozen=True)
class AgentSpec:
    name: str  # the LlmAgent name, the web/<name> app, the registry key
    description: str
    instruction: str
    tools: tuple[str, ...]  # registry names (scanner/adapter/tools/registry.py), in the order the model sees them
    budget: str | int  # a Settings field name, or a literal (specialists; SPECIALIST_<NAME>_MAX_CALLS overrides it)
    node: str = ""  # how the graph runs it: "stage" (document, timeout+degrade), "worker" (parallel items), "tool" (AgentTool), "" (not in the graph)
    output_schema: type | None = None  # the document the FINAL answer must validate as (tools stay usable)
    role: str = ""  # "" | "investigate" | "critique" — the router's axis; verify/critic are the generic fallbacks
    kinds: frozenset[str] = frozenset()  # hypothesis kinds this specialist takes
    cwes: frozenset[str] = frozenset()  # CWEs this specialist takes (win over kinds)
    skills: tuple[str, ...] = ()
    window: bool = True  # tool-window digest callback
    per_branch: bool = True  # budget scope
    per_invocation: bool = False
    consults_knowledge: bool = False  # gets the Knowledge agent as an AgentTool
    flag: str = ""  # Settings switch that turns the agent off (None in the graph): "critic", "triage", "threat_model", ...
    folder: str = field(default="", compare=False)  # web/<folder>; differs from name only when the name shadows stdlib

    @property
    def app(self) -> str:
        return self.folder or self.name


def new_agent(
    name: str,
    description: str,
    instruction: str,
    tools: list,
    max_calls: int,
    *,
    model,
    per_branch: bool = True,
    per_invocation: bool = False,
    window: bool = True,
    stop_run: bool = False,
    overlay: str = "",
    output_schema=None,
) -> LlmAgent:
    """An agent that sees only its instruction + its own tool turns; `overlay` is appended to the instruction.
    `output_schema` (a core pydantic model) makes ADK enforce the shape of the FINAL answer; tools stay usable
    during the thought loop (google/adk/agents/llm_agent.py: output_schema + tools are supported together)."""
    before_model = [budget_callback(max_calls, per_branch=per_branch, stop_run=stop_run, per_invocation=per_invocation)]
    if window:
        before_model.append(tool_window_callback())
    return LlmAgent(
        name=name,
        model=model,
        description=description,
        instruction=instruction + (f"\n\n{overlay}" if overlay else ""),
        tools=tools,
        include_contents="none",
        before_model_callback=before_model,
        before_tool_callback=log_tools_callback,
        output_schema=output_schema,
    )


def max_calls(spec: AgentSpec, settings: Settings | None = None) -> int:
    """The budget of one activation: a Settings field, or the spec's literal with the SPECIALIST_<NAME>_MAX_CALLS override."""
    if isinstance(spec.budget, str):
        return getattr(settings or Settings(), spec.budget)
    v = os.environ.get(f"SPECIALIST_{spec.name.upper()}_MAX_CALLS", "")  # ponytail: the one env read outside Settings
    return int(v) if v.isdigit() and int(v) > 0 else spec.budget


def build(spec: AgentSpec, model, ctx: ToolContext, settings: Settings | None = None, *, overlay: str = "",
          extra_tools: list | None = None) -> LlmAgent:
    """A wired LlmAgent for one run: the spec's roster built from `ctx`, its budget from `settings`."""
    names = [n for n in spec.tools if n != "web_search" or (ctx.settings.web_search == "tavily" and ctx.settings.tavily_api_key)]
    tools = make(names, ctx) + list(extra_tools or [])
    return new_agent(spec.name, spec.description, spec.instruction, tools, max_calls(spec, settings), model=model,
                     per_branch=spec.per_branch, per_invocation=spec.per_invocation, window=spec.window, overlay=overlay,
                     output_schema=spec.output_schema)
