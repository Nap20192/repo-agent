"""LlmAgent factories. One `new_agent` carries the house conventions (fresh context per activation, per-branch
budget with a forced-JSON last call, tool-window digest, tool-call logging); the named factories only add
the role's instruction and defaults. Tools are injected by the runner."""

from __future__ import annotations

from google.adk.agents import LlmAgent

from scanner.app.callbacks import (
    budget_callback,
    log_tools_callback,
    tool_window_callback,
)
from scanner.app.instructions import (
    ARCHITECT_INSTRUCTION,
    CRITIC_INSTRUCTION,
    THREAT_MODELER_INSTRUCTION,
    VERIFIER_INSTRUCTION,
)


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
) -> LlmAgent:
    """An agent that sees only its instruction + its own tool turns; `overlay` is appended to the instruction."""
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
    )


def new_verifier(model, tools: list, max_calls: int = 30) -> LlmAgent:
    return new_agent("verify", "proves or rejects one hypothesis and reports the finding under the gate",
                     VERIFIER_INSTRUCTION, tools, max_calls, model=model)


def new_critic(model, tools: list, max_calls: int = 20) -> LlmAgent:
    return new_agent("critic", "adversarial pass: tries to disprove each confirmed finding; survivors stay confirmed",
                     CRITIC_INSTRUCTION, tools, max_calls, model=model)


def new_architect(model, tools: list, max_calls: int = 40, overlay: str = "") -> LlmAgent:
    """`overlay`: stack-specific instruction suffix (Go services / Node / Python web), chosen by the runner."""
    return new_agent("architect", "interprets the structural skeleton into an ArchitectureModel",
                     ARCHITECT_INSTRUCTION, tools, max_calls, model=model, overlay=overlay)


def new_threat_modeler(model, tools: list, max_calls: int = 6) -> LlmAgent:
    return new_agent("threat_modeler", "derives grounded threats and deployment intent from the ArchitectureModel",
                     THREAT_MODELER_INSTRUCTION, tools, max_calls, model=model, window=False)
