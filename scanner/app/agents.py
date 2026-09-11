"""LlmAgent factories: Verifier (= Investigator), Critic, Architect, ThreatModeler. Tools are injected by the runner."""

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


def new_verifier(model, tools: list, max_calls: int = 30) -> LlmAgent:
    return LlmAgent(
        name="verify",
        description="proves or rejects one hypothesis and reports the finding under the gate",
        model=model,
        instruction=VERIFIER_INSTRUCTION,
        tools=tools,
        include_contents="none",
        before_model_callback=[budget_callback(max_calls, per_branch=True), tool_window_callback()],
        before_tool_callback=log_tools_callback,
    )

def new_critic(model, tools: list, max_calls: int = 20) -> LlmAgent:
    return LlmAgent(
        name="critic",
        description="adversarial pass: tries to disprove each confirmed finding; survivors stay confirmed",
        model=model,
        instruction=CRITIC_INSTRUCTION,
        tools=tools,
        include_contents="none",
        before_model_callback=[budget_callback(max_calls, per_branch=True), tool_window_callback()],
        before_tool_callback=log_tools_callback,
    )

def new_architect(model, tools: list, max_calls: int = 40) -> LlmAgent:
    return LlmAgent(
        name="architect", description="interprets the structural skeleton into an ArchitectureModel",
        model=model, instruction=ARCHITECT_INSTRUCTION, tools=tools, include_contents="none",
        before_model_callback=[budget_callback(max_calls, per_branch=True), tool_window_callback()], before_tool_callback=log_tools_callback,
    )

def new_threat_modeler(model, tools: list, max_calls: int = 6) -> LlmAgent:
    return LlmAgent(
        name="threat_modeler", description="derives grounded threats and deployment intent from the ArchitectureModel",
        model=model, instruction=THREAT_MODELER_INSTRUCTION, tools=tools, include_contents="none",
        before_model_callback=budget_callback(max_calls, per_branch=True), before_tool_callback=log_tools_callback,
    )
