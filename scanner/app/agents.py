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
    CONFIRM_INSTRUCTION,
    CRITIC_INSTRUCTION,
    REVIEW_INSTRUCTION,
    THREAT_MODELER_INSTRUCTION,
    TRIAGE_BATCH_INSTRUCTION,
    TRIAGE_INSTRUCTION,
    VERIFIER_INSTRUCTION,
    VIABILITY_INSTRUCTION,
)
from scanner.core.workflow import Confirmation, ReviewVerdict, TriageBatch, Viability


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


def new_triage(model, tools: list, max_calls: int = 4) -> LlmAgent:
    """Rapid classification of one baseline (file/entry point): flagged or not, with classes — no verdicts."""
    return new_agent("triage", "flags files/entry points worth a specialist audit; cheap, read-only",
                     TRIAGE_INSTRUCTION, tools, max_calls, model=model)


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


# --- card 45: the verdict ladder and the batch triage -------------------------------------------------------

def new_review(model, tools: list, max_calls: int = 8) -> LlmAgent:
    """Independent validation of one confirmed finding: 13-rule checklist as data, status annotation;
    FALSE_POSITIVE only through disprove_finding."""
    return new_agent("review", "reviews one confirmed finding against the 13-rule checklist; annotates, disproves via the gate",
                     REVIEW_INSTRUCTION, tools, max_calls, model=model, output_schema=ReviewVerdict)


def new_viability(model, tools: list, max_calls: int = 6) -> LlmAgent:
    """Production viability of one reviewed finding; NON_VIABLE only through disprove_finding."""
    return new_agent("viability", "judges production reachability of one reviewed finding; fail-safe CONDITIONAL_VIABLE",
                     VIABILITY_INSTRUCTION, tools, max_calls, model=model, output_schema=Viability)


def new_confirm(model, tools: list, max_calls: int = 8) -> LlmAgent:
    """Static confirmation of a PROVISIONALLY_VALID finding: promotion by a higher-confidence report_finding."""
    return new_agent("confirm", "closes a provisional finding's open hops by reading code; promotes via report_finding",
                     CONFIRM_INSTRUCTION, tools, max_calls, model=model, output_schema=Confirmation)


def new_triage_batch(model, tools: list, max_calls: int = 4) -> LlmAgent:
    """Rapid classification of a batch of files (Capella triage): flagged or not, with classes; no verdicts."""
    return new_agent("triage_batch", "flags files worth a specialist audit, a batch at a time; cheap, read-only",
                     TRIAGE_BATCH_INSTRUCTION, tools, max_calls, model=model, output_schema=TriageBatch)
