"""SPEC of the `domain` consultant (see scanner.app.agents.base.AgentSpec)."""

from scanner.app.agents.base import AgentSpec
from scanner.app.agents.domain.instruction import INSTRUCTION
from scanner.app.agents.domain.tools import ROSTER

SPEC = AgentSpec(
    name="domain",
    description="answers ONE question about an entity or a business rule: owner field, rules, guards — from the domain map, verified in code",
    instruction=INSTRUCTION,
    tools=ROSTER,
    budget="domain_max_calls",
    node="tool",
    per_branch=False,  # an AgentTool call is a fresh root invocation (branch None): budget per invocation
    per_invocation=True,
)
