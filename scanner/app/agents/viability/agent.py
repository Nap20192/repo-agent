"""SPEC of the `viability` agent (see scanner.app.agents.base.AgentSpec)."""

from scanner.app.agents.base import AgentSpec
from scanner.app.agents.viability.instruction import INSTRUCTION
from scanner.app.agents.viability.tools import ROSTER
from scanner.core.workflow import Viability

SPEC = AgentSpec(
    name='viability',
    description='judges production reachability of one reviewed finding; fail-safe CONDITIONAL_VIABLE',
    instruction=INSTRUCTION,
    tools=ROSTER,
    budget='viability_max_calls',
    node="worker",
    output_schema=Viability,
    flag="critic",
)
