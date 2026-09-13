"""SPEC of the `architect` agent (see scanner.app.agents.base.AgentSpec)."""

from scanner.app.agents.architect.instruction import INSTRUCTION
from scanner.app.agents.architect.tools import ROSTER
from scanner.app.agents.base import AgentSpec

SPEC = AgentSpec(
    name='architect',
    description='interprets the structural skeleton into an ArchitectureModel',
    instruction=INSTRUCTION,
    tools=ROSTER,
    budget='architect_max_calls',
    node="stage",
    flag="threat_model",
)
