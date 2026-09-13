"""SPEC of the `domain_modeler` agent (see scanner.app.agents.base.AgentSpec)."""

from scanner.app.agents.base import AgentSpec
from scanner.app.agents.domain_modeler.instruction import INSTRUCTION
from scanner.app.agents.domain_modeler.tools import ROSTER

SPEC = AgentSpec(
    name='domain_modeler',
    description='turns the domain skeleton + ArchitectureModel into grounded business rules',
    instruction=INSTRUCTION,
    tools=ROSTER,
    budget='domain_modeler_max_calls',
    node="stage",
    window=False,
    flag="domain_model",
)
