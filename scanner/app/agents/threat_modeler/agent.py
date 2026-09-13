"""SPEC of the `threat_modeler` agent (see scanner.app.agents.base.AgentSpec)."""

from scanner.app.agents.base import AgentSpec
from scanner.app.agents.threat_modeler.instruction import INSTRUCTION
from scanner.app.agents.threat_modeler.tools import ROSTER

SPEC = AgentSpec(
    name='threat_modeler',
    description='derives grounded threats and deployment intent from the ArchitectureModel',
    instruction=INSTRUCTION,
    tools=ROSTER,
    budget='threat_modeler_max_calls',
    node="stage",
    window=False,
    flag="threat_model",
)
