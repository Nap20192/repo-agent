"""SPEC of the `model` agent (see scanner.app.agents.base.AgentSpec)."""

from scanner.app.agents.base import AgentSpec
from scanner.app.agents.model.instruction import INSTRUCTION
from scanner.app.agents.model.tools import ROSTER

SPEC = AgentSpec(
    name="model",
    description="builds the ArchitectureModel and the ThreatModel of the target in one pass",
    instruction=INSTRUCTION,
    tools=ROSTER,
    budget="model_max_calls",
    node="stage",
    flag="threat_model",
)
