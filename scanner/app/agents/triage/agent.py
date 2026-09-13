"""SPEC of the `triage` agent (see scanner.app.agents.base.AgentSpec)."""

from scanner.app.agents.base import AgentSpec
from scanner.app.agents.triage.instruction import INSTRUCTION
from scanner.app.agents.triage.tools import ROSTER

SPEC = AgentSpec(
    name='triage',
    description='flags files/entry points worth a specialist audit; cheap, read-only',
    instruction=INSTRUCTION,
    tools=ROSTER,
    budget='triage_max_calls',
)
