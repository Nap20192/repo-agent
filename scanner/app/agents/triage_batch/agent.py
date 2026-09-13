"""SPEC of the `triage_batch` agent (see scanner.app.agents.base.AgentSpec)."""

from scanner.app.agents.base import AgentSpec
from scanner.app.agents.triage_batch.instruction import INSTRUCTION
from scanner.app.agents.triage_batch.tools import ROSTER
from scanner.core.workflow import TriageBatch

SPEC = AgentSpec(
    name='triage_batch',
    description='flags files worth a specialist audit, a batch at a time; cheap, read-only',
    instruction=INSTRUCTION,
    tools=ROSTER,
    budget='triage_max_calls',
    node="worker",
    output_schema=TriageBatch,
    flag="triage",
)
