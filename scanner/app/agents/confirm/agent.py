"""SPEC of the `confirm` agent (see scanner.app.agents.base.AgentSpec)."""

from scanner.app.agents.base import AgentSpec
from scanner.app.agents.confirm.instruction import INSTRUCTION
from scanner.app.agents.confirm.tools import ROSTER
from scanner.core.workflow import Confirmation

SPEC = AgentSpec(
    name='confirm',
    description="closes a provisional finding's open hops by reading code; promotes via report_finding",
    instruction=INSTRUCTION,
    tools=ROSTER,
    budget='confirm_max_calls',
    node="worker",
    output_schema=Confirmation,
    flag="critic",
)
