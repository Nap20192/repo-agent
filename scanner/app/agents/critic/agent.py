"""SPEC of the `critic` agent (see scanner.app.agents.base.AgentSpec)."""

from scanner.app.agents.base import AgentSpec
from scanner.app.agents.critic.instruction import INSTRUCTION
from scanner.app.agents.critic.tools import ROSTER

SPEC = AgentSpec(
    name='critic',
    description='adversarial pass: tries to disprove each confirmed finding; survivors stay confirmed',
    instruction=INSTRUCTION,
    tools=ROSTER,
    budget='critic_max_calls',
    role="critique",
)
