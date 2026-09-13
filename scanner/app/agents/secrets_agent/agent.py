"""SPEC of the `secrets` specialist (see scanner.app.agents.base.AgentSpec)."""

from scanner.app.agents.base import AgentSpec
from scanner.app.agents.secrets_agent.instruction import INSTRUCTION
from scanner.app.agents.secrets_agent.tools import ROSTER

SPEC = AgentSpec(
    name='secrets',
    description='hardcoded / leaked credentials',
    instruction=INSTRUCTION,
    tools=ROSTER,
    budget=10,
    node="worker",
    role='investigate',
    kinds=frozenset(('secret',)),
    cwes=frozenset({"CWE-798", "CWE-312", "CWE-321"}),
    skills=('information-disclosure',),
    flag="specialists",
    folder='secrets_agent',
)
