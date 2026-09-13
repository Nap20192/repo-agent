"""SPEC of the `dependency_critic` specialist (see scanner.app.agents.base.AgentSpec)."""

from scanner.app.agents.base import AgentSpec
from scanner.app.agents.dependency_critic.instruction import INSTRUCTION
from scanner.app.agents.dependency_critic.tools import ROSTER

SPEC = AgentSpec(
    name='dependency_critic',
    description='disproves dependency findings: patched, uncalled',
    instruction=INSTRUCTION,
    tools=ROSTER,
    budget=12,
    node="worker",
    role='critique',
    kinds=frozenset(('dependency',)),
    cwes=frozenset(),
    skills=('counterevidence', 'severity-calibration'),
    consults_knowledge=True,
    flag="specialists",
)
