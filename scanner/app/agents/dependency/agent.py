"""SPEC of the `dependency` specialist (see scanner.app.agents.base.AgentSpec)."""

from scanner.app.agents.base import AgentSpec
from scanner.app.agents.dependency.instruction import INSTRUCTION
from scanner.app.agents.dependency.tools import ROSTER

SPEC = AgentSpec(
    name='dependency',
    description='vulnerable dependencies: advisory + reachability (A06)',
    instruction=INSTRUCTION,
    tools=ROSTER,
    budget=15,
    node="worker",
    role='investigate',
    kinds=frozenset(('dependency',)),
    cwes=frozenset(),
    skills=('dependency-advisory',),
    consults_knowledge=True,
    flag="specialists",
)
