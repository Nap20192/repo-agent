"""SPEC of the `authz_critic` specialist (see scanner.app.agents.base.AgentSpec)."""

from scanner.app.agents.authz_critic.instruction import INSTRUCTION
from scanner.app.agents.authz_critic.tools import ROSTER
from scanner.app.agents.base import AgentSpec

SPEC = AgentSpec(
    name='authz_critic',
    description='disproves authz findings: intended business rules',
    instruction=INSTRUCTION,
    tools=ROSTER,
    consults=('domain',),
    budget=20,
    node="worker",
    role='critique',
    kinds=frozenset(('authz',)),
    cwes=frozenset({"CWE-284", "CWE-285", "CWE-639", "CWE-862", "CWE-863", "CWE-840", "CWE-352", "CWE-287", "CWE-347", "CWE-915", "CWE-306", "CWE-307", "CWE-384", "CWE-613"}),
    skills=('counterevidence', 'severity-calibration'),
    flag="specialists",
)
