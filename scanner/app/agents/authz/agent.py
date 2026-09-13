"""SPEC of the `authz` specialist (see scanner.app.agents.base.AgentSpec)."""

from scanner.app.agents.authz.instruction import INSTRUCTION
from scanner.app.agents.authz.tools import ROSTER
from scanner.app.agents.base import AgentSpec

SPEC = AgentSpec(
    name='authz',
    description='authorization, IDOR, authentication and session (A01, A07)',
    instruction=INSTRUCTION,
    tools=ROSTER,
    budget=30,
    node="worker",
    role='investigate',
    kinds=frozenset(('authz',)),
    cwes=frozenset({"CWE-284", "CWE-285", "CWE-639", "CWE-862", "CWE-863", "CWE-840", "CWE-352", "CWE-287", "CWE-347", "CWE-915", "CWE-306", "CWE-307", "CWE-384", "CWE-613"}),
    skills=('verifier-proof', 'authz-idor', 'business-logic'),
    flag="specialists",
)
