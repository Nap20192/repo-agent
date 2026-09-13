"""SPEC of the `taint` specialist (see scanner.app.agents.base.AgentSpec)."""

from scanner.app.agents.base import AgentSpec
from scanner.app.agents.taint.instruction import INSTRUCTION
from scanner.app.agents.taint.tools import ROSTER

SPEC = AgentSpec(
    name='taint',
    description='source→sink tracing for injection-class flaws',
    instruction=INSTRUCTION,
    tools=ROSTER,
    budget=30,
    node="worker",
    role='investigate',
    kinds=frozenset(('entry', 'sink')),
    cwes=frozenset({"CWE-89", "CWE-78", "CWE-77", "CWE-88", "CWE-22", "CWE-79", "CWE-80", "CWE-918", "CWE-94", "CWE-95", "CWE-1336", "CWE-943", "CWE-611", "CWE-502", "CWE-601"}),
    skills=('verifier-proof', 'source-aware-discovery'),
    flag="specialists",
)
