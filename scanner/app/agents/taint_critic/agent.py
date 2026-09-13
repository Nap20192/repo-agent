"""SPEC of the `taint_critic` specialist (see scanner.app.agents.base.AgentSpec)."""

from scanner.app.agents.base import AgentSpec
from scanner.app.agents.taint_critic.instruction import INSTRUCTION
from scanner.app.agents.taint_critic.tools import ROSTER

SPEC = AgentSpec(
    name='taint_critic',
    description='disproves taint findings: dominance, reachability',
    instruction=INSTRUCTION,
    tools=ROSTER,
    budget=20,
    node="worker",
    role='critique',
    kinds=frozenset(('entry', 'sink')),
    cwes=frozenset({"CWE-89", "CWE-78", "CWE-77", "CWE-88", "CWE-22", "CWE-79", "CWE-80", "CWE-918", "CWE-94", "CWE-95", "CWE-1336", "CWE-943", "CWE-611", "CWE-502", "CWE-601"}),
    skills=('counterevidence', 'severity-calibration'),
    flag="specialists",
)
