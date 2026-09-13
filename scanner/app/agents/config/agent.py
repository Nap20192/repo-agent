"""SPEC of the `config` specialist (see scanner.app.agents.base.AgentSpec)."""

from scanner.app.agents.base import AgentSpec
from scanner.app.agents.config.instruction import INSTRUCTION
from scanner.app.agents.config.tools import ROSTER

SPEC = AgentSpec(
    name='config',
    description='security misconfiguration, logging, crypto hygiene (A02, A05, A09)',
    instruction=INSTRUCTION,
    tools=ROSTER,
    budget=12,
    node="worker",
    role='investigate',
    kinds=frozenset(()),
    cwes=frozenset({"CWE-614", "CWE-1004", "CWE-942", "CWE-16", "CWE-209", "CWE-532", "CWE-778", "CWE-327", "CWE-328", "CWE-338", "CWE-295", "CWE-319", "CWE-1357"}),
    skills=('severity-calibration',),
    flag="specialists",
)
