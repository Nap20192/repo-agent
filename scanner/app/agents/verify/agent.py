"""SPEC of the `verify` agent (see scanner.app.agents.base.AgentSpec)."""

from scanner.app.agents.base import AgentSpec
from scanner.app.agents.verify.instruction import INSTRUCTION
from scanner.app.agents.verify.tools import ROSTER

SPEC = AgentSpec(
    name='verify',
    description='proves or rejects one hypothesis and reports the finding under the gate',
    instruction=INSTRUCTION,
    tools=ROSTER,
    consults=('knowledge', 'domain'),
    budget='verifier_max_calls',
)
