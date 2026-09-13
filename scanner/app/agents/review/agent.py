"""SPEC of the `review` agent (see scanner.app.agents.base.AgentSpec)."""

from scanner.app.agents.base import AgentSpec
from scanner.app.agents.review.instruction import INSTRUCTION
from scanner.app.agents.review.tools import ROSTER
from scanner.core.workflow import ReviewVerdict

SPEC = AgentSpec(
    name='review',
    description='reviews one confirmed finding against the 13-rule checklist; annotates, disproves via the gate',
    instruction=INSTRUCTION,
    tools=ROSTER,
    consults=('knowledge', 'domain'),
    budget='review_max_calls',
    node="worker",
    output_schema=ReviewVerdict,
    flag="critic",
)
