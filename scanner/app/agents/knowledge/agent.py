"""SPEC of the `knowledge` agent (see scanner.app.agents.base.AgentSpec)."""

from scanner.app.agents.base import AgentSpec
from scanner.app.agents.knowledge.instruction import INSTRUCTION
from scanner.app.agents.knowledge.tools import ROSTER

SPEC = AgentSpec(
    name="knowledge",
    description="answers questions about known vulnerabilities from OSV, GitHub Advisory DB, NVD, EPSS, KEV, deps.dev",
    instruction=INSTRUCTION,
    tools=ROSTER,
    budget="knowledge_max_calls",
    node="tool",
    per_branch=False,  # an AgentTool call is a fresh root invocation (branch None): budget per invocation
    per_invocation=True,
)
