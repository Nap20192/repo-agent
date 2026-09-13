"""Every agent of the project, one folder each (agent.py SPEC, instruction.py, tools.py), declared with the same
AgentSpec and built by the same factory. `registry.AGENTS` lists them; the router lives next to it."""

from scanner.app.agents.base import AgentSpec, build, max_calls, new_agent

__all__ = ["AgentSpec", "build", "max_calls", "new_agent"]
