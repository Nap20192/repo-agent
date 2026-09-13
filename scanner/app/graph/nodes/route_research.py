"""route_research: none | budget → export; otherwise → dedupe (one edge to export per map: ADK has no duplicate edges)."""

from __future__ import annotations

from google.adk.events import Event
from google.adk.workflow import FunctionNode

from scanner.app.graph import planning
from scanner.core.workflow import ResearchResult


def route_research_node() -> FunctionNode:
    def route_research(node_input: dict) -> Event:
        r = ResearchResult.model_validate(node_input)
        route = planning.route_research(r.findings, r.stop == "budget")
        return Event(route="none" if route == "budget" else route, output=node_input)  # one edge to export per map (ADK: no duplicate edges)
    return FunctionNode(func=route_research, name="route_research")
