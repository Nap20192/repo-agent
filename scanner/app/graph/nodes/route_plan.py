"""route_plan: empty queue → export; otherwise fan the triage sweep out, one item per file batch."""

from __future__ import annotations

from google.adk.events import Event
from google.adk.workflow import FunctionNode

from scanner.app.graph import planning


def route_plan_node() -> FunctionNode:
    def route_plan(node_input: dict) -> Event:
        """empty → export; default → the triage sweep, which fans out one item per file batch."""
        route = planning.route_plan(node_input.get("queue", []))
        return Event(route=route, output=[{"files": b} for b in node_input.get("batches", [])] if route == "default" else node_input)
    return FunctionNode(func=route_plan, name="route_plan")
