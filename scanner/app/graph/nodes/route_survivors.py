"""route_survivors: no confirmed model finding left → export; otherwise → route_intent with the survivors."""

from __future__ import annotations

from google.adk.events import Event
from google.adk.workflow import FunctionNode

from scanner.app.graph import planning
from scanner.app.graph.helpers import llm_findings
from scanner.core.ports import RunStore


def route_survivors_node(store: RunStore) -> FunctionNode:
    def route_survivors(node_input) -> Event:
        survivors = llm_findings(store)
        return Event(route=planning.route_survivors(len(survivors)), output=[f.model_dump() for f in survivors])
    return FunctionNode(func=route_survivors, name="route_survivors")
