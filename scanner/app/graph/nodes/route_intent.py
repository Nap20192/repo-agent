"""route_intent: a sample / test target → mark_sample; production → the viability critic."""

from __future__ import annotations

from google.adk.events import Event
from google.adk.workflow import FunctionNode

from scanner.app.graph import planning
from scanner.core.ports import RunStore


def route_intent_node(store: RunStore) -> FunctionNode:
    def route_intent(node_input: list) -> Event:
        return Event(route=planning.route_intent(store.artifact("threat_model")), output=node_input)
    return FunctionNode(func=route_intent, name="route_intent")
