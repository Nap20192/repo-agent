"""mark_sample: every survivor annotated viability=SAMPLE_OR_TEST (the target is a sample, not production)."""

from __future__ import annotations

from google.adk.workflow import FunctionNode

from scanner.core.ports import RunStore


def mark_sample_node(store: RunStore) -> FunctionNode:
    def mark_sample(node_input: list) -> list:
        for f in node_input or []:
            store.annotate(f["id"], viability="SAMPLE_OR_TEST")
        return node_input
    return FunctionNode(func=mark_sample, name="mark_sample")
