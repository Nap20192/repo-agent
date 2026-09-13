"""dedupe: near-duplicate confirmed model findings → the duplicate rejected; the survivors fan the review out."""

from __future__ import annotations

import logging

from google.adk.workflow import FunctionNode

from scanner import core
from scanner.app.graph import planning
from scanner.app.graph.helpers import llm_findings
from scanner.core.ports import RunStore

log = logging.getLogger("scanner.graph.dedupe")


def dedupe_node(store: RunStore) -> FunctionNode:
    def dedupe(node_input) -> list:
        pairs = planning.dedupe(store.findings())
        for keeper, dup in pairs:
            store.set_status(dup, core.REJECTED, [f"duplicate of {keeper}"], note=f"dedupe: {dup} duplicates {keeper}")
        if pairs:
            log.info("dedupe: %d duplicates merged", len(pairs))
        return [f.model_dump() for f in llm_findings(store)]  # the review worker fans these out
    return FunctionNode(func=dedupe, name="dedupe")
