"""plan: anchors + grounded threats + entry-point baselines → the hypothesis queue (reconcile.build_queue)."""

from __future__ import annotations

import logging
from collections.abc import Callable

from google.adk.events import Event
from google.adk.workflow import FunctionNode

from scanner.app.graph.reconcile import build_queue, split_direct
from scanner.core import Candidate
from scanner.core.ports import RunStore
from scanner.core.workflow import QueueState

log = logging.getLogger("scanner.graph.plan")


def plan_node(store: RunStore, locate, entry_points_fn: Callable[[], list[Candidate]] | None) -> FunctionNode:
    def plan(node_input) -> Event:
        """The queue; route "empty" → export when there is nothing to investigate."""
        queue, done = build_queue(store, split_direct(store.anchors())[1], None, locate, entry_points_fn, None)
        qs = QueueState(queue=queue, done=sorted(done)).model_dump()
        store.put_artifact("plan", qs)
        log.info("plan: %d hypotheses", len(queue))
        return Event(route="empty" if not queue else "default", output=qs)
    return FunctionNode(func=plan, name="plan")
