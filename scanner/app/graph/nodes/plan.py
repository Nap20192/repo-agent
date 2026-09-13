"""plan: the hypothesis queue + file batches (Shannon plan: every file in some investigation) → PlanState artifact."""

from __future__ import annotations

import logging
from collections.abc import Callable

from google.adk.workflow import node

from scanner.app.graph import planning
from scanner.app.graph.reconcile import build_queue, split_direct
from scanner.core import Candidate, Threat
from scanner.core.ports import RunStore
from scanner.core.workflow import PlanState

log = logging.getLogger("scanner.graph.plan")


def plan_node(store: RunStore, threats: list[Threat], locate, entry_points_fn: Callable[[], list[Candidate]] | None,
              source_files_fn: Callable[[], list[str]] | None, triage_batch: int):
    async def plan(ctx, node_input: dict) -> dict:
        """Queue + file batches (Shannon plan: every file in some investigation); `grounding_dropped` to state."""
        ctx.state["grounding_dropped"] = int((node_input or {}).get("dropped", 0))
        queue, done = build_queue(store, split_direct(store.anchors())[1], threats, locate, entry_points_fn, source_files_fn)
        files = sorted({h.reads[0] for h in queue if h.kind == "entry" and h.reads})
        ps = PlanState.model_validate(planning.plan_state(queue, done, files, triage_batch)).model_dump()
        store.put_artifact("plan", ps)  # fold_triage reads the queue back from here (the sweep's output is per batch)
        log.info("plan: %d hypotheses, %d files in %d triage batches", len(queue), len(files), len(ps["batches"]))
        return ps
    return node(plan, rerun_on_resume=True, name="plan")
