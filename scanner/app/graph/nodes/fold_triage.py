"""fold_triage: the sweep's batch outputs + the plan → the QueueState the audit drains (coverage artifact, fail open)."""

from __future__ import annotations

from google.adk.workflow import FunctionNode

from scanner.app.graph import planning
from scanner.core import Dossier
from scanner.core.ports import RunStore
from scanner.core.workflow import PlanState, QueueState


def fold_triage_node(store: RunStore) -> FunctionNode:
    def fold(node_input: list) -> dict:
        ps = PlanState.model_validate(store.artifact("plan") or {})
        planned = [f for b in ps.batches for f in b]
        queue, rejected, coverage = planning.fold_triage(node_input or [], planned, list(ps.queue))
        store.put_artifact("triage_coverage", coverage)
        if rejected:
            store.put_dossiers(-1, [Dossier.model_validate(d) for d in rejected])  # round -1: cleared by the sweep
        return QueueState(queue=queue, done=ps.done).model_dump()
    return FunctionNode(func=fold, name="fold_triage")
