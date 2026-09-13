"""critic: production viability (Shannon critic) — Viability → annotation `viability`; NON_VIABLE without a gate call
is recorded as CONDITIONAL_VIABLE (fail-safe). The node is named `critic`; the agent behind it is `viability`."""

from __future__ import annotations

from scanner import core
from scanner.app.graph.workers import annotating_worker
from scanner.core.ports import Router, RunStore
from scanner.core.workflow import Viability


def viability_node(critic, store: RunStore, specialists: dict, router: Router | None, max_parallel: int):
    """Production viability (Shannon critic): Viability → annotation `viability`; NON_VIABLE without a gate call
    is recorded as CONDITIONAL_VIABLE (fail-safe)."""
    def annotate(fd: dict, md: dict) -> None:
        v = Viability.model_validate({**md, "finding_id": fd["id"]})
        val = v.viability
        if val == "NON_VIABLE" and any(f.id == fd["id"] and f.status == core.CONFIRMED for f in store.findings()):
            val = "CONDITIONAL_VIABLE"
            store.add_note(f"critic {fd['id']}: NON_VIABLE without a counter-quote — kept CONDITIONAL_VIABLE", fd["id"])
        store.annotate(fd["id"], viability=val)
    return annotating_worker("critic", critic, store, specialists, router, max_parallel, annotate)
