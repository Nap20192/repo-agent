"""review: independent validation (Shannon review) — ReviewVerdict → annotation `review`."""

from __future__ import annotations

from scanner import core
from scanner.app.graph.workers import annotating_worker
from scanner.core.ports import Router, RunStore
from scanner.core.workflow import ReviewVerdict


def review_node(review, store: RunStore, specialists: dict, router: Router | None, max_parallel: int):
    """Independent validation (Shannon review): ReviewVerdict → annotation `review`. FALSE_POSITIVE without a
    disprove_finding call (the finding is still confirmed) is recorded as NEEDS_RESEARCH."""
    def annotate(fd: dict, md: dict) -> None:
        v = ReviewVerdict.model_validate({**md, "finding_id": fd["id"]})
        status = v.status
        if status == "FALSE_POSITIVE" and any(f.id == fd["id"] and f.status == core.CONFIRMED for f in store.findings()):
            status = "NEEDS_RESEARCH"  # the agent said FP but never disproved it through the gate
            store.add_note(f"review {fd['id']}: FALSE_POSITIVE without a counter-quote — kept as NEEDS_RESEARCH", fd["id"])
        store.annotate(fd["id"], review={"status": status, "reasoning": v.reasoning, "repro_hints": v.repro_hints,
                                         "checklist": {k: r.model_dump() for k, r in v.checklist.items()}})
    return annotating_worker("review", review, store, specialists, router, max_parallel, annotate)
