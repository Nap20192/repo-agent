"""confirm: static confirmation of PROVISIONALLY_VALID findings — Confirmation → annotation `repro_status`; promotion
happens inside the agent through a second report_finding with a higher confidence."""

from __future__ import annotations

from scanner.app.graph.workers import annotating_worker
from scanner.core.ports import RunStore
from scanner.core.workflow import Confirmation


def confirm_node(confirm, store: RunStore, max_parallel: int):
    """Static confirmation of PROVISIONALLY_VALID findings: Confirmation → annotation `repro_status`; promotion
    happens inside the agent through a second report_finding with a higher confidence. Items whose review is
    not provisional pass through with 0 calls (the worker's input is the viability worker's output list)."""
    def annotate(fd: dict, md: dict) -> None:
        c = Confirmation.model_validate({**md, "finding_id": fd["id"]})
        store.annotate(fd["id"], repro_status=c.repro_status)

    def only_provisional(item: dict) -> dict | None:
        fid = item.get("finding_id") or item.get("id")
        f = next((x for x in store.findings() if x.id == fid), None)
        return f.model_dump() if f is not None and f.review.get("status") == "PROVISIONALLY_VALID" else None
    return annotating_worker("confirm", confirm, store, {}, None, max_parallel, annotate, select=only_provisional)
