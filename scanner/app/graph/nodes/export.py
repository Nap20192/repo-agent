"""export: the terminal node — stop reason, rounds, timings → ExportResult (SARIF + summary are written by the runner)."""

from __future__ import annotations

import logging

from google.adk.workflow import node

from scanner import core
from scanner.app.graph.helpers import llm_findings
from scanner.core.ports import RunStore
from scanner.core.workflow import ExportResult

log = logging.getLogger("scanner.graph.export")


def export_node(store: RunStore, timings: dict[str, float]):
    async def export(ctx, node_input) -> dict:
        stop = str(ctx.state.get(core.STATE_STOP_REASON) or "")
        rounds = int(ctx.state.get(core.STATE_ROUND) or 0)
        ctx.state[core.STATE_STOP_REASON] = stop
        reductions = [t.removeprefix("stage ") for t in (n["text"] for n in store.notes()) if t.startswith("stage ") and "failed" in t]
        store.put_artifact("timings", timings)
        if stop:
            log.warning("scan: export (%s)", stop)
        res = ExportResult(rounds=rounds, stop_reason=stop, timings=timings,
                           coverage="reduced" if reductions else "complete", reductions=reductions)
        log.info("export: %d confirmed (%d direct), coverage %s", len(store.findings()) - len(llm_findings(store, core.REJECTED)),
                 sum(f.source == "direct" for f in store.findings()), res.coverage)
        return res.model_dump()
    return node(export, rerun_on_resume=True, name="export")
