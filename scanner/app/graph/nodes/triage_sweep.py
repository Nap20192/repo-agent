"""triage_sweep: the triage agent over FILE BATCHES, in parallel — {"files": [...]} in, TriageBatch dict out."""

from __future__ import annotations

import logging

from google.adk.workflow import node

from scanner.app.graph.helpers import model_json, why
from scanner.core.ports import RunStore

log = logging.getLogger("scanner.graph.triage")


def triage_sweep_node(triage, store: RunStore, max_parallel: int):
    """Triage fan-out over FILE BATCHES (Shannon research/triage): one {"files": [...]} in → TriageBatch dict out.
    No agent → every file flagged (the audit decides); a failed/JSON-less batch → no classifications, so
    fold_triage marks its files missing and keeps their baselines (fail open, coverage=reduced)."""
    async def triage_sweep(ctx, node_input: dict) -> dict:
        files = list((node_input or {}).get("files", []))
        if triage is None:
            return {"classifications": [{"file": f, "flagged": True, "classes": [], "why": "triage off"} for f in files]}
        out = None
        try:
            out = await ctx.run_node(triage, {"files": files}, run_id=f"triage_{abs(hash(tuple(files)))}")
        except Exception as e:  # noqa: BLE001 — one failed batch must not cancel the sweep
            log.warning("triage batch %s: %s", files[:1], why(e))
            store.add_note(f"triage batch failed: {why(e)}")
        md = model_json(out) or {}
        cls = [c for c in md.get("classifications", []) if isinstance(c, dict)]
        for c in cls:
            c["classes"] = [x.upper() for x in c.get("classes", []) if isinstance(x, str) and x.upper().startswith("CWE-")]
            c["why"] = str(c.get("why", ""))[:300]
        return {"classifications": cls}
    return node(triage_sweep, parallel_worker=True, max_parallel_workers=max_parallel or None,
                rerun_on_resume=True, name="triage_sweep")
