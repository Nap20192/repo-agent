"""model: the one modelling stage — the Model agent answers {"architecture_model", "threat_model"} in one pass; both are
grounded (reconcile.ground_artifacts) and stored as artifacts. No agent (THREAT_MODEL=0) → no artifacts, the plan
works from anchors alone."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable

from google.adk.workflow import node

from scanner.app.graph.helpers import model_json, why
from scanner.app.graph.nodes.build_skeleton import anchor_view
from scanner.app.graph.reconcile import KNOWN_WSTG, ground_artifacts
from scanner.core.ports import RunStore
from scanner.core.workflow import DirectResult, ScanSkeleton

log = logging.getLogger("scanner.graph.model")


def model_node(store: RunStore, agent, has_symbol: Callable[[str], bool], locate, stage_timeout: float, timings: dict[str, float]):
    async def model(ctx, node_input: dict) -> dict | None:  # node_input: DirectResult + skeleton fields
        if (am := store.artifact("architecture_model")) is not None:  # resume: the stage already ran for this run
            return {"architecture_model": am, "threat_model": store.artifact("threat_model")}
        if agent is None:
            return None
        d, sk = DirectResult.model_validate(node_input), ScanSkeleton.model_validate(node_input)
        payload = {"target": sk.target, "entry_points": [c.model_dump() for c in sk.entry_points], "anchors": anchor_view(d.remaining)}
        t0, out = time.monotonic(), None
        try:
            out = await asyncio.wait_for(ctx.run_node(agent, payload, run_id="stage_model"), stage_timeout)
        except Exception as e:  # noqa: BLE001 — a failed/slow model stage degrades to "no model"
            log.warning("stage model failed: %s", why(e))
            store.add_note(f"stage model failed: {why(e)}")
        timings["model"] = round(time.monotonic() - t0, 3)
        parsed = model_json(out)
        if not parsed:
            log.warning("stage model: no valid JSON, continuing without it")
            store.add_note("stage model: no valid JSON")
            return None

        def grounded(symbol: str) -> bool:
            return has_symbol(symbol) or bool(locate and locate(symbol))

        am_g, _, tm_g, notes = ground_artifacts(parsed.get("architecture_model"), None, parsed.get("threat_model"), grounded, KNOWN_WSTG)
        for n in notes:
            store.add_note(n)
        if am_g is not None:
            store.put_artifact("architecture_model", am_g)
        if tm_g is not None:
            store.put_artifact("threat_model", tm_g)
        log.info("model: %d threats, %d grounding notes", len((tm_g or {}).get("threats", [])), len(notes))
        return {"architecture_model": am_g, "threat_model": tm_g}
    return node(model, rerun_on_resume=True, name="model")
