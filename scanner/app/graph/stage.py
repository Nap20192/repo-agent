"""stage_node: a modelling stage — a dynamic node running its LlmAgent as a child with a timeout; a failed or slow
model degrades to "no artifact" (a bare agent on a static edge cannot degrade: an exception fails the Workflow).
Resume: an artifact already in the store means the stage ran."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable

from google.adk.workflow import node

from scanner.app.graph.helpers import model_json, why
from scanner.core.ports import RunStore

log = logging.getLogger("scanner.graph.stage")


def stage_node(store: RunStore, agent, node_name: str, name: str, payload_of: Callable[[dict], dict], stage_timeout: float,
               timings: dict[str, float]):
    """A modelling stage: dynamic node `node_name` running `agent` as its child, artifact `name`."""
    async def stage(ctx, node_input):
        if (cached := store.artifact(name)) is not None:  # resume: the stage already ran for this run
            return cached
        if agent is None:
            return None
        t0, out = time.monotonic(), None
        try:
            out = await asyncio.wait_for(ctx.run_node(agent, payload_of(node_input), run_id=f"stage_{name}"), stage_timeout)
        except Exception as e:  # noqa: BLE001 — a failed/slow model stage degrades to "no artifact"
            log.warning("stage %s failed: %s", name, why(e))
            store.add_note(f"stage {name} failed: {why(e)}")
        timings[name] = round(time.monotonic() - t0, 3)
        parsed = model_json(out)
        if parsed is None:
            log.warning("stage %s: no valid JSON, continuing without it", name)
            store.add_note(f"stage {name}: no valid JSON")
        else:
            store.put_artifact(name, parsed)
        return parsed
    stage.__name__ = node_name
    return node(stage, rerun_on_resume=True, name=node_name)
