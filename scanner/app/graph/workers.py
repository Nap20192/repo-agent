"""annotating_worker: a parallel worker over the model's confirmed findings — the shape of review, critic (viability)
and confirm. The agent's JSON becomes an annotation; verdict changes only through the gates inside the agent."""

from __future__ import annotations

import logging
from collections.abc import Callable

from google.adk.workflow import node

from scanner.adapter.skills import skills_for
from scanner.app.graph.helpers import model_json, pick_agent, why
from scanner.core import Finding
from scanner.core.ports import Router, RunStore

log = logging.getLogger("scanner.graph.workers")


def annotating_worker(name: str, agent, store: RunStore, specialists: dict, router: Router | None, max_parallel: int,
                      annotate: Callable[[dict, dict], None], role: str = "critique",
                      select: Callable[[dict], dict | None] | None = None):
    """A parallel worker over the model's confirmed findings: {finding, anchor, specialist, skills} → the agent;
    its JSON becomes an annotation through `annotate(finding_dict, json)`; verdict changes only through the gates
    inside the agent. No agent → 0 calls, the finding passes through. `select` maps the incoming item to the
    finding dict to work on (None = skip with 0 calls); by default the item IS the finding dict."""
    async def worker(ctx, node_input: dict) -> dict:
        if select is not None:
            picked_item = select(node_input)
            if picked_item is None:
                return {"finding_id": node_input.get("finding_id") or node_input.get("id", ""), "specialist": "", "error": "", "skipped": True}
            node_input = picked_item
        f = Finding.model_validate(node_input)
        if agent is None:
            return {"finding_id": f.id, "specialist": "", "error": ""}
        a = store.anchor(f.anchor_id)
        picked, sname, suffix = pick_agent(f, role, specialists, router, agent)
        payload = {"finding": f.model_dump(), "anchor": a.model_dump() if a else None, "specialist": sname,
                   "skills": skills_for(f.cwe, "", "critique")}
        if suffix:
            payload["instructions"] = suffix
        err, out = "", None
        try:
            out = await ctx.run_node(picked, payload, run_id=f"{name}_{f.id}")
        except Exception as e:  # noqa: BLE001 — a failed pass never loses a confirmed finding
            err = why(e)
            log.warning("%s %s failed: %s", name, f.id, err)
            store.add_note(f"{name} {f.id} failed: {err}", f.id)
        md = model_json(out)
        if md is not None:
            try:
                annotate(node_input, md)
            except (ValueError, KeyError) as e:
                err = err or f"invalid {name} JSON: {e}"
                store.add_note(f"{name} {f.id}: {err}", f.id)
        return {"finding_id": f.id, "specialist": sname, "error": err}
    return node(worker, parallel_worker=True, max_parallel_workers=max_parallel or None, rerun_on_resume=True, name=name)
