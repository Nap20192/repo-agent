"""critique: the one adversarial pass — near-duplicates merged, then the Critic over every confirmed model finding in
parallel: it disproves through the gate (finding → uncertain) or leaves it confirmed; its JSON is the `review`
annotation. No agent (CRITIC=0) → the findings pass through."""

from __future__ import annotations

import logging

from google.adk.workflow import node

from scanner import core
from scanner.adapter.skills import skills_for
from scanner.app.agents.registry import lang_of, overlay
from scanner.app.graph import planning
from scanner.app.graph.helpers import llm_findings, model_json, why
from scanner.core import Finding
from scanner.core.ports import RunStore

log = logging.getLogger("scanner.graph.critique")


def critique_node(store: RunStore, critic, max_parallel: int):
    worker = critic_worker(store, critic, max_parallel)

    async def critique(ctx, node_input) -> dict:
        pairs = planning.dedupe(store.findings())
        for keeper, dup in pairs:
            store.set_status(dup, core.REJECTED, [f"duplicate of {keeper}"], note=f"dedupe: {dup} duplicates {keeper}")
        if pairs:
            log.info("dedupe: %d duplicates merged", len(pairs))
        findings = llm_findings(store)
        if critic is None or not findings:
            return {"critiqued": 0, "disproved": 0}
        outs = await ctx.run_node(worker, [f.model_dump() for f in findings], run_id="critique") or []
        disproved = sum(1 for f in store.findings() if f.status == core.UNCERTAIN and f.source != "direct")
        return {"critiqued": len(outs), "disproved": disproved}
    return node(critique, rerun_on_resume=True, name="critique")


def critic_worker(store: RunStore, critic, max_parallel: int):
    """The Critic over one finding dict: {finding, anchor, specialist, skills, instructions} → the agent; the verdict
    changes only through disprove_finding inside it; its JSON becomes the `review` annotation."""
    async def critic_item(ctx, node_input: dict) -> dict:  # node_input: one finding dict
        f = Finding.model_validate(node_input)
        a = store.anchor(f.anchor_id)
        cls, suffix = overlay(f, lang_of([f.file]), "critique")
        payload = {"finding": f.model_dump(), "anchor": a.model_dump() if a else None, "specialist": cls, "skills": skills_for(f.cwe, "", "critique")}
        if suffix:
            payload["instructions"] = suffix
        err, out = "", None
        try:
            out = await ctx.run_node(critic, payload, run_id=f"critic_{f.id}")
        except Exception as e:  # noqa: BLE001 — a failed pass never loses a confirmed finding
            err = why(e)
            log.warning("critic %s failed: %s", f.id, err)
            store.add_note(f"critic {f.id} failed: {err}", f.id)
        md = model_json(out) or {}
        still_confirmed = any(x.id == f.id and x.status == core.CONFIRMED for x in store.findings())
        claimed = bool(md.get("disproved"))
        status = "UNCERTAIN" if not still_confirmed else ("NEEDS_RESEARCH" if claimed else "VALID")
        if claimed and still_confirmed:
            store.add_note(f"critic {f.id}: disproved in prose without a counter-quote — kept confirmed", f.id)
        store.annotate(f.id, review={"status": status, "reasoning": str(md.get("reason", ""))[:500]})
        return {"finding_id": f.id, "specialist": cls, "error": err, "status": status}
    return node(critic_item, parallel_worker=True, max_parallel_workers=max_parallel or None, rerun_on_resume=True, name="critic")
