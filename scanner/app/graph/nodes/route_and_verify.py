"""route_and_verify: the Investigator fan-out — one hypothesis in, one Dossier out; the class section + language overlay
ride along as the activation's instruction suffix (what the specialist agents used to be)."""

from __future__ import annotations

import logging

from google.adk.workflow import node

from scanner.adapter.skills import skill_for, skills_for
from scanner.app.agents.registry import lang_of, overlay
from scanner.app.graph.helpers import dossier_from_store, model_json, why
from scanner.core import Dossier, Hypothesis
from scanner.core.ports import RunStore

log = logging.getLogger("scanner.graph.verify")


def route_and_verify_node(store: RunStore, verifier, max_parallel: int):
    """Investigator fan-out: one hypothesis dict in, one Dossier dict out; ADK runs the items ≤ max_parallel at a
    time. Verdict from STORE facts (report_finding/disprove_finding wrote them); the model's JSON only adds
    notes/new_hypotheses; a failing item yields an error dossier instead of cancelling the batch."""
    async def route_and_verify(ctx, node_input: dict) -> dict:
        h = Hypothesis.model_validate(node_input)
        cls, suffix = overlay(h, lang_of(h.reads), "investigate")
        payload = {**h.model_dump(), "skill": skill_for(h.cwe, h.kind), "skills": skills_for(h.cwe, h.kind), "specialist": cls}
        if suffix:
            payload["instructions"] = suffix
        out, err = None, ""
        try:
            out = await ctx.run_node(verifier, payload, run_id=f"verify_{h.id}")
        except Exception as e:  # noqa: BLE001 — one lost hypothesis must not cancel the batch (ADK raises the first)
            err = why(e)
        d = dossier_from_store(store.findings(), h).model_copy(update={"specialist": cls})
        if (md := model_json(out)) is not None:
            try:
                m = Dossier.model_validate(md)
                d.notes, d.new_hypotheses = m.notes, m.new_hypotheses
            except ValueError as e:
                d.error = f"invalid Dossier JSON: {e}"
        elif not d.finding_id:  # nothing in the store and no JSON: the verifier never got there
            d.error = err or "no Dossier JSON and nothing reported"
        if d.error:
            log.warning("verify %s: %s", h.id, d.error)
        return {**d.model_dump(), "failed": bool(err)}  # failed: the specialist raised (not a soft "no JSON")
    return node(route_and_verify, parallel_worker=True, max_parallel_workers=max_parallel or None,
                rerun_on_resume=True, name="route_and_verify")
