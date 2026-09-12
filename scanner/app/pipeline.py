"""The scan graph on the ADK 2.9 Workflow API (docs/adr/0007): START → build_skeleton → plan → investigate → finish.

Stages: Architect → DomainModeler → ThreatModeler → grounding → direct findings → queue → Investigator rounds →
Critic → report. The bodies are dynamic nodes with their own try/except because ADK fails the whole Workflow on
any node error and a scan must degrade, not abort."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from pathlib import Path

from google.adk.workflow import START, Workflow, node
from pydantic import ConfigDict

from scanner import core
from scanner.app.graph import gate_hypotheses
from scanner.app.graph_nodes import (
    _model_json,
    _why,
    anchor_view,
    build_skeleton_node,
    direct_findings_node,
    route_and_critique_node,
    route_and_verify_node,
    triage_node,
)
from scanner.app.reconcile import KNOWN_WSTG, build_queue, ground_artifacts, key, reconcile
from scanner.core import Anchor, ArchitectureModel, Candidate, Dossier, Hypothesis, Threat, ThreatModel
from scanner.core.ports import Closeable, Router, RunStore
from scanner.core.workflow import InvestigateResult, QueueState, Report, ScanSkeleton

log = logging.getLogger("scanner.pipeline")

STAGES = ("architecture_model", "domain_map", "threat_model")


class ScanWorkflow(Workflow):
    """The Workflow plus the code Index it was wired with (closed by the runner)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)
    index: Closeable | None = None


def build_workflow(
    *, store: RunStore, target: str, verifier, critic=None, architect=None, domain_modeler=None, threat_modeler=None,
    triage=None,
    specialists: dict | None = None, router: Router | None = None,
    has_anchor: Callable[[str], bool], has_symbol: Callable[[str], bool],
    locate: Callable[[str], tuple[str, int] | None] | None = None,
    entry_points_fn: Callable[[], list[Candidate]] | None = None, threats: list[Threat] | None = None,
    source_files_fn: Callable[[], list[str]] | None = None,
    max_rounds: int = 4, max_hyps: int = 8, max_parallel: int = 3, stage_timeout: float = 600.0,
    index: Closeable | None = None,
) -> ScanWorkflow:
    """Wire the four-node graph for one run. The model's JSON only adds notes; verdicts come from the store."""
    specialists = specialists or {}
    threats = list(threats or [])
    timings: dict[str, float] = {}  # per run; `finish` persists it as the `timings` artifact
    direct_node = direct_findings_node(store, target)
    verify_node = route_and_verify_node(store, verifier, specialists, router, max_parallel)
    critique_node = route_and_critique_node(store, critic, specialists, router, max_parallel) if critic is not None else None
    sweep_node = triage_node(triage, max_parallel) if triage is not None else None

    async def triage_batch(ctx, accepted: list[Hypothesis], rnd: int) -> tuple[list[Hypothesis], list[Dossier]]:
        """Card 44: the cheap sweep over a batch's baselines (kind entry; scanner sinks and threats skip it).
        Unflagged → a rejected dossier with the reason (coverage stays provable); flagged → the triage class and
        reason ride along into the specialist audit. ponytail: per batch, so a sweep never looks past
        max_hyps items — widen the batch when triage is measurably cheaper than the audit."""
        base = [h for h in accepted if h.kind == "entry"]
        if sweep_node is None or not base:
            return accepted, []
        outs = await ctx.run_node(sweep_node, [h.model_dump() for h in base], run_id=f"triage_r{rnd}") or []
        by_id = {o.get("id"): o for o in outs}
        keep, rejected = [], []
        for h in accepted:
            o = by_id.get(h.id)
            if o is None or o.get("flagged", True):
                if o and o.get("why"):
                    h.claim += f". Triage: {o['why']}"
                if o and o.get("classes"):
                    h.cwe = o["classes"][0]
                keep.append(h)
            else:
                rejected.append(Dossier(hypothesis_id=h.id, verdict=core.REJECTED, notes=f"triage: {o.get('why', '')}",
                                        specialist="triage"))
        log.info("triage round %d: %d of %d baselines flagged", rnd, len(base) - len(rejected), len(base))
        return keep, rejected

    async def stage(ctx, agent, name: str, payload: dict) -> dict | None:
        """One LLM stage: cached artifact (resume) or the agent on `payload` bounded by stage_timeout; its JSON
        is persisted as the artifact; failure / invalid JSON → note, None."""
        if (cached := store.artifact(name)) is not None:
            return cached
        t0, out = time.monotonic(), None
        try:
            out = await asyncio.wait_for(ctx.run_node(agent, payload, run_id=f"stage_{name}"), stage_timeout)
        except Exception as e:  # noqa: BLE001 — a failed/slow model stage degrades to "no artifact"
            log.warning("stage %s failed: %s", name, _why(e))
            store.add_note(f"stage {name} failed: {_why(e)}")
        timings[name] = round(time.monotonic() - t0, 3)
        parsed = _model_json(out)
        if parsed is None:
            log.warning("stage %s: no valid JSON, continuing without it", name)
            store.add_note(f"stage {name}: no valid JSON")
        else:
            store.put_artifact(name, parsed)
        return parsed

    async def plan(ctx, node_input: dict) -> dict:
        """Direct findings → Architect → DomainModeler → ThreatModeler → grounding → the queue."""
        sk = ScanSkeleton.model_validate(node_input)
        out = await ctx.run_node(direct_node, [a.model_dump() for a in store.anchors()], run_id="direct_findings")
        anchors = [Anchor.model_validate(a) for a in (out or {}).get("remaining", [])]
        arts: dict = {}
        if architect is not None:
            payload = {"target": sk.target, "entry_points": [c.model_dump() for c in sk.entry_points], "anchors": anchor_view(anchors)}
            arts["architecture_model"] = await stage(ctx, architect, "architecture_model", payload)
        am = arts.get("architecture_model") or ArchitectureModel().model_dump()
        if domain_modeler is not None:
            from scanner.adapter.domain import extract  # adapter stays importable without the graph

            skeleton = extract(Path(target), index).model_dump() if Path(target).is_dir() else {}
            arts["domain_map"] = await stage(ctx, domain_modeler, "domain_map", {"architecture_model": am, "skeleton": skeleton})
        if threat_modeler is not None:
            payload = {"architecture_model": am, "domain_map": arts.get("domain_map") or {}}
            if arts.setdefault("threat_model", await stage(ctx, threat_modeler, "threat_model", payload)):
                try:
                    tm = ThreatModel.model_validate(arts["threat_model"])
                    log.info("threat model: %d threats, intent=%s", len(tm.threats), tm.intent)
                except ValueError as e:
                    log.warning("threat_model: invalid: %s", e)

        def grounded(symbol: str) -> bool:
            return has_symbol(symbol) or bool(locate and locate(symbol))

        am_g, dm_g, tm_g, notes = ground_artifacts(*(store.artifact(s) for s in STAGES), grounded, KNOWN_WSTG)
        for st, art in zip(STAGES, (am_g, dm_g, tm_g), strict=True):
            if art is not None:
                store.put_artifact(st, art)
        for n in notes:
            store.add_note(n)
        if notes:
            log.info("grounding: %d items dropped or corrected", len(notes))
        ctx.state["grounding_dropped"] = len(notes)
        queue, done = build_queue(store, anchors, threats, locate, entry_points_fn, source_files_fn)
        return QueueState(queue=queue, done=sorted(done)).model_dump()

    async def investigate(ctx, node_input: dict) -> dict:
        """Drain the queue in ≤ max_hyps batches through the gate and the Investigator fan-out until empty,
        the round limit or the budget."""
        qs = QueueState.model_validate(node_input)
        queue, done = list(qs.queue), set(qs.done)
        rnd, stop = int(ctx.state.get(core.STATE_ROUND) or 0), ""
        while queue:
            if rnd >= max_rounds:
                stop = "round limit"
                break
            batch, queue = queue[:max_hyps], queue[max_hyps:]
            done |= {key(h) for h in batch}  # gated-out items are done too: they never become grounded
            accepted = gate_hypotheses(batch, rnd, store, has_anchor, has_symbol, max_hyps)
            store.put_hypotheses(rnd, accepted)
            ctx.state[core.STATE_ROUND] = rnd + 1
            ctx.state["queue"] = len(queue)
            if not accepted:
                rnd += 1
                continue
            t0 = time.monotonic()
            accepted, triaged_out = await triage_batch(ctx, accepted, rnd)
            if not accepted:  # the sweep cleared the whole batch: no audit this round
                store.put_dossiers(rnd, triaged_out)
                rnd += 1
                continue
            outs = await ctx.run_node(verify_node, [h.model_dump() for h in accepted], run_id=f"verify_r{rnd}") or []
            timings[f"verify_{rnd}"] = round(time.monotonic() - t0, 3)
            dossiers = [Dossier.model_validate(o) for o in outs]
            budget = bool(ctx.state.get(core.STATE_BUDGET_EXHAUSTED))
            # every specialist of the round raised (not a soft "no JSON"): the round failed
            failed = "; ".join(d.error for d in dossiers if d.error) if outs and all(o.get("failed") for o in outs) else ""
            if failed and not budget and rnd == 0:
                raise RuntimeError(f"verify round 0 failed: {failed}")  # a failed run keeps no round-0 dossiers
            store.put_dossiers(rnd, [*triaged_out, *dossiers])
            rnd += 1
            if budget:
                stop = "budget"
                break
            if failed:
                stop = f"verify round {rnd - 1} failed: {failed}"
                break
            queue = reconcile([h for d in dossiers for h in d.new_hypotheses[:3]], queue, done)
        return InvestigateResult(rounds=rnd, stop=stop).model_dump()

    async def finish(ctx, node_input: dict) -> dict:
        """Critic over the model's confirmed findings (direct ones are facts), then the report."""
        res = InvestigateResult.model_validate(node_input)
        if critique_node is not None:
            confirmed = [f for f in store.findings() if f.status == core.CONFIRMED and f.source != "direct"]
            if confirmed:
                t0 = time.monotonic()
                await ctx.run_node(critique_node, [f.model_dump() for f in confirmed], run_id="critic")
                timings["critic"] = round(time.monotonic() - t0, 3)
                still = sum(1 for f in store.findings() if f.status == core.CONFIRMED and f.source != "direct")
                log.info("critic: %d confirmed → %d survived", len(confirmed), still)
        if res.stop:
            log.warning("scan_v3: finish (%s)", res.stop)
        ctx.state[core.STATE_STOP_REASON] = res.stop
        store.put_artifact("timings", timings)
        return Report(rounds=res.rounds, stop_reason=res.stop, timings=timings).model_dump()

    a = build_skeleton_node(store, target, entry_points_fn)
    b, c, d = (node(f, rerun_on_resume=True, name=f.__name__) for f in (plan, investigate, finish))
    # no state_schema: ADK rejects undeclared keys, and the budget callback writes per-branch keys (`budget_exhausted:<branch>`)
    return ScanWorkflow(name="scan_v3", edges=[(START, a), (a, b), (b, c), (c, d)], index=index)
