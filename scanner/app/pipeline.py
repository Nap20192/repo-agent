"""The scan graph as a STATIC ADK 2.9 Workflow (docs/adr/0008): Shannon's Capella stages as graph edges.

    START → scan → build_skeleton → direct_findings ─┬→ architect ─┐
                                                     └→ recon ─────┴→ join_model → domain_modeler → threat_modeler
    → ground → plan → route_plan {empty → export | default → triage_sweep} → fold_triage → audit
    → route_research {none|budget → export | default → dedupe} → review → route_survivors {none → export | default}
    → route_intent {sample → mark_sample | default → critic} ; mark_sample → calibrate ; critic → confirm → calibrate → export

Constructs, on purpose (spike: docs/plans/shannon-graph.md §6): FunctionNodes for deterministic work and the four
route maps; a JoinNode for the architect ∥ recon fan-in; the modelling stages are dynamic nodes that run their
LlmAgent as a child (a bare agent on a static edge cannot degrade: an exception fails the Workflow); the sweeps
(triage, review, viability, confirm) are parallel workers over their agent; `audit` is the one dynamic loop whose
shape depends on data; `export` and `calibrate` are plain nodes with several incoming edges (JoinNode would wait
for branches a route skipped). Verdicts come only from the store (report_finding / disprove_finding); the
model's JSON adds notes and annotations."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from pathlib import Path

from google.adk.events import Event
from google.adk.workflow import DEFAULT_ROUTE, START, FunctionNode, JoinNode, Workflow, node
from pydantic import ConfigDict

from scanner import core
from scanner.adapter.static import ScanResult
from scanner.app import plan as planning
from scanner.app.graph import gate_hypotheses
from scanner.app.graph_nodes import (
    _model_json,
    _why,
    anchor_view,
    build_skeleton_node,
    confirm_node,
    direct_findings_node,
    review_node,
    route_and_verify_node,
    scan_node,
    triage_sweep_node,
    viability_node,
)
from scanner.app.reconcile import KNOWN_WSTG, build_queue, ground_artifacts, key, reconcile
from scanner.core import Anchor, ArchitectureModel, Candidate, Dossier, Threat, ThreatModel
from scanner.core.ports import Closeable, Router, RunStore
from scanner.core.workflow import (
    DirectResult,
    ExportResult,
    PlanState,
    QueueState,
    ReconMap,
    ResearchResult,
    ScanSkeleton,
)

log = logging.getLogger("scanner.pipeline")

STAGES = ("architecture_model", "domain_map", "threat_model")
NODES = ("scan", "build_skeleton", "direct_findings", "architect", "recon", "join_model", "domain_modeler",
         "threat_modeler", "ground", "plan", "route_plan", "triage_sweep", "fold_triage", "audit", "route_research",
         "dedupe", "review", "route_survivors", "route_intent", "mark_sample", "critic", "confirm", "calibrate", "export")


class ScanWorkflow(Workflow):
    """The Workflow plus the code Index it was wired with (closed by the runner)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)
    index: Closeable | None = None


def _llm(store: RunStore, status: str = core.CONFIRMED):
    return [f for f in store.findings() if f.status == status and f.source != "direct"]


def build_workflow(
    *, store: RunStore, target: str, verifier, critic=None, architect=None, domain_modeler=None, threat_modeler=None,
    triage=None, review=None, confirm=None,
    specialists: dict | None = None, router: Router | None = None,
    has_anchor: Callable[[str], bool], has_symbol: Callable[[str], bool],
    locate: Callable[[str], tuple[str, int] | None] | None = None,
    entry_points_fn: Callable[[], list[Candidate]] | None = None, threats: list[Threat] | None = None,
    scan_fn: Callable[[], ScanResult] | None = None,
    source_files_fn: Callable[[], list[str]] | None = None,
    recon_fn: Callable[[], dict] | None = None,
    knowledge_cfg=None,
    max_rounds: int = 4, max_hyps: int = 8, max_parallel: int = 3, stage_timeout: float = 600.0,
    triage_batch: int = 10, triage_parallel: int = 4,
    index: Closeable | None = None,
) -> ScanWorkflow:
    """Wire the 24-node graph for one run. Agents left None turn their node into a no-op of the same name so
    the diagram is stable; `scan_fn` None means the anchors are already in the store (tests)."""
    specialists = specialists or {}
    threats = list(threats or [])
    timings: dict[str, float] = {}  # per run; `export` persists it as the `timings` artifact
    verify_node = route_and_verify_node(store, verifier, specialists, router, max_parallel)

    # --- modelling stages: dynamic nodes around the agent (timeout + degrade to "no artifact") ---------------
    def stage_node(agent, node_name: str, name: str, payload_of: Callable[[dict], dict]):
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
        stage.__name__ = node_name
        return node(stage, rerun_on_resume=True, name=node_name)

    def architect_payload(direct: dict) -> dict:
        d = DirectResult.model_validate(direct)  # direct_findings passes the skeleton through (target, entry_points)
        sk = ScanSkeleton.model_validate(direct)
        return {"target": sk.target, "entry_points": [c.model_dump() for c in sk.entry_points], "anchors": anchor_view(d.remaining)}

    def domain_payload(joined: dict) -> dict:
        am = (joined or {}).get("architect") or ArchitectureModel().model_dump()
        from scanner.adapter.domain import extract  # adapter stays importable without the graph

        skeleton = extract(Path(target), index).model_dump() if Path(target).is_dir() else {}
        return {"architecture_model": am, "skeleton": skeleton, "recon": (joined or {}).get("recon") or {}}

    def threat_payload(_dm) -> dict:
        am = store.artifact("architecture_model") or ArchitectureModel().model_dump()
        rec = store.artifact("recon") or {}
        return {"architecture_model": am, "domain_map": store.artifact("domain_map") or {}, "auth": rec.get("auth", [])}

    architect_node = stage_node(architect, "architect", "architecture_model", architect_payload)
    domain_node = stage_node(domain_modeler, "domain_modeler", "domain_map", domain_payload)
    threat_node = stage_node(threat_modeler, "threat_modeler", "threat_model", threat_payload)

    def recon(node_input) -> dict:
        """Shannon pre-recon deliverables without a model: sinks by class, guards, config files (adapter/recon)."""
        if (cached := store.artifact("recon")) is not None:
            return cached
        rec = {"sources": [], "sinks": {}, "auth": [], "config_files": []}
        if recon_fn is not None:
            try:
                rec = ReconMap.model_validate(recon_fn()).model_dump()  # JSON-native: the artifact store dumps it
            except Exception as e:  # noqa: BLE001 — recon is an inventory; an error is an empty inventory
                log.warning("recon failed: %s", e)
                store.add_note(f"recon failed: {e}")
        store.put_artifact("recon", rec)
        return rec

    def ground(node_input) -> dict:
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
        if tm_g:
            try:
                tm = ThreatModel.model_validate(tm_g)
                log.info("threat model: %d threats, intent=%s", len(tm.threats), tm.intent)
            except ValueError as e:
                log.warning("threat_model: invalid: %s", e)
        return {"dropped": len(notes)}

    async def plan(ctx, node_input: dict) -> dict:
        """Queue + file batches (Shannon plan: every file in some investigation); `grounding_dropped` to state."""
        ctx.state["grounding_dropped"] = int((node_input or {}).get("dropped", 0))
        queue, done = build_queue(store, _non_direct(store), threats, locate, entry_points_fn, source_files_fn)
        files = sorted({h.reads[0] for h in queue if h.kind == "entry" and h.reads})
        ps = PlanState.model_validate(planning.plan_state(queue, done, files, triage_batch)).model_dump()
        store.put_artifact("plan", ps)  # fold_triage reads the queue back from here (the sweep's output is per batch)
        log.info("plan: %d hypotheses, %d files in %d triage batches", len(queue), len(files), len(ps["batches"]))
        return ps

    def route_plan(node_input: dict) -> Event:
        """empty → export; default → the triage sweep, which fans out one item per file batch."""
        route = planning.route_plan(node_input.get("queue", []))
        return Event(route=route, output=[{"files": b} for b in node_input.get("batches", [])] if route == "default" else node_input)

    sweep = triage_sweep_node(triage, store, triage_parallel)

    def fold(node_input: list) -> dict:
        ps = PlanState.model_validate(store.artifact("plan") or {})
        planned = [f for b in ps.batches for f in b]
        queue, rejected, coverage = planning.fold_triage(node_input or [], planned, list(ps.queue))
        store.put_artifact("triage_coverage", coverage)
        if rejected:
            store.put_dossiers(-1, [Dossier.model_validate(d) for d in rejected])  # round -1: cleared by the sweep
        return QueueState(queue=queue, done=ps.done).model_dump()

    async def audit(ctx, node_input: dict) -> dict:
        """Drain the queue in ≤ max_hyps batches through the gate and the Investigator fan-out until empty,
        the round limit or the budget — the one node whose shape depends on data."""
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
            outs = await ctx.run_node(verify_node, [h.model_dump() for h in accepted], run_id=f"verify_r{rnd}") or []
            timings[f"verify_{rnd}"] = round(time.monotonic() - t0, 3)
            dossiers = [Dossier.model_validate(o) for o in outs]
            budget = bool(ctx.state.get(core.STATE_BUDGET_EXHAUSTED))
            failed = "; ".join(d.error for d in dossiers if d.error) if outs and all(o.get("failed") for o in outs) else ""
            if failed and not budget and rnd == 0:
                raise RuntimeError(f"verify round 0 failed: {failed}")  # a failed run keeps no round-0 dossiers
            store.put_dossiers(rnd, dossiers)
            rnd += 1
            if budget:
                stop = "budget"
                break
            if failed:
                stop = f"verify round {rnd - 1} failed: {failed}"
                break
            queue = reconcile([h for d in dossiers for h in d.new_hypotheses[:3]], queue, done)
        ctx.state[core.STATE_STOP_REASON] = stop
        return ResearchResult(rounds=rnd, stop=stop, findings=len(_llm(store))).model_dump()

    def route_research(node_input: dict) -> Event:
        r = ResearchResult.model_validate(node_input)
        route = planning.route_research(r.findings, r.stop == "budget")
        return Event(route="none" if route == "budget" else route, output=node_input)  # one edge to export per map (ADK: no duplicate edges)

    def dedupe(node_input) -> list:
        pairs = planning.dedupe(store.findings())
        for keeper, dup in pairs:
            store.set_status(dup, core.REJECTED, [f"duplicate of {keeper}"], note=f"dedupe: {dup} duplicates {keeper}")
        if pairs:
            log.info("dedupe: %d duplicates merged", len(pairs))
        return [f.model_dump() for f in _llm(store)]  # the review worker fans these out

    rev = review_node(review, store, specialists, router, max_parallel)

    def route_survivors(node_input) -> Event:
        survivors = _llm(store)
        return Event(route=planning.route_survivors(len(survivors)), output=[f.model_dump() for f in survivors])

    def route_intent(node_input: list) -> Event:
        return Event(route=planning.route_intent(store.artifact("threat_model")), output=node_input)

    def mark_sample(node_input: list) -> list:
        for f in node_input or []:
            store.annotate(f["id"], viability="SAMPLE_OR_TEST")
        return node_input

    viab = viability_node(critic, store, specialists, router, max_parallel)

    conf = confirm_node(confirm, store, max_parallel)  # confirms only PROVISIONALLY_VALID reviews (0 calls otherwise)

    def calibrate(node_input) -> dict:
        intent = (store.artifact("threat_model") or {}).get("intent", "production")
        cal = planning.calibrate_all(store.findings(), intent, store.artifact("architecture_model"), knowledge_cfg)
        for fid, c in cal.items():
            store.annotate(fid, calibration=c)
        return {"calibrated": len(cal)}

    async def export(ctx, node_input) -> dict:
        stop = str(ctx.state.get(core.STATE_STOP_REASON) or "")
        rounds = int(ctx.state.get(core.STATE_ROUND) or 0)
        ctx.state[core.STATE_STOP_REASON] = stop
        cov = store.artifact("triage_coverage") or {}
        reductions = [f"triage missing {len(cov['missing'])} files"] if cov.get("missing") else []
        reductions += [t.removeprefix("stage ") for t, _ in ((n["text"], n["ref"]) for n in store.notes()) if t.startswith("stage ") and "failed" in t]
        store.put_artifact("timings", timings)
        if stop:
            log.warning("scan: export (%s)", stop)
        res = ExportResult(rounds=rounds, stop_reason=stop, timings=timings,
                           coverage="reduced" if reductions else "complete", reductions=reductions)
        log.info("export: %d confirmed (%d direct), coverage %s", len(store.findings()) - len(_llm(store, core.REJECTED)),
                 sum(f.source == "direct" for f in store.findings()), res.coverage)
        return res.model_dump()

    # --- assembly --------------------------------------------------------------------------------------------
    n_scan = scan_node(store, scan_fn) if scan_fn is not None else FunctionNode(func=lambda node_input: {"anchors": len(store.anchors())}, name="scan")
    n_skel = build_skeleton_node(store, target, entry_points_fn)
    n_direct = direct_findings_node(store, target)
    n_recon = FunctionNode(func=recon, name="recon")
    n_join = JoinNode(name="join_model")
    n_ground = FunctionNode(func=ground, name="ground")
    n_plan = node(plan, rerun_on_resume=True, name="plan")
    n_route_plan = FunctionNode(func=route_plan, name="route_plan")
    n_fold = FunctionNode(func=fold, name="fold_triage")
    n_audit = node(audit, rerun_on_resume=True, name="audit")
    n_route_research = FunctionNode(func=route_research, name="route_research")
    n_dedupe = FunctionNode(func=dedupe, name="dedupe")
    n_route_surv = FunctionNode(func=route_survivors, name="route_survivors")
    n_route_intent = FunctionNode(func=route_intent, name="route_intent")
    n_mark = FunctionNode(func=mark_sample, name="mark_sample")
    n_cal = FunctionNode(func=calibrate, name="calibrate")
    n_export = node(export, rerun_on_resume=True, name="export")

    edges = [
        (START, n_scan, n_skel, n_direct, (architect_node, n_recon), n_join, domain_node, threat_node, n_ground, n_plan, n_route_plan),
        (n_route_plan, {"empty": n_export, DEFAULT_ROUTE: sweep}),
        (sweep, n_fold, n_audit, n_route_research),
        (n_route_research, {"none": n_export, DEFAULT_ROUTE: n_dedupe}),
        (n_dedupe, rev, n_route_surv),
        (n_route_surv, {"none": n_export, DEFAULT_ROUTE: n_route_intent}),
        (n_route_intent, {"sample": n_mark, DEFAULT_ROUTE: viab}),
        (n_mark, n_cal),
        (viab, conf, n_cal, n_export),
    ]
    # no state_schema: ADK rejects undeclared keys, and the budget callback writes per-branch keys (`budget_exhausted:<branch>`)
    return ScanWorkflow(name="scan", edges=edges, index=index)


def _non_direct(store: RunStore) -> list[Anchor]:
    from scanner.app.reconcile import split_direct

    return split_direct(store.anchors())[1]
