"""Nodes of the ADK 2.9 Workflow graph (card 43, docs/plans/workflow-migration.md §2/§4), built per run by
factories that close over the RunStore and the wired agents — the graph itself is assembled in scanner.app.pipeline.

Deterministic steps are FunctionNodes (`build_skeleton`, `direct_findings`); the fan-outs are parallel-worker
nodes (`route_and_verify`, `route_and_critique`) that route each item to a specialist in code, run it with
`ctx.run_node` and contain the failure per item — ADK raises the first worker exception and cancels the batch
otherwise (`google/adk/workflow/_parallel_worker.py`)."""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

from google.adk.workflow import FunctionNode, node

from scanner import core
from scanner.adapter.knowledge import enrichment_for, imported_by
from scanner.adapter.skills import skill_for, skills_for
from scanner.adapter.static import ScanResult
from scanner.app.graph import dossier_from_store, parse_json, pick_agent
from scanner.app.reconcile import direct_finding, split_direct
from scanner.core import Anchor, Candidate, Dossier, Finding, Hypothesis
from scanner.core.ports import Router, RunStore
from scanner.core.workflow import ScanSkeleton

log = logging.getLogger("scanner.graph_nodes")


def skeleton(target: str, entry_points_fn: Callable[[], list[Candidate]] | None) -> ScanSkeleton:
    """What the modelling stages receive: the target and its entry points (anchors are read from the store by plan)."""
    return ScanSkeleton(target=target, entry_points=list(entry_points_fn()) if entry_points_fn else [])


def anchor_view(anchors: list[Anchor]) -> list[dict]:
    """The trimmed anchor list the modelling stages see."""
    return [{"id": a.id, "tool": a.tool, "cwe": a.cwe, "file": a.file, "line": a.line, "message": a.message[:120]}
            for a in anchors]


def scan_node(store: RunStore, scan_fn: Callable[[], ScanResult]) -> FunctionNode:
    """START → the pre-pass as a graph node: run the static scanners, save their anchors, record what ran and
    what failed in the `scan` artifact. Resume: an existing artifact means the anchors are already in the store."""
    def scan(node_input) -> dict:  # node_input: the user turn that started the run, unused
        if (cached := store.artifact("scan")) is not None:
            return {k: cached[k] for k in ("anchors", "ran", "failed")}
        res = scan_fn()
        for tool, why in res.failed.items():
            log.warning("static: %s failed: %s", tool, why)
        store.save_anchors(res.anchors)
        by_tool = {t: n for t in res.ran if (n := sum(a.tool == t for a in res.anchors))}
        log.info("pre-pass: %d anchors — %s%s", len(res.anchors), ", ".join(f"{t} {n}" for t, n in by_tool.items()),
                 f"; failed: {', '.join(res.failed)}" if res.failed else "")
        store.put_artifact("scan", {"anchors": len(res.anchors), "by_tool": by_tool, "ran": res.ran, "failed": res.failed})
        return {"anchors": len(res.anchors), "ran": res.ran, "failed": res.failed}
    return FunctionNode(func=scan, name="scan")


def build_skeleton_node(store: RunStore, target: str, entry_points_fn: Callable[[], list[Candidate]] | None) -> FunctionNode:
    """START → skeleton. The pre-pass (scanners) already ran in runner.prepare; this node reads its anchors."""
    def build_skeleton(node_input) -> ScanSkeleton:  # node_input: the user turn that started the run, unused
        return skeleton(target, entry_points_fn)
    return FunctionNode(func=build_skeleton, name="build_skeleton")


def report_direct(store: RunStore, target: str, direct: list[Anchor]) -> list[str]:
    """Direct anchors → confirmed findings through the store's dedup, no model: osv with its knowledge record
    and an import count, gitleaks/semgrep as they are. Artifact `direct_findings` lists the ids (card 42)."""
    cfg = getattr(store, "knowledge", None)
    ids = []
    for a in direct:
        e = enrichment_for(a.id, cfg) if a.tool == "osv" and cfg is not None else None
        pkg = (e or {}).get("package") or (a.snippet.split() or [""])[0]
        n = imported_by(Path(target), pkg) if a.tool == "osv" and pkg and target else None
        ids.append(store.report(direct_finding(a, e, n)).id)
    store.put_artifact("direct_findings", {"ids": ids})
    if direct:
        log.info("direct findings: %d scanner results reported without the model (%s)", len(direct),
                 ", ".join(f"{t} {sum(a.tool == t for a in direct)}" for t in dict.fromkeys(a.tool for a in direct)))
    return ids


def direct_findings_node(store: RunStore, target: str) -> FunctionNode:
    """On a static edge after build_skeleton: the store's anchors → DirectResult {remaining, reported} plus the
    skeleton fields passed through (target, entry_points) so the Architect's payload needs no side channel.
    Called dynamically with a list of anchor dicts (tests), it classifies that list instead."""
    def direct_findings(node_input) -> dict:
        given = node_input if isinstance(node_input, list) else None
        anchors = [Anchor.model_validate(a) for a in given] if given is not None else store.anchors()
        direct, rest = split_direct(anchors)
        out = {"remaining": [a.model_dump() for a in rest], "reported": report_direct(store, target, direct)}
        if isinstance(node_input, dict):
            out.update({k: node_input[k] for k in ("target", "entry_points") if k in node_input})
        return out
    return FunctionNode(func=direct_findings, name="direct_findings", rerun_on_resume=True)


def _why(e: Exception) -> str:
    """ADK wraps a dynamic node's exception (DynamicNodeFailError.error): keep the original message."""
    cause = getattr(e, "error", None)
    return f"{e}: {cause}" if cause is not None else str(e)


def _model_json(out) -> dict | None:
    """The model's JSON from a node output: a dict (FunctionNode/output_schema), text (LlmAgent) or nothing."""
    if isinstance(out, dict):
        return out
    return parse_json(out) if isinstance(out, str) else None


def route_and_verify_node(store: RunStore, verifier, specialists: dict, router: Router | None, max_parallel: int):
    """Investigator fan-out: one hypothesis dict in, one Dossier dict out; ADK runs the items ≤ max_parallel at a
    time. Verdict from STORE facts (report_finding/disprove_finding wrote them); the model's JSON only adds
    notes/new_hypotheses; a failing item yields an error dossier instead of cancelling the batch."""
    async def route_and_verify(ctx, node_input: dict) -> dict:
        h = Hypothesis.model_validate(node_input)
        agent, name, suffix = pick_agent(h, "investigate", specialists, router, verifier)
        payload = {**h.model_dump(), "skill": skill_for(h.cwe, h.kind), "skills": skills_for(h.cwe, h.kind), "specialist": name}
        if suffix:
            payload["instructions"] = suffix  # language overlay, once an instruction append at clone time
        out, err = None, ""
        try:
            out = await ctx.run_node(agent, payload, run_id=f"verify_{h.id}")
        except Exception as e:  # noqa: BLE001 — one lost hypothesis must not cancel the batch (ADK raises the first)
            err = _why(e)
        d = dossier_from_store(store.findings(), h).model_copy(update={"specialist": name})
        if (md := _model_json(out)) is not None:
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
            log.warning("triage batch %s: %s", files[:1], _why(e))
            store.add_note(f"triage batch failed: {_why(e)}")
        md = _model_json(out) or {}
        cls = [c for c in md.get("classifications", []) if isinstance(c, dict)]
        for c in cls:
            c["classes"] = [x.upper() for x in c.get("classes", []) if isinstance(x, str) and x.upper().startswith("CWE-")]
            c["why"] = str(c.get("why", ""))[:300]
        return {"classifications": cls}
    return node(triage_sweep, parallel_worker=True, max_parallel_workers=max_parallel or None,
                rerun_on_resume=True, name="triage_sweep")


def _annotating_worker(name: str, agent, store: RunStore, specialists: dict, router: Router | None, max_parallel: int,
                       annotate: Callable[[dict, dict], None], role: str = "critique"):
    """A parallel worker over the model's confirmed findings: {finding, anchor, specialist, skills} → the agent;
    its JSON becomes an annotation through `annotate(finding_dict, json)`; verdict changes only through the gates
    inside the agent. No agent → 0 calls, the finding passes through."""
    async def worker(ctx, node_input: dict) -> dict:
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
            err = _why(e)
            log.warning("%s %s failed: %s", name, f.id, err)
            store.add_note(f"{name} {f.id} failed: {err}", f.id)
        md = _model_json(out)
        if md is not None:
            try:
                annotate(node_input, md)
            except (ValueError, KeyError) as e:
                err = err or f"invalid {name} JSON: {e}"
                store.add_note(f"{name} {f.id}: {err}", f.id)
        return {"finding_id": f.id, "specialist": sname, "error": err}
    return node(worker, parallel_worker=True, max_parallel_workers=max_parallel or None, rerun_on_resume=True, name=name)


def review_node(review, store: RunStore, specialists: dict, router: Router | None, max_parallel: int):
    """Independent validation (Shannon review): ReviewVerdict → annotation `review`. FALSE_POSITIVE without a
    disprove_finding call (the finding is still confirmed) is recorded as NEEDS_RESEARCH."""
    from scanner.core.workflow import ReviewVerdict

    def annotate(fd: dict, md: dict) -> None:
        v = ReviewVerdict.model_validate({**md, "finding_id": fd["id"]})
        status = v.status
        if status == "FALSE_POSITIVE" and any(f.id == fd["id"] and f.status == core.CONFIRMED for f in store.findings()):
            status = "NEEDS_RESEARCH"  # the agent said FP but never disproved it through the gate
            store.add_note(f"review {fd['id']}: FALSE_POSITIVE without a counter-quote — kept as NEEDS_RESEARCH", fd["id"])
        store.annotate(fd["id"], review={"status": status, "reasoning": v.reasoning, "repro_hints": v.repro_hints,
                                         "checklist": {k: r.model_dump() for k, r in v.checklist.items()}})
    return _annotating_worker("review", review, store, specialists, router, max_parallel, annotate)


def viability_node(critic, store: RunStore, specialists: dict, router: Router | None, max_parallel: int):
    """Production viability (Shannon critic): Viability → annotation `viability`; NON_VIABLE without a gate call
    is recorded as CONDITIONAL_VIABLE (fail-safe)."""
    from scanner.core.workflow import Viability

    def annotate(fd: dict, md: dict) -> None:
        v = Viability.model_validate({**md, "finding_id": fd["id"]})
        val = v.viability
        if val == "NON_VIABLE" and any(f.id == fd["id"] and f.status == core.CONFIRMED for f in store.findings()):
            val = "CONDITIONAL_VIABLE"
            store.add_note(f"critic {fd['id']}: NON_VIABLE without a counter-quote — kept CONDITIONAL_VIABLE", fd["id"])
        store.annotate(fd["id"], viability=val)
    return _annotating_worker("critic", critic, store, specialists, router, max_parallel, annotate)


def confirm_node(confirm, store: RunStore, max_parallel: int):
    """Static confirmation of PROVISIONALLY_VALID findings: Confirmation → annotation `repro_status`; promotion
    happens inside the agent through a second report_finding with a higher confidence."""
    from scanner.core.workflow import Confirmation

    def annotate(fd: dict, md: dict) -> None:
        c = Confirmation.model_validate({**md, "finding_id": fd["id"]})
        store.annotate(fd["id"], repro_status=c.repro_status)
    return _annotating_worker("confirm", confirm, store, {}, None, max_parallel, annotate)
