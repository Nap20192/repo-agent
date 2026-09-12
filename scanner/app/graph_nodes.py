"""Nodes of the ADK 2.9 Workflow graph (card 43, docs/plans/workflow-migration.md §2/§4), built per run by
factories that close over the RunStore and the wired agents — the graph itself is assembled in pipeline v3.

Deterministic steps are FunctionNodes (`build_skeleton`, `direct_findings`); the fan-outs are parallel-worker
nodes (`route_and_verify`, `route_and_critique`) that route each item to a specialist in code, run it with
`ctx.run_node` and contain the failure per item — ADK raises the first worker exception and cancels the batch
otherwise (`google/adk/workflow/_parallel_worker.py`)."""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

from google.adk.workflow import FunctionNode

from scanner.adapter.knowledge import enrichment_for, imported_by
from scanner.app.reconcile import direct_finding, split_direct
from scanner.core import Anchor, Candidate
from scanner.core.ports import RunStore
from scanner.core.workflow import ScanSkeleton

log = logging.getLogger("scanner.graph_nodes")


def skeleton(store: RunStore, target: str, entry_points_fn: Callable[[], list[Candidate]] | None,
             anchors: list[Anchor] | None = None) -> ScanSkeleton:
    """What the modelling stages receive: the target, its entry points and a trimmed anchor view."""
    anchors = store.anchors() if anchors is None else anchors
    return ScanSkeleton(
        target=target,
        entry_points=list(entry_points_fn()) if entry_points_fn else [],
        anchors=[{"id": a.id, "tool": a.tool, "cwe": a.cwe, "file": a.file, "line": a.line, "message": a.message[:120]}
                 for a in anchors],
    )


def build_skeleton_node(store: RunStore, target: str, entry_points_fn: Callable[[], list[Candidate]] | None) -> FunctionNode:
    """START → skeleton. The pre-pass (scanners) already ran in runner.prepare; this node reads its anchors."""
    def build_skeleton(node_input) -> ScanSkeleton:  # node_input: the user turn that started the run, unused
        return skeleton(store, target, entry_points_fn)
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
    """anchors (dicts) → {"remaining": anchors the model may investigate, "reported": finding ids}."""
    def direct_findings(node_input: list[dict]) -> dict:
        direct, rest = split_direct([Anchor.model_validate(a) for a in node_input])
        return {"remaining": [a.model_dump() for a in rest], "reported": report_direct(store, target, direct)}
    return FunctionNode(func=direct_findings, name="direct_findings", rerun_on_resume=True)
