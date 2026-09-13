"""The scan graph as a STATIC ADK Workflow (docs/adr/0010): seven nodes.

    START → scan → build_skeleton → direct_findings → model → plan ─(empty)→ export
                                                              └(default)→ audit → critique → export

`scan` runs the scanners (anchors → store); `direct_findings` reports osv/gitleaks/semgrep-ERROR anchors without a model;
`model` is the one LLM modelling stage (architecture + threats, grounded); `plan` builds the hypothesis queue; `audit` is
the round loop over the Investigator fan-out (class section + language overlay per hypothesis); `critique` dedupes and
runs the Critic over every confirmed finding; `export` closes. Verdicts come only from the store
(report_finding / disprove_finding); the model's JSON adds notes and annotations."""

from __future__ import annotations

from collections.abc import Callable

from google.adk.workflow import DEFAULT_ROUTE, START, Workflow
from pydantic import ConfigDict

from scanner.adapter.scanners import ScanResult
from scanner.app.graph.nodes import (
    audit_node,
    build_skeleton_node,
    critique_node,
    direct_findings_node,
    export_node,
    model_node,
    plan_node,
    route_and_verify_node,
    scan_node,
)
from scanner.core import Candidate
from scanner.core.ports import Index, RunStore

NODES = ("scan", "build_skeleton", "direct_findings", "model", "plan", "audit", "critique", "export")


class ScanWorkflow(Workflow):
    """The Workflow plus the code Index it was wired with (closed by the runner)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)
    index: Index | None = None


def build_workflow(
    *, store: RunStore, target: str, verifier, critic=None, model=None,
    has_anchor: Callable[[str], bool], has_symbol: Callable[[str], bool],
    locate: Callable[[str], tuple[str, int] | None] | None = None,
    entry_points_fn: Callable[[], list[Candidate]] | None = None,
    scan_fn: Callable[[], ScanResult] | None = None,
    max_rounds: int = 4, max_hyps: int = 8, max_parallel: int = 3, stage_timeout: float = 600.0,
    index: Index | None = None,
) -> ScanWorkflow:
    """Wire the graph for one run. Agents left None turn their node into a no-op of the same name so the diagram is
    stable; `scan_fn` None means the anchors are already in the store (tests)."""
    timings: dict[str, float] = {}  # per run; `export` persists it as the `timings` artifact
    verify_node = route_and_verify_node(store, verifier, max_parallel)
    n_scan = scan_node(store, scan_fn)
    n_skel = build_skeleton_node(store, target, entry_points_fn)
    n_direct = direct_findings_node(store, target)
    n_model = model_node(store, model, has_symbol, locate, stage_timeout, timings)
    n_plan = plan_node(store, locate, entry_points_fn)
    n_audit = audit_node(store, verify_node, has_anchor, has_symbol, max_rounds, max_hyps, timings)
    n_critique = critique_node(store, critic, max_parallel)
    n_export = export_node(store, timings)
    edges = [
        (START, n_scan, n_skel, n_direct, n_model, n_plan),
        (n_plan, {"empty": n_export, DEFAULT_ROUTE: n_audit}),
        (n_audit, n_critique, n_export),
    ]
    # no state_schema: ADK rejects undeclared keys, and the budget callback writes per-branch keys (`budget_exhausted:<branch>`)
    return ScanWorkflow(name="scan", edges=edges, index=index)
