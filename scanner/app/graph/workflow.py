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

from collections.abc import Callable

from google.adk.workflow import DEFAULT_ROUTE, START, JoinNode, Workflow
from pydantic import ConfigDict

from scanner.adapter.scanners import ScanResult
from scanner.app.graph.nodes import (
    architect_node,
    audit_node,
    build_skeleton_node,
    calibrate_node,
    confirm_node,
    dedupe_node,
    direct_findings_node,
    domain_modeler_node,
    export_node,
    fold_triage_node,
    ground_node,
    mark_sample_node,
    plan_node,
    recon_node,
    review_node,
    route_and_verify_node,
    route_intent_node,
    route_plan_node,
    route_research_node,
    route_survivors_node,
    scan_node,
    threat_modeler_node,
    triage_sweep_node,
    viability_node,
)
from scanner.core import Candidate, Threat
from scanner.core.ports import Closeable, Router, RunStore

STAGES = ("architecture_model", "domain_map", "threat_model")
NODES = ("scan", "build_skeleton", "direct_findings", "architect", "recon", "join_model", "domain_modeler",
         "threat_modeler", "ground", "plan", "route_plan", "triage_sweep", "fold_triage", "audit", "route_research",
         "dedupe", "review", "route_survivors", "route_intent", "mark_sample", "critic", "confirm", "calibrate", "export")


class ScanWorkflow(Workflow):
    """The Workflow plus the code Index it was wired with (closed by the runner)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)
    index: Closeable | None = None


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

    n_scan = scan_node(store, scan_fn)
    n_skel = build_skeleton_node(store, target, entry_points_fn)
    n_direct = direct_findings_node(store, target)
    n_architect = architect_node(store, architect, stage_timeout, timings)
    n_recon = recon_node(store, recon_fn)
    n_join = JoinNode(name="join_model")
    n_domain = domain_modeler_node(store, domain_modeler, target, index, stage_timeout, timings)
    n_threat = threat_modeler_node(store, threat_modeler, stage_timeout, timings)
    n_ground = ground_node(store, has_symbol, locate)
    n_plan = plan_node(store, threats, locate, entry_points_fn, source_files_fn, triage_batch)
    n_route_plan = route_plan_node()
    n_sweep = triage_sweep_node(triage, store, triage_parallel)
    n_fold = fold_triage_node(store)
    n_audit = audit_node(store, verify_node, has_anchor, has_symbol, max_rounds, max_hyps, timings)
    n_route_research = route_research_node()
    n_dedupe = dedupe_node(store)
    n_review = review_node(review, store, specialists, router, max_parallel)
    n_route_surv = route_survivors_node(store)
    n_route_intent = route_intent_node(store)
    n_mark = mark_sample_node(store)
    n_viab = viability_node(critic, store, specialists, router, max_parallel)
    n_conf = confirm_node(confirm, store, max_parallel)  # confirms only PROVISIONALLY_VALID reviews (0 calls otherwise)
    n_cal = calibrate_node(store, knowledge_cfg)
    n_export = export_node(store, timings)

    edges = [
        (START, n_scan, n_skel, n_direct, (n_architect, n_recon), n_join, n_domain, n_threat, n_ground, n_plan, n_route_plan),
        (n_route_plan, {"empty": n_export, DEFAULT_ROUTE: n_sweep}),
        (n_sweep, n_fold, n_audit, n_route_research),
        (n_route_research, {"none": n_export, DEFAULT_ROUTE: n_dedupe}),
        (n_dedupe, n_review, n_route_surv),
        (n_route_surv, {"none": n_export, DEFAULT_ROUTE: n_route_intent}),
        (n_route_intent, {"sample": n_mark, DEFAULT_ROUTE: n_viab}),
        (n_mark, n_cal),
        (n_viab, n_conf, n_cal, n_export),
    ]
    # no state_schema: ADK rejects undeclared keys, and the budget callback writes per-branch keys (`budget_exhausted:<branch>`)
    return ScanWorkflow(name="scan", edges=edges, index=index)
