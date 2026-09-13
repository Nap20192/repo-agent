"""The contract of the static Shannon graph (card 45), pinned without any model.

1. What the ADK dev-UI builder renders: exactly the 24 nodes in graph order, one JoinNode, the four route maps with
   their labels and targets, the parallel-worker sweeps, the modelling stages as dynamic nodes.
2. One end-to-end run per route with node doubles: what each path writes (artifacts, annotations, session state).
3. Degradation: a failing stage agent, triage worker or review worker leaves a note and the run still exports.
"""

import pytest
from google.adk.apps import App
from google.adk.cli.utils.graph_serialization import serialize_app_info
from google.adk.workflow import FunctionNode

from scanner import core
from scanner.app.graph.workflow import NODES
from scanner.core import Anchor, Candidate
from tests.fakes import A1, FakeRun, _run, _workflow, fake_stage_node, fake_verifier_node, notes_of

OSV = Anchor(id="a_osv", tool="osv", rule_id="GHSA-x", rule_ids=["GHSA-x"], severity="high", file="package-lock.json",
             line=1, snippet="lodash 4.17.11", message="lodash@4.17.11: 1 advisories")
EPS = [Candidate(kind="entry", file="x.js", line=1, symbol="x", route=["GET /x"])]


def _agent(store, name: str, reply, fail: bool = False):
    """review / critic / confirm double: notes the finding it saw, returns canned JSON (or raises)."""
    async def agent(ctx, node_input: dict):
        if fail:
            raise RuntimeError("boom")
        store.add_note(f"{name}:" + node_input["finding"]["id"])
        return reply
    return FunctionNode(func=agent, name=name, rerun_on_resume=True)


def _sweep(store, flagged: bool = True, fail: bool = False):
    async def triage(ctx, node_input: dict):
        if fail:
            raise RuntimeError("boom")
        store.add_note("triaged:" + ",".join(node_input["files"]))
        return {"classifications": [{"file": f, "flagged": flagged, "classes": ["CWE-79"], "why": "w"} for f in node_input["files"]]}
    return FunctionNode(func=triage, name="triage_batch", rerun_on_resume=True)


# --- 1. the builder's view -------------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def graph():
    info = serialize_app_info(App(name="fullscan", root_agent=_workflow(FakeRun())))
    return info["root_agent"]["graph"]


def test_builder_lists_exactly_the_24_nodes_in_graph_order(graph):
    names = [n["name"] for n in graph["nodes"] if n["name"] != "__START__"]
    assert len(names) == 24 and set(names) == set(NODES)
    assert names[:12] == ["scan", "build_skeleton", "direct_findings", "architect", "recon", "join_model", "domain_modeler",
                          "threat_modeler", "ground", "plan", "route_plan", "export"]  # export is declared by the first route map


def test_builder_shows_the_join_the_sweeps_and_the_dynamic_stages(graph):
    types = {n["name"]: n["type"] for n in graph["nodes"]}
    assert types["join_model"] == "join"
    assert {types[n] for n in ("triage_sweep", "review", "critic", "confirm")} == {"node"}  # parallel workers
    assert {types[n] for n in ("scan", "build_skeleton", "direct_findings", "recon", "ground", "dedupe", "mark_sample", "calibrate")} == {"function"}
    assert {types[n] for n in ("architect", "domain_modeler", "threat_modeler", "plan", "audit", "export")} == {"function"}
    assert all(n["rerun_on_resume"] for n in graph["nodes"] if n["name"] in ("architect", "domain_modeler", "threat_modeler", "audit", "export"))


def test_builder_shows_the_fan_out_and_the_route_maps(graph):
    edges = [(e["from_node"]["name"], e.get("route"), e["to_node"]["name"]) for e in graph["edges"] if isinstance(e, dict)]
    assert ("direct_findings", None, "architect") in edges and ("direct_findings", None, "recon") in edges  # fan-out
    assert ("architect", None, "join_model") in edges and ("recon", None, "join_model") in edges  # fan-in
    routes = {(f, r, t) for f, r, t in edges if r is not None}
    assert {("route_plan", "empty", "export"), ("route_research", "none", "export"), ("route_survivors", "none", "export"),
            ("route_intent", "sample", "mark_sample")} <= routes
    defaults = {f: t for f, r, t in routes if r == "__DEFAULT__"}
    assert defaults == {"route_plan": "triage_sweep", "route_research": "dedupe", "route_survivors": "route_intent", "route_intent": "critic"}
    assert ("mark_sample", None, "calibrate") in edges and ("confirm", None, "calibrate") in edges and ("calibrate", None, "export") in edges


# --- 2. one run per route ---------------------------------------------------------------------------------------

def test_route_plan_empty_goes_straight_to_export():
    run = FakeRun([OSV])  # only a direct anchor: nothing to investigate
    rev = _agent(run, "review", {"status": "VALID"})
    state = _run(_workflow(run, review=rev, recon_fn=lambda: {"sources": [], "sinks": {}, "auth": [], "config_files": []}))
    assert run.artifact("recon") is not None and run.artifact("plan")["queue"] == []
    assert run.artifact("triage_coverage") is None and run.hyps == {}  # the sweep and the audit never ran
    assert not any(t.startswith("review:") for t, _ in notes_of(run))
    assert run.artifact("timings") is not None and state[core.STATE_STOP_REASON] == ""
    assert run.findings()[0].source == "direct" and run.findings()[0].calibration == {}  # calibrate is not on this path


def test_route_research_none_goes_to_export_without_review():
    run = FakeRun([A1])

    async def rejecting(ctx, node_input: dict):
        run.report(core.Finding(anchor_id=node_input["anchor_id"], hypothesis_id=node_input["id"], cwe="CWE-89", file="main.go",
                                title="t", status=core.REJECTED, evidence=["x"]))
        return {"hypothesis_id": node_input["id"], "verdict": core.REJECTED}
    rev = _agent(run, "review", {"status": "VALID"})
    state = _run(_workflow(run, verifier=FunctionNode(func=rejecting, name="v", rerun_on_resume=True), review=rev, max_parallel=1))
    assert run.artifact("triage_coverage")["coverage"] == "complete" and run.doss[0][0].verdict == core.REJECTED
    assert not any(t.startswith("review:") for t, _ in notes_of(run)) and run.artifact("timings") is not None
    assert state[core.STATE_STOP_REASON] == "" and state[core.STATE_ROUND] == 1


def test_route_research_budget_goes_to_export_and_keeps_the_stop_reason():
    run = FakeRun()
    rev = _agent(run, "review", {"status": "VALID"})
    state = _run(_workflow(run, verifier=fake_verifier_node(run, global_flag=True), review=rev))
    assert state[core.STATE_STOP_REASON] == "budget" and run.artifact("timings") is not None
    assert not any(t.startswith("review:") for t, _ in notes_of(run))


def test_route_intent_sample_marks_survivors_and_calibrates_without_the_critic():
    run = FakeRun([A1, OSV])
    tm = fake_stage_node(run, "threat_modeler", {"intent": "sample", "threats": []})
    crit = _agent(run, "critic", {"viability": "VIABLE"})
    conf = _agent(run, "confirm", {"repro_status": "statically_confirmed"})
    _run(_workflow(run, threat_modeler=tm, review=_agent(run, "review", {"status": "PROVISIONALLY_VALID"}), critic=crit,
                   confirm=conf, max_parallel=1))
    f = next(x for x in run.findings() if x.source != "direct")
    assert f.review["status"] == "PROVISIONALLY_VALID" and f.viability == "SAMPLE_OR_TEST" and f.repro_status == ""
    assert f.calibration and not any(t.startswith(("critic:", "confirm:")) for t, _ in notes_of(run))


def test_full_path_review_critic_confirm_calibrate_export():
    run = FakeRun([A1, OSV])
    seen = []
    rev = _agent(run, "review", {"status": "PROVISIONALLY_VALID", "reasoning": "r",
                                 "checklist": {"sink_reached": {"outcome": "PASS", "reason": "ok"}}})
    crit = _agent(run, "critic", {"viability": "VIABLE", "reasoning": "prod route"})
    conf = _agent(run, "confirm", {"repro_status": "statically_confirmed", "repro_hints": ["curl …"]})
    state = _run(_workflow(run, triage=_sweep(run), entry_points_fn=lambda: EPS, review=rev, critic=crit, confirm=conf,
                           architect=fake_stage_node(run, "architect", {"entities": []}), max_parallel=1))
    f = next(x for x in run.findings() if x.source != "direct")
    assert f.status == core.CONFIRMED and f.review["checklist"]["sink_reached"]["outcome"] == "PASS"
    assert f.viability == "VIABLE" and f.repro_status == "statically_confirmed" and f.calibration["priority"]
    direct = next(x for x in run.findings() if x.source == "direct")
    assert direct.review == {} and direct.viability == "" and direct.calibration  # never reviewed, still calibrated
    assert [t for t, _ in notes_of(run) if t.startswith(("review:", "critic:", "confirm:"))] == [f"review:{f.id}", f"critic:{f.id}", f"confirm:{f.id}"]
    assert run.artifact("triage_coverage")["flagged"] == ["x.js"]
    assert {"architecture_model", "verify_0"} <= set(run.artifact("timings")) and state[core.STATE_STOP_REASON] == ""
    assert seen == []


# --- 3. degradation ------------------------------------------------------------------------------------------------

def test_failing_stage_agent_is_noted_and_the_run_exports():
    run = FakeRun()
    _run(_workflow(run, architect=fake_verifier_node(run, "architect", fail_prefix=""),  # raises on any input
                   domain_modeler=fake_stage_node(run, "domain_modeler", None)))
    assert run.artifact("architecture_model") is None and run.artifact("domain_map") is None
    assert any(t.startswith("stage architecture_model failed:") for t, _ in notes_of(run))
    assert any(t == "stage domain_map: no valid JSON" for t, _ in notes_of(run))
    assert run.hyps[0] and run.artifact("timings") is not None


def test_failing_triage_worker_keeps_baselines_reduces_coverage_and_exports():
    run = FakeRun()
    _run(_workflow(run, triage=_sweep(run, fail=True), entry_points_fn=lambda: EPS, max_parallel=1))
    cov = run.artifact("triage_coverage")
    assert cov["coverage"] == "reduced" and cov["missing"] == ["x.js"]
    assert [h.kind for h in run.hyps[0]] == ["sink", "sink", "entry"] and any("triage batch failed" in t for t, _ in notes_of(run))
    assert run.artifact("timings") is not None


def test_failing_review_worker_keeps_the_finding_and_exports():
    run = FakeRun()
    _run(_workflow(run, review=_agent(run, "review", {}, fail=True), critic=_agent(run, "critic", {"viability": "VIABLE"}), max_parallel=1))
    f = run.findings()[0]
    assert f.status == core.CONFIRMED and f.review == {} and f.viability == "VIABLE"  # the ladder went on past the failed review
    assert any("review f_1 failed" in t for t, _ in notes_of(run)) and run.artifact("timings") is not None
