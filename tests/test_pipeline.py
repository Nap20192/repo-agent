"""The small graph (card 51) under the real ADK Runner with node doubles — the contract, node by node.
Assertions are on the store, the artifacts and the session state, never on branch names."""


import pytest
from google.adk.workflow import FunctionNode

from scanner import core
from scanner.core import Anchor, Candidate, Finding, Threat
from tests.fakes import (
    A1,
    A2,
    FakeRun,
    _run,
    _workflow,
    fake_stage_node,
    fake_verifier_node,
    notes_of,
)

OSV = Anchor(id="a_osv", tool="osv", rule_id="GHSA-x", rule_ids=["GHSA-x"], severity="high", file="package-lock.json",
             line=1, snippet="lodash 4.17.11", message="lodash@4.17.11: 1 advisories")


# --- plan: stages ------------------------------------------------------------------------------------------


def test_queue_orders_threats_anchors_and_coverage_by_priority():
    run = FakeRun()
    run.put_artifact("threat_model", {"threats": [Threat(cwe="CWE-639", claim="idor", symbol="getOrder", priority=90).model_dump()]})
    wf = _workflow(run,
                   has_symbol=lambda s: s == "listOrders", locate=lambda s: ("orders.go", 5) if s == "getOrder" else None,
                   entry_points_fn=lambda: [Candidate(kind="entry", symbol="listOrders", file="list.go", line=3)], max_parallel=1)
    _run(wf)
    assert [(h.kind, h.priority) for h in run.hyps[0]] == [("authz", 90), ("sink", 60), ("sink", 60), ("entry", 10)]


def test_direct_anchors_are_findings_before_round_0_and_never_hypotheses():
    run = FakeRun([A1, OSV])
    _run(_workflow(run))
    assert run.findings()[0].anchor_id == "a_osv" and run.findings()[0].source == "direct"
    assert [h.anchor_id for h in run.hyps[0]] == ["a_1"] and run.artifact("direct_findings") == {"ids": ["f_1"]}


# --- investigate ---------------------------------------------------------------------------------------------

def test_done_blocks_requeue_and_rounds_are_counted():
    run = FakeRun()
    state = _run(_workflow(run, max_parallel=1))  # the fake proposes "dup of a_1" every time
    assert [h.anchor_id for h in run.hyps[0]] == ["a_1", "a_2"] and run.hyps[1] == []
    assert state[core.STATE_ROUND] == 2 and isinstance(state["queue"], int) and state[core.STATE_STOP_REASON] == ""
    assert [d.verdict for d in run.doss[0]] == [core.CONFIRMED, core.REJECTED] and run.doss[0][0].notes == "n"


@pytest.mark.parametrize("kw, stop", [({"max_hyps": 1, "max_rounds": 5}, ""), ({"max_hyps": 1, "max_rounds": 1}, "round limit")])
def test_max_hyps_batches_and_round_limit(kw, stop):
    run = FakeRun()
    state = _run(_workflow(run, max_parallel=1, **kw))
    assert [h.anchor_id for h in run.hyps[0]] == ["a_1"]
    assert state[core.STATE_STOP_REASON] == stop
    if not stop:
        assert [h.anchor_id for h in run.hyps[1]] == ["a_2"]


def test_verify_failure_round0_raises_later_finishes_with_reason():
    run = FakeRun()
    with pytest.raises(Exception, match="verify round 0 failed"):
        _run(_workflow(run, verifier=fake_verifier_node(run, fail_prefix="h0")))
    assert run.doss == {}  # a failed round 0 leaves no dossiers behind (review: store parity)
    run = FakeRun()
    state = _run(_workflow(run, verifier=fake_verifier_node(run, fail_prefix="h1"), max_hyps=1, max_parallel=1))
    assert state[core.STATE_STOP_REASON].startswith("verify round 1 failed:") and "boom" in state[core.STATE_STOP_REASON]
    assert 1 in run.doss and run.doss[1][0].error


def test_own_budget_marks_the_dossier_and_the_run_goes_on():
    run = FakeRun()
    state = _run(_workflow(run, verifier=fake_verifier_node(run, budget=True)))
    assert state[core.STATE_STOP_REASON] == "" and all(d.error for d in run.doss[0])


def test_global_budget_flag_stops_the_run():
    run = FakeRun()
    state = _run(_workflow(run, verifier=fake_verifier_node(run, global_flag=True)))
    assert state[core.STATE_STOP_REASON] == "budget" and state[core.STATE_ROUND] == 1











def test_scan_node_is_the_first_edge_when_scan_fn_is_given():
    from scanner.adapter.scanners import ScanResult
    run = FakeRun(anchors=[])  # an empty store: the scan node is what fills it
    wf = _workflow(run, scan_fn=lambda: ScanResult(anchors=[A1], ran=["gosec"]))
    assert [n.name for n in wf.graph.nodes][:3] == ["__START__", "scan", "build_skeleton"]
    _run(wf)
    assert [a.id for a in run.anchors()] == [A1.id] and run.artifact("scan")["ran"] == ["gosec"]


def test_model_stage_stores_grounded_architecture_and_threats_and_degrades():
    run = FakeRun([A1])
    am = {"entities": [{"name": "Server", "symbol": "main"}], "trust_boundaries": [], "vuln_classes": [], "deployment_signals": [], "notes": []}
    tm = {"threats": [{"symbol": "main", "cwe": "CWE-89", "claim": "x", "file": "main.go", "line": 22}], "notes": []}
    stage = fake_stage_node(run, "model", {"architecture_model": am, "threat_model": tm})
    _run(_workflow(run, model=stage, has_symbol=lambda s: s == "main", max_rounds=1))
    assert run.artifact("architecture_model")["entities"][0]["symbol"] == "main" and run.artifact("threat_model")["threats"][0]["cwe"] == "CWE-89"
    run2 = FakeRun([A1])
    _run(_workflow(run2, model=fake_stage_node(run2, "model", "not json"), max_rounds=1))
    assert run2.artifact("architecture_model") is None and any("stage model" in t for t, _ in notes_of(run2))


def test_critique_dedupes_then_annotates_and_disproof_only_through_the_gate():
    run = FakeRun([A1, A2])
    f1 = run.report(Finding(anchor_id=A1.id, cwe="CWE-89", file="main.go", line=22, title="SQLi", status=core.CONFIRMED, evidence=["q"], confidence=0.9))
    f2 = run.report(Finding(anchor_id=A2.id, cwe="CWE-78", file="main.go", line=30, title="cmdi", status=core.CONFIRMED, evidence=["q"], confidence=0.9))

    async def critic(ctx, node_input):
        fd = node_input["finding"]
        assert node_input["specialist"] == "taint" and "instructions" in node_input
        if fd["id"] == f2.id:
            run.set_status(f2.id, core.UNCERTAIN, ["critic: constant"], "critic disproved")  # the gate, as disprove_finding would
            return {"finding_id": fd["id"], "disproved": True, "reason": "constant input"}
        return {"finding_id": fd["id"], "disproved": True, "reason": "prose only"}  # claimed, never through the gate

    _run(_workflow(run, verifier=fake_verifier_node(run), critic=FunctionNode(func=critic, name="c", rerun_on_resume=True), max_rounds=1))
    st = {f.id: f for f in run.findings()}
    assert st[f1.id].status == core.CONFIRMED and st[f1.id].review["status"] == "NEEDS_RESEARCH"
    assert st[f2.id].status == core.UNCERTAIN and st[f2.id].review["status"] == "UNCERTAIN"


def test_no_critic_and_empty_plan_route_straight_to_export():
    run = FakeRun([])
    state = _run(_workflow(run, critic=None, max_rounds=1))
    assert run.artifact("timings") is not None and state.get(core.STATE_STOP_REASON) == ""


def test_workflow_is_the_small_graph():
    from scanner.app.graph.workflow import NODES
    wf = _workflow(FakeRun([A1]))
    assert wf.name == "scan" and NODES == ("scan", "build_skeleton", "direct_findings", "model", "plan", "audit", "critique", "export")


def test_export_records_timings_and_stop_reason():
    run = FakeRun([A1])
    state = _run(_workflow(run, model=fake_stage_node(run, "model", {"architecture_model": {"entities": []}, "threat_model": {"threats": []}}), max_parallel=1))
    t = run.artifact("timings")
    assert {"model", "verify_0"} <= set(t) and state[core.STATE_STOP_REASON] == ""
