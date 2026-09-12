"""Card 43 step 5: the v3 Workflow (START → build_skeleton → plan → investigate → finish) under the real ADK
Runner with node doubles — the graph contract, node by node.
Assertions are on the store and the session state, never on branch names."""

import json

import pytest

from scanner import core
from scanner.core import Anchor, Candidate, Threat, ThreatModel
from tests.fakes import (
    A1,
    FakeRun,
    _run,
    _workflow,
    fake_critic_node,
    fake_stage_node,
    fake_verifier_node,
    notes_of,
)

OSV = Anchor(id="a_osv", tool="osv", rule_id="GHSA-x", rule_ids=["GHSA-x"], severity="high", file="package-lock.json",
             line=1, snippet="lodash 4.17.11", message="lodash@4.17.11: 1 advisories")


# --- plan: stages ------------------------------------------------------------------------------------------

def test_stage_valid_json_is_stored_and_the_payload_is_the_skeleton():
    run = FakeRun()
    arch = fake_stage_node(run, "architect", {"entities": [{"name": "api"}]})
    _run(_workflow(run, architect=arch, entry_points_fn=lambda: [Candidate(kind="entry", file="main.go", line=3, symbol="h")]))
    assert run.artifact("architecture_model") == {"entities": [{"name": "api"}]}
    seen = next(json.loads(t[5:]) for t, _ in notes_of(run) if t.startswith("seen:"))
    assert seen["target"] == "/t" and seen["entry_points"][0]["symbol"] == "h" and seen["anchors"][0]["id"] == "a_1"


def test_stage_invalid_json_and_exception_are_noted_and_the_scan_goes_on():
    run = FakeRun()
    _run(_workflow(run, architect=fake_stage_node(run, "architect", None)))
    assert run.artifact("architecture_model") is None
    assert any(t == "stage architecture_model: no valid JSON" for t, _ in notes_of(run))
    assert run.hyps[0]  # the queue was still built and investigated

    run = FakeRun()
    _run(_workflow(run, architect=fake_verifier_node(run, "architect", fail_prefix="")))  # a node that raises
    assert run.artifact("architecture_model") is None
    assert any(t.startswith("stage architecture_model failed:") for t, _ in notes_of(run))
    assert run.hyps[0]


def test_stage_resume_skips_the_agent_when_the_artifact_exists():
    run = FakeRun()
    run.put_artifact("architecture_model", {"entities": [{"name": "cached"}]})
    _run(_workflow(run, architect=fake_stage_node(run, "architect", {"entities": [{"name": "fresh"}]})))
    assert run.artifact("architecture_model")["entities"][0]["name"] == "cached"
    assert not any(t.startswith("seen:") for t, _ in notes_of(run))


def test_threat_modeler_threats_are_grounded_minted_and_intent_normalised():
    run = FakeRun()
    tm = fake_stage_node(run, "threat_modeler", {"intent": "SAMPLE_OR_TEST_ONLY", "threats": [
        {"cwe": "CWE-639", "claim": "idor", "symbol": "getOrder", "priority": 90},
        {"cwe": "CWE-79", "claim": "ghost", "symbol": "", "priority": 30}]})
    seen = {}
    _run(_workflow(run, threat_modeler=tm, has_symbol=lambda s: s == "getOrder",
                   locate=lambda s: ("orders.go", 5) if s == "getOrder" else None))
    assert ThreatModel.model_validate(run.artifact("threat_model")).intent == "sample"
    seen = next(json.loads(t[5:]) for t, _ in notes_of(run) if t.startswith("seen:"))
    assert seen["architecture_model"]["entities"] == []  # runs on the empty model without an Architect
    claims = [h.claim for h in run.hyps[0]]
    assert claims[0] == "idor" and "ghost" not in claims


# --- plan: queue ----------------------------------------------------------------------------------------------

def test_queue_orders_threats_anchors_and_coverage_by_priority():
    run = FakeRun()
    wf = _workflow(run, threats=[Threat(cwe="CWE-639", claim="idor", symbol="getOrder", priority=90)],
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


def test_specialist_routing_and_overlay_in_the_payload():
    run = FakeRun()
    seen = []
    from google.adk.workflow import FunctionNode

    async def spy(ctx, node_input: dict):
        seen.append((node_input["specialist"], node_input.get("instructions")))
        return {"hypothesis_id": node_input["id"], "verdict": "uncertain", "notes": "spy"}
    taint = FunctionNode(func=spy, name="taint", rerun_on_resume=True)
    router = lambda item, lang, role: (("taint", f"OVERLAY:{lang}") if getattr(item, "cwe", "") == "CWE-89" else ("", ""))
    _run(_workflow(run, specialists={"taint": taint}, router=router, max_parallel=1))
    assert seen == [("taint", "OVERLAY:go")]
    assert [d.specialist for d in run.doss[0]] == ["taint", ""] and run.doss[0][0].notes == "spy"


# --- finish ---------------------------------------------------------------------------------------------------

def test_critic_downgrades_llm_confirmed_but_skips_direct_and_survives_failure():
    run = FakeRun([A1, OSV])
    _run(_workflow(run, critic=fake_critic_node(run)))
    by = {f.anchor_id: f.status for f in run.findings()}
    assert by["a_1"] == core.UNCERTAIN and by["a_osv"] == core.CONFIRMED
    assert [t for t, _ in notes_of(run) if t.startswith("critic:")] == ["critic:critic"]

    run = FakeRun()
    _run(_workflow(run, critic=fake_critic_node(run, fail=True)))
    assert run.findings()[0].status == core.CONFIRMED and any("failed" in t for t, _ in notes_of(run))


def test_finish_records_timings_and_the_stop_reason():
    run = FakeRun()
    state = _run(_workflow(run, architect=fake_stage_node(run, "architect", {"entities": []}), critic=fake_critic_node(run)))
    t = run.artifact("timings")
    assert {"architecture_model", "verify_0", "critic"} <= set(t) and state[core.STATE_STOP_REASON] == ""


# --- card 39 contract: artifacts are grounded before they feed the queue ----------------------------------------

def test_plan_grounds_artifacts_before_the_queue():
    run = FakeRun()
    arch = fake_stage_node(run, "architect", {"entities": [{"name": "X", "grounding_symbol": "nowhere"}],
                                             "vuln_classes": [{"cwe": "CWE-89", "wstg_id": "WSTG-174"}]})
    dm = fake_stage_node(run, "domain_modeler", {"entities": [], "roles": [], "gaps": [], "notes": [],
                                                "rules": [{"id": "r1", "statement": "s", "entity": "Order", "symbol": "Server.login"}]})
    tm = fake_stage_node(run, "threat_modeler", {"intent": "production", "notes": [], "threats": [
        {"cwe": "CWE-79", "claim": "ghost", "symbol": "nowhere", "priority": 90},
        {"cwe": "CWE-89", "claim": "real", "symbol": "searchHandler", "priority": 80, "wstg_id": "WSTG-999"}]})
    state = _run(_workflow(run, architect=arch, domain_modeler=dm, threat_modeler=tm, has_symbol=lambda s: s == "searchHandler",
                           locate=lambda s: ("main.go", 20) if s == "searchHandler" else None, max_parallel=1))
    assert run.artifact("architecture_model")["vuln_classes"][0]["wstg_id"] == "WSTG-INJT-05"
    assert run.artifact("architecture_model")["entities"] == []
    assert run.artifact("domain_map")["rules"] == [] and run.artifact("domain_map")["gaps"]
    assert [t["symbol"] for t in run.artifact("threat_model")["threats"]] == ["searchHandler"]
    claims = [h.claim for h in run.hyps[0]]
    assert "real" in claims and "ghost" not in claims
    assert state["grounding_dropped"] >= 3 and any("nowhere" in t for t, _ in notes_of(run))


def test_workflow_is_a_four_node_graph():
    from google.adk.workflow import Workflow
    wf = _workflow(FakeRun())
    assert isinstance(wf, Workflow) and wf.name == "scan"
    names = {n.name for e in wf.edges for n in e if hasattr(n, "name")}
    assert {"build_skeleton", "plan", "investigate", "finish"} <= names


# --- card 44: triage --------------------------------------------------------------------------------------

def _triage_double(store, flag_files: set[str], fail_file: str = ""):
    """Triage stand-in: flags hypotheses whose file is in flag_files, raises for fail_file."""
    from google.adk.workflow import FunctionNode

    async def triage(ctx, node_input: dict):
        f = node_input["file"]
        if f == fail_file:
            raise RuntimeError("boom")
        store.add_note("triaged:" + f)
        return {"file": f, "flagged": f in flag_files, "classes": ["CWE-943"], "why": "db call on request field"}
    return FunctionNode(func=triage, name="triage", rerun_on_resume=True)


def test_triage_gates_baselines_and_records_unflagged_as_rejected():
    run = FakeRun([])
    eps = [Candidate(kind="entry", file="allocations.js", line=8, symbol="displayAllocations", route=["GET /allocations/:userId"]),
           Candidate(kind="entry", file="tutorial.js", line=8, symbol="displayTutorial", route=["GET /tutorial"])]
    verified = []
    from google.adk.workflow import FunctionNode

    async def verify(ctx, node_input: dict):
        verified.append((node_input["file"] if "file" in node_input else node_input["reads"][0], node_input["cwe"], node_input["claim"]))
        return {"hypothesis_id": node_input["id"], "verdict": "uncertain", "notes": "v"}
    wf = _workflow(run, verifier=FunctionNode(func=verify, name="verify", rerun_on_resume=True),
                   triage=_triage_double(run, {"allocations.js"}), entry_points_fn=lambda: eps, max_parallel=1)
    _run(wf)
    assert [t for t, _ in notes_of(run) if t.startswith("triaged:")] == ["triaged:allocations.js", "triaged:tutorial.js"]
    assert [(f, c) for f, c, _ in verified] == [("allocations.js", "CWE-943")]  # flagged: verified with the triage class
    assert "Triage: db call on request field" in verified[0][2]
    rejected = [d for d in run.doss[0] if d.verdict == core.REJECTED]
    assert len(rejected) == 1 and "triage" in rejected[0].notes and rejected[0].specialist == "triage"
    assert len(run.doss[0]) == 2  # one triage rejection + one verified dossier, same round


def test_triage_failure_fails_open_and_scanner_anchors_skip_triage():
    run = FakeRun()  # A1/A2: scanner sinks — never triaged
    eps = [Candidate(kind="entry", file="x.js", line=1, symbol="x", route=["GET /x"])]
    _run(_workflow(run, triage=_triage_double(run, set(), fail_file="x.js"), entry_points_fn=lambda: eps, max_parallel=1))
    assert [t for t, _ in notes_of(run) if t.startswith("triaged:")] == []  # the double raised before noting
    hyps = run.hyps[0]
    assert [h.kind for h in hyps] == ["sink", "sink", "entry"]
    assert [d.verdict for d in run.doss[0]] == [core.CONFIRMED, core.REJECTED, core.REJECTED]  # the baseline reached the verifier (fail open)
    assert all(d.notes == "n" and d.specialist != "triage" for d in run.doss[0])


def test_no_triage_node_means_the_old_flow():
    run = FakeRun([])
    eps = [Candidate(kind="entry", file="x.js", line=1, symbol="x", route=["GET /x"])]
    _run(_workflow(run, entry_points_fn=lambda: eps, max_parallel=1))
    assert len(run.doss[0]) == 1 and run.doss[0][0].specialist == ""


def test_scan_node_is_the_first_edge_when_scan_fn_is_given():
    from scanner.adapter.static import ScanResult
    run = FakeRun(anchors=[])  # an empty store: the scan node is what fills it
    wf = _workflow(run, scan_fn=lambda: ScanResult(anchors=[A1], ran=["gosec"]))
    assert [n.name for n in wf.graph.nodes][:3] == ["__START__", "scan", "build_skeleton"]
    _run(wf)
    assert [a.id for a in run.anchors()] == [A1.id] and run.artifact("scan")["ran"] == ["gosec"]
