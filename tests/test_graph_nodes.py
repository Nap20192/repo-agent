"""Card 43 steps 3–4: the Workflow nodes, run one at a time under the real ADK Runner with the fakes."""

from scanner import core
from scanner.app.graph import nodes as graph_nodes
from scanner.core import Anchor, Candidate, Dossier, Finding, Hypothesis
from scanner.core.workflow import ScanSkeleton
from tests.fakes import A1, A2, FakeRun, _run_node

OSV = Anchor(id="a_osv", tool="osv", rule_id="GHSA-x", rule_ids=["GHSA-x"], severity="high", file="package-lock.json",
             line=1, snippet="lodash 4.17.11", message="lodash@4.17.11: 1 advisories")


def test_build_skeleton_node_trims_anchors_and_lists_entry_points():
    run = FakeRun([A1, A2])
    entries = [Candidate(kind="entry", file="main.go", line=3, symbol="h")]
    outs = _run_node(graph_nodes.build_skeleton_node(run, "/t", lambda: entries))
    sk = ScanSkeleton.model_validate(outs[-1])
    assert sk.target == "/t" and [c.symbol for c in sk.entry_points] == ["h"]


def test_direct_findings_node_reports_without_the_model_and_returns_the_rest():
    run = FakeRun([A1, OSV])
    outs = _run_node(graph_nodes.direct_findings_node(run, ""), [a.model_dump() for a in run.anchors()])
    out = outs[-1]
    assert [f.anchor_id for f in run.findings()] == ["a_osv"] and run.findings()[0].source == "direct"
    assert out["reported"] == ["f_1"] and [a["id"] for a in out["remaining"]] == ["a_1"]
    assert run.artifact("direct_findings") == {"ids": ["f_1"]}


# --- step 4: parallel-worker nodes -------------------------------------------------------------------------

def _verifier_node(store, fail: bool = False):
    """Node-shaped specialist double: confirms CWE-89 through the store, returns a Dossier dict; or raises."""
    from google.adk.workflow import FunctionNode

    async def fake(ctx, node_input: dict) -> dict:
        if fail:
            raise RuntimeError("boom")
        h = node_input
        status = core.CONFIRMED if h["cwe"] == "CWE-89" else core.REJECTED
        store.report(Finding(anchor_id=h["anchor_id"], hypothesis_id=h["id"], cwe=h["cwe"], file="main.go",
                             title="t", status=status, evidence=["db.Query(x)"]))
        return {"hypothesis_id": h["id"], "verdict": status, "notes": "seen " + h["specialist"],
                "new_hypotheses": [{"kind": "sink", "cwe": "CWE-89", "claim": "dup", "anchor_id": "a_1"}]}
    return FunctionNode(func=fake, name="fake_fail" if fail else "fake_ok", rerun_on_resume=True)


def _router(item, lang, role):
    return ("taint", "overlay") if getattr(item, "cwe", "") == "CWE-89" else ("", "")


def test_route_and_verify_routes_contains_failures_and_keeps_order():
    run = FakeRun([A1, A2])
    node = graph_nodes.route_and_verify_node(run, verifier=_verifier_node(run, fail=True),
                                             specialists={"taint": _verifier_node(run)}, router=_router, max_parallel=2)
    hs = [Hypothesis(id="h0-1", kind="sink", cwe="CWE-89", anchor_id="a_1", reads=["main.go"]),
          Hypothesis(id="h0-2", kind="sink", cwe="CWE-78", anchor_id="a_2", reads=["main.go"])]
    outs = _run_node(node, [h.model_dump() for h in hs])
    ds = [Dossier.model_validate(d) for d in outs[-1]]
    assert [d.hypothesis_id for d in ds] == ["h0-1", "h0-2"]  # batch order, not completion order
    assert ds[0].verdict == core.CONFIRMED and ds[0].finding_id == "f_1" and ds[0].specialist == "taint"
    assert ds[0].notes == "seen taint" and ds[0].new_hypotheses[0].anchor_id == "a_1"
    assert ds[1].verdict == core.UNCERTAIN and "boom" in ds[1].error and ds[1].specialist == ""
    assert len(run.findings()) == 1  # the failing generic verifier reported nothing


def test_route_and_verify_verdict_comes_from_the_store_not_the_model_text():
    run = FakeRun([A1])
    from google.adk.workflow import FunctionNode

    async def prose(ctx, node_input: dict) -> str:
        run.report(Finding(anchor_id="a_1", hypothesis_id="h0-1", cwe="CWE-89", file="main.go", title="t",
                           status=core.CONFIRMED, evidence=["db.Query(x)"]))
        return "I confirmed it but forgot the JSON"
    node = graph_nodes.route_and_verify_node(run, verifier=FunctionNode(func=prose, name="prose", rerun_on_resume=True),
                                             specialists={}, router=None, max_parallel=0)
    d = Dossier.model_validate(_run_node(node, [Hypothesis(id="h0-1", kind="sink", cwe="CWE-89", anchor_id="a_1").model_dump()])[-1][0])
    assert d.verdict == core.CONFIRMED and d.finding_id == "f_1" and d.error == ""


def test_review_worker_routes_to_specialist_critics_and_annotates():
    run = FakeRun([A1])
    f = run.report(Finding(anchor_id="a_1", cwe="CWE-89", file="main.go", title="t", status=core.CONFIRMED, evidence=["e"]))
    from google.adk.workflow import FunctionNode

    async def critic(ctx, node_input: dict) -> dict:
        assert node_input["finding"]["status"] == core.CONFIRMED and node_input["anchor"]["id"] == "a_1"
        run.set_status(node_input["finding"]["id"], core.UNCERTAIN, ["critic: parameterized"])  # through the gate in real runs
        return {"finding_id": node_input["finding"]["id"], "status": "FALSE_POSITIVE", "reasoning": "parameterized"}
    node = graph_nodes.review_node(FunctionNode(func=critic, name="c", rerun_on_resume=True), run,
                                   specialists={"taint_critic": FunctionNode(func=critic, name="tc", rerun_on_resume=True)},
                                   router=lambda item, lang, role: ("taint_critic", ""), max_parallel=1)
    outs = _run_node(node, [f.model_dump()])
    assert outs[-1] == [{"finding_id": "f_1", "specialist": "taint_critic", "error": ""}]
    assert run.findings()[0].status == core.UNCERTAIN  # the agent disproved it → FALSE_POSITIVE stands
    assert run.findings()[0].review["status"] == "FALSE_POSITIVE"


def test_triage_sweep_without_an_agent_flags_every_file():
    run = FakeRun()
    outs = _run_node(graph_nodes.triage_sweep_node(None, run, 2), [{"files": ["a.js", "b.js"]}])
    assert [c["file"] for c in outs[-1][0]["classifications"]] == ["a.js", "b.js"]
    assert all(c["flagged"] for c in outs[-1][0]["classifications"])


# --- shared helpers (scanner/app/graph.py) -------------------------------------------------------------------

def test_parse_json_and_dossier_from_store():
    from scanner.app.graph.helpers import dossier_from_store, parse_json
    assert parse_json("junk {\"a\": {\"b\": 1}} tail") == {"a": {"b": 1}}
    assert parse_json("nope") is None
    h = Hypothesis(id="h0-1", anchor_id="a_1")
    fs = [Finding(id="f1", anchor_id="a_1", status=core.REJECTED), Finding(id="f2", anchor_id="a_1", hypothesis_id="h0-1", status=core.CONFIRMED),
          Finding(id="f3", anchor_id="a_1", hypothesis_id="other", status=core.CONFIRMED)]
    assert dossier_from_store(fs, h).finding_id == "f2"
    assert dossier_from_store([], h).verdict == core.UNCERTAIN


def test_pick_agent_unknown_name_falls_back_and_no_router_is_generic():
    from scanner.app.graph.helpers import pick_agent
    h = Hypothesis(id="h0-1", anchor_id="a_1", cwe="CWE-89", reads=["main.go"])
    assert pick_agent(h, "investigate", {}, lambda item, lang, role: ("nope", "x"), "generic") == ("generic", "", "")
    assert pick_agent(h, "investigate", {"taint": "t"}, None, "generic") == ("generic", "", "")
    assert pick_agent(h, "investigate", {"taint": "t"}, lambda item, lang, role: ("taint", f"OVERLAY:{lang}"), "generic") == ("t", "taint", "OVERLAY:go")


def test_skill_lists_for_investigators_and_critics():
    """Investigators get the WSTG/class/analysis skill list; critics get the control skill first."""
    from scanner.adapter.skills import skills_for
    inv = skills_for("CWE-89", "sink")
    crit = skills_for("CWE-89", "", "critique")
    assert inv and inv[0].startswith("wstg-") and crit and crit[0].startswith("control-")


def test_scan_node_saves_anchors_and_writes_the_scan_artifact():
    """The pre-pass is a graph node: scanners run inside the Workflow, anchors land in the store, the
    artifact records what ran and what failed (visible in adk web, replayed on resume)."""
    from scanner.adapter.scanners import ScanResult
    run = FakeRun()
    res = ScanResult(anchors=[A1, A2], ran=["gosec", "semgrep"], failed={"osv": "no manifests"})
    outs = _run_node(graph_nodes.scan_node(run, lambda: res))
    assert [a.id for a in run.anchors()] == [A1.id, A2.id]
    assert outs[-1] == {"anchors": 2, "ran": ["gosec", "semgrep"], "failed": {"osv": "no manifests"}}
    assert run.artifact("scan") == {"anchors": 2, "by_tool": {"gosec": 2}, "ran": ["gosec", "semgrep"], "failed": {"osv": "no manifests"}}


def test_scan_node_is_skipped_on_resume_when_anchors_exist():
    from scanner.adapter.scanners import ScanResult
    run = FakeRun([A1])
    run.put_artifact("scan", {"anchors": 1, "by_tool": {"gosec": 1}, "ran": ["gosec"], "failed": {}})
    calls = []

    def scan():
        calls.append(1)
        return ScanResult()
    outs = _run_node(graph_nodes.scan_node(run, scan))
    assert calls == [] and outs[-1]["anchors"] == 1 and [a.id for a in run.anchors()] == [A1.id]
