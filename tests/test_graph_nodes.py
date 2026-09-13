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



def test_route_and_verify_overlays_the_class_contains_failures_and_keeps_order():
    """One Investigator for every hypothesis; the class section rides in the payload (specialist = the class name);
    a raising activation yields an error dossier in place, the batch order survives."""
    run = FakeRun([A1, A2])
    hs = [Hypothesis(id="h0-1", kind="sink", cwe="CWE-89", anchor_id="a_1", reads=["main.go"]),
          Hypothesis(id="h0-2", kind="sink", cwe="CWE-78", anchor_id="a_2", reads=["main.go"])]
    outs = _run_node(graph_nodes.route_and_verify_node(run, _verifier_node(run), max_parallel=2), [h.model_dump() for h in hs])
    ds = [Dossier.model_validate(d) for d in outs[-1]]
    assert [d.hypothesis_id for d in ds] == ["h0-1", "h0-2"]  # batch order, not completion order
    assert ds[0].verdict == core.CONFIRMED and ds[0].finding_id == "f_1" and ds[0].specialist == "taint"
    assert ds[0].notes == "seen taint" and ds[0].new_hypotheses[0].anchor_id == "a_1"
    assert ds[1].verdict == core.REJECTED and ds[1].specialist == "taint"  # CWE-78 is taint too; the double rejects it
    run2 = FakeRun([A1])
    outs = _run_node(graph_nodes.route_and_verify_node(run2, _verifier_node(run2, fail=True), max_parallel=1), [hs[0].model_dump()])
    d = Dossier.model_validate(outs[-1][0])
    assert d.verdict == core.UNCERTAIN and "boom" in d.error and not run2.findings()


def test_route_and_verify_verdict_comes_from_the_store_not_the_model_text():
    run = FakeRun([A1])
    from google.adk.workflow import FunctionNode

    async def prose(ctx, node_input: dict) -> str:
        run.report(Finding(anchor_id="a_1", hypothesis_id="h0-1", cwe="CWE-89", file="main.go", title="t",
                           status=core.CONFIRMED, evidence=["db.Query(x)"]))
        return "I confirmed it but forgot the JSON"
    node = graph_nodes.route_and_verify_node(run, FunctionNode(func=prose, name="prose", rerun_on_resume=True), max_parallel=0)
    d = Dossier.model_validate(_run_node(node, [Hypothesis(id="h0-1", kind="sink", cwe="CWE-89", anchor_id="a_1").model_dump()])[-1][0])
    assert d.verdict == core.CONFIRMED and d.finding_id == "f_1" and d.error == ""


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


def test_scan_node_runs_the_scanners_off_the_event_loop():
    """The pre-pass is minutes of subprocesses: it must not block adk web's loop (the SSE stream went silent and the
    UI cancelled the run)."""
    import threading

    from scanner.adapter.scanners import ScanResult
    run = FakeRun()
    seen = {}

    def scan():
        seen["thread"] = threading.get_ident()
        return ScanResult(anchors=[A1], ran=["gosec"])
    _run_node(graph_nodes.scan_node(run, scan))
    assert seen["thread"] != threading.get_ident() and A1.id in [a.id for a in run.anchors()]


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
