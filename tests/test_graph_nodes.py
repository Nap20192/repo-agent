"""Card 43 steps 3–4: the Workflow nodes, run one at a time under the real ADK Runner with the fakes."""

from scanner.app import graph_nodes
from scanner.core import Anchor, Candidate
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
    assert sk.anchors[0] == {"id": "a_1", "tool": "gosec", "cwe": "CWE-89", "file": "main.go", "line": 22, "message": ""}


def test_direct_findings_node_reports_without_the_model_and_returns_the_rest():
    run = FakeRun([A1, OSV])
    outs = _run_node(graph_nodes.direct_findings_node(run, ""), [a.model_dump() for a in run.anchors()])
    out = outs[-1]
    assert [f.anchor_id for f in run.findings()] == ["a_osv"] and run.findings()[0].source == "direct"
    assert out["reported"] == ["f_1"] and [a["id"] for a in out["remaining"]] == ["a_1"]
    assert run.artifact("direct_findings") == {"ids": ["f_1"]}
