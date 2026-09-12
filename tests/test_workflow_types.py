"""Card 43 step 1: the payloads that travel between Workflow nodes (core, no ADK) round-trip as JSON."""

from scanner.core import Candidate, Hypothesis
from scanner.core.workflow import InvestigateResult, QueueState, Report, ScanSkeleton


def test_skeleton_round_trip():
    s = ScanSkeleton(target="/t", entry_points=[Candidate(kind="entry", file="main.go", line=3, symbol="h")],
                     anchors=[{"id": "a_1", "tool": "gosec", "cwe": "CWE-89", "file": "main.go", "line": 22, "message": "m"}])
    assert ScanSkeleton.model_validate(s.model_dump()) == s
    assert ScanSkeleton.model_validate_json(s.model_dump_json()).entry_points[0].symbol == "h"


def test_queue_state_keeps_hypotheses_and_done_keys():
    q = QueueState(queue=[Hypothesis(id="h0-1", kind="sink", cwe="CWE-89", anchor_id="a_1")], done=["a:a_1"])
    back = QueueState.model_validate_json(q.model_dump_json())
    assert back.queue[0].anchor_id == "a_1" and set(back.done) == {"a:a_1"}


def test_result_and_report_defaults():
    assert InvestigateResult().rounds == 0 and InvestigateResult().stop == ""
    r = Report(rounds=2, stop_reason="round limit", timings={"verify_0": 1.5})
    assert Report.model_validate(r.model_dump()) == r


def test_card45_schemas_round_trip_and_ignore_extras():
    """Plan §3 schemas: every node payload is a pydantic model with extra='ignore' (model output may carry noise)."""
    from scanner.core import Anchor
    from scanner.core.workflow import (
        Confirmation,
        DirectResult,
        ExportResult,
        PlanState,
        ReconMap,
        ResearchResult,
        ReviewVerdict,
        RuleEval,
        TriageBatch,
        TriageClassification,
        TriageCoverage,
        Viability,
    )
    a = Anchor(id="a_1", tool="gosec", rule_id="G1", cwe="CWE-89", severity="high", file="m.go", line=2)
    d = DirectResult(remaining=[a], reported=["f_1"])
    assert DirectResult.model_validate_json(d.model_dump_json()).remaining[0].id == "a_1"
    r = ReconMap(sources=[Candidate(kind="entry", file="r.js", line=3, symbol="h")], sinks={"CWE-89": ["db.js:10"]},
                 auth=["isLoggedIn"], config_files=["config/env.js"])
    assert ReconMap.model_validate(r.model_dump()) == r and ReconMap().sinks == {}
    p = PlanState(queue=[Hypothesis(id="h0-1", kind="entry", anchor_id="a_1")], done=["k"], batches=[["a.js", "b.js"]])
    assert PlanState.model_validate_json(p.model_dump_json()).batches == [["a.js", "b.js"]]
    t = TriageBatch(classifications=[TriageClassification(file="a.js", flagged=True, classes=["CWE-79"], why="render")])
    assert TriageBatch.model_validate({"classifications": [{"file": "a.js", "flagged": True, "noise": 1}]}).classifications[0].classes == []
    assert t.classifications[0].flagged is True
    c = TriageCoverage(considered=3, classified=2, missing=["c.js"], flagged=["a.js"])
    assert TriageCoverage.model_validate(c.model_dump()) == c
    assert ResearchResult(rounds=2, stop="", findings=4).findings == 4
    rv = ReviewVerdict(finding_id="f_1", status="PROVISIONALLY_VALID", reasoning="r", repro_hints=["h"],
                       checklist={"hypothetical_misuse": RuleEval(outcome="PASS", reason="ok")})
    assert ReviewVerdict.model_validate_json(rv.model_dump_json()).checklist["hypothetical_misuse"].outcome == "PASS"
    assert Viability(finding_id="f_1", viability="CONDITIONAL_VIABLE", reasoning="x").viability == "CONDITIONAL_VIABLE"
    assert Confirmation(finding_id="f_1", repro_status="statically_confirmed").repro_hints == []
    e = ExportResult(rounds=1, stop_reason="", timings={}, reductions=["triage missing 2 files"], coverage="reduced")
    assert ExportResult.model_validate(e.model_dump()).coverage == "reduced" and ExportResult().coverage == "complete"


def test_card45_literals_reject_unknown_values():
    import pytest

    from scanner.core.workflow import ReviewVerdict, RuleEval, Viability
    with pytest.raises(ValueError):
        RuleEval(outcome="MAYBE", reason="")
    with pytest.raises(ValueError):
        ReviewVerdict(finding_id="f", status="OK", reasoning="")
    with pytest.raises(ValueError):
        Viability(finding_id="f", viability="YES", reasoning="")
