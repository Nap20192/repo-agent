"""Node payload schemas: what crosses the edges of the small graph."""

from scanner.core import Anchor, Candidate, Hypothesis
from scanner.core.workflow import DirectResult, ExportResult, QueueState, ResearchResult, ScanSkeleton


def test_skeleton_round_trip():
    s = ScanSkeleton(target="/t", entry_points=[Candidate(kind="entry", file="a.go", line=3, symbol="h")])
    assert ScanSkeleton.model_validate(s.model_dump()) == s and ScanSkeleton().entry_points == []


def test_queue_state_keeps_hypotheses_and_done_keys():
    q = QueueState(queue=[Hypothesis(id="h0-1", kind="entry", anchor_id="a_1")], done=["k"])
    assert QueueState.model_validate_json(q.model_dump_json()).queue[0].id == "h0-1"


def test_direct_result_research_and_export_defaults_and_ignore_extras():
    d = DirectResult(remaining=[Anchor(id="a", tool="gosec", rule_id="G1", file="a.go", line=1)], reported=["f_1"], noise=1)
    assert DirectResult.model_validate(d.model_dump()).reported == ["f_1"]
    assert ResearchResult().stop == "" and ResearchResult(rounds=2, stop="budget", findings=3).findings == 3
    e = ExportResult(rounds=1, stop_reason="", timings={"model": 1.5}, reductions=["model failed"])
    assert ExportResult.model_validate_json(e.model_dump_json()).coverage == "complete" and e.reductions == ["model failed"]
