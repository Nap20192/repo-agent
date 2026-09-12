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
