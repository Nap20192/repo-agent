import json

from scanner.adapter.store import Store
from scanner.core import CONFIRMED, REJECTED, Anchor, Dossier, Finding, Hypothesis


def test_store_roundtrip_dedup_and_reports(tmp_path):
    run = Store(str(tmp_path / "s.db")).start_run("t")
    a = Anchor(id="a_1", tool="gosec", rule_id="G201", cwe="CWE-89", severity="high", file="main.go", line=22)
    run.save_anchors([a])
    assert run.anchor("a_1") == a and run.anchor("nope") is None and len(run.anchors()) == 1

    run.put_hypotheses(0, [Hypothesis(id="h0-0", kind="sink", claim="c", anchor_id="a_1")])
    run.put_dossiers(0, [Dossier(hypothesis_id="h0-0", verdict=CONFIRMED)])

    f1 = run.report(Finding(anchor_id="a_1", cwe="CWE-89", file="main.go", line=22, title="sqli",
                            severity="high", status=REJECTED, confidence=0.3))
    assert f1.id == "f_1"
    # same anchor, lower confidence → existing returned unchanged
    assert run.report(Finding(anchor_id="a_1", title="x", status=CONFIRMED, confidence=0.1)).status == REJECTED
    # same cwe+file+line, higher confidence → verdict replaced, same id
    f3 = run.report(Finding(cwe="CWE-89", file="main.go", line=22, title="y", status=CONFIRMED,
                            evidence=["db.Query(..)"], confidence=0.9))
    assert f3.id == "f_1" and f3.status == CONFIRMED and len(run.findings()) == 1

    run.log_gate("a_1", "no evidence")
    run.add_note("n", "a_1")
    assert run.notes()[0]["text"] == "n"

    sarif = json.loads(run.write_report(tmp_path / "out").read_text())
    res = sarif["runs"][0]["results"]
    assert len(res) == 1 and res[0]["ruleId"] == "CWE-89" and res[0]["level"] == "error"
    summary = json.loads(run.write_summary(tmp_path / "out").read_text())
    assert summary["confirmed"] == 1 and summary["gate_refusals"] == 1 and summary["run_id"] == run.id
    run.finish("done")


def test_orphans_marked_stopped(tmp_path):
    s = Store(str(tmp_path / "s.db"))
    r1 = s.start_run("t")
    s.start_run("t")
    assert s.db.execute("SELECT status FROM runs WHERE id=?", (r1.id,)).fetchone()[0] == "stopped"
