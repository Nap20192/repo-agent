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


def test_report_fills_owasp_fields_and_sarif_taxonomies(tmp_path):
    run = Store(str(tmp_path / "s.db")).start_run("t")
    f = run.report(Finding(anchor_id="a_1", cwe="CWE-89", file="main.go", line=22, title="sqli", severity="high",
                           status=CONFIRMED, evidence=["db.Query(x)"], confidence=0.9))
    assert f.wstg_id == "WSTG-INJT-05" and f.top10 == "A05:2025" and f.remediation and "SQL_Injection" in f.remediation_url
    sarif = json.loads(run.write_report(tmp_path / "out").read_text())
    run0 = sarif["runs"][0]
    names = {t["name"] for t in run0["taxonomies"]}
    assert names == {"WSTG", "OWASP Top 10 2021", "OWASP Top 10 2025", "ASVS"}
    res = run0["results"][0]
    assert {x["toolComponent"]["name"] for x in res["taxa"]} == names
    assert res["fixes"][0]["description"]["text"] == f.remediation
    summary = json.loads(run.write_summary(tmp_path / "out").read_text())
    assert summary["findings"][0]["remediation_url"] == f.remediation_url


def test_report_without_cwe_does_not_raise(tmp_path):
    """Dependency (osv) and entrypoint anchors carry no CWE; report() must still record the verdict."""
    from scanner.core import Anchor, Finding
    run = Store(str(tmp_path / "s.db")).start_run("t")
    run.save_anchors([Anchor(id="a_osv", tool="osv", rule_id="GHSA-x", cwe="", severity="high", file="go.mod", line=1)])
    f = run.report(Finding(anchor_id="a_osv", cwe="", file="go.mod", line=1, title="vuln dep", status="confirmed", evidence=["knowledge:GHSA-x"]))
    assert f.id == "f_1" and f.remediation == "" and f.top10 == ""


def test_sarif_taxonomies_declare_every_result_taxon(tmp_path):
    from scanner.core import Anchor, Finding
    run = Store(str(tmp_path / "s.db")).start_run("t")
    run.save_anchors([Anchor(id="a", tool="gosec", cwe="CWE-89", severity="high", file="m.go", line=1)])
    run.report(Finding(anchor_id="a", cwe="CWE-89", file="m.go", line=1, title="sqli", status="confirmed", evidence=["x"]))
    sarif = json.loads(run.write_report(tmp_path).read_text())["runs"][0]
    declared = {(t["name"], x["id"]) for t in sarif["taxonomies"] for x in t["taxa"]}
    used = {(x["toolComponent"]["name"], x["id"]) for r in sarif["results"] for x in r["taxa"]}
    assert used and used <= declared
    assert any(x["name"] == "SQL Injection" for t in sarif["taxonomies"] if t["name"] == "WSTG" for x in t["taxa"])


def test_summary_exposure_comes_from_the_architecture_model(tmp_path):
    from scanner.core import Anchor, Finding
    run = Store(str(tmp_path / "s.db")).start_run("t")
    run.save_anchors([Anchor(id="a", tool="gosec", cwe="CWE-78", severity="high", file="main.go", line=30)])
    run.report(Finding(anchor_id="a", cwe="CWE-78", file="main.go", line=30, title="pingHandler cmdi", status="confirmed", evidence=["x"], confidence=0.9))
    run.put_artifact("architecture_model", {"entities": [], "trust_boundaries": ["Srv: pingHandler - untrusted input"]})
    s = json.loads(run.write_summary(tmp_path).read_text())
    assert s["findings"][0]["calibration"]["multiplier"] > 0.7  # exposed: ×1.0 instead of internal ×0.8


def test_direct_source_lands_in_sarif_and_summary(tmp_path):
    run = Store(str(tmp_path / "s.db")).start_run("t")
    run.report(Finding(anchor_id="a_1", cwe="CWE-798", file="c.js", line=6, title="secret", severity="high",
                       status=CONFIRMED, evidence=["c.js:6: k"], confidence=1.0, source="direct"))
    sarif = json.loads(run.write_report(tmp_path / "out").read_text())
    assert sarif["runs"][0]["results"][0]["properties"]["source"] == "direct"
    summary = json.loads(run.write_summary(tmp_path / "out").read_text())
    assert summary["findings"][0]["source"] == "direct"


def test_direct_findings_dedup_by_anchor_only(tmp_path):
    """Two vulnerable packages with the same CWE both sit at package-lock.json:1 — they are two findings."""
    run = Store(str(tmp_path / "s.db")).start_run("t")
    for a in ("a_osv1", "a_osv2"):
        run.report(Finding(anchor_id=a, cwe="CWE-1321", file="package-lock.json", line=1, title=a, severity="high",
                           status=CONFIRMED, evidence=["package-lock.json:1"], confidence=1.0, source="direct"))
    assert len(run.findings()) == 2
    assert run.report(Finding(anchor_id="a_osv1", cwe="CWE-1321", file="package-lock.json", line=1, title="again",
                              status=CONFIRMED, confidence=1.0, source="direct")).id == "f_1"


def test_llm_findings_dedup_within_near_lines(tmp_path):
    from scanner.adapter.store import Store
    run = Store(str(tmp_path / "s.db")).start_run("/t")
    a = run.report(Finding(anchor_id="a1", cwe="CWE-95", file="c.js", line=32, title="eval", status="confirmed", confidence=0.9))
    b = run.report(Finding(anchor_id="a2", cwe="CWE-95", file="c.js", line=34, title="eval again", status="confirmed", confidence=0.5))
    far = run.report(Finding(anchor_id="a3", cwe="CWE-95", file="c.js", line=90, title="other eval", status="confirmed", confidence=0.5))
    assert b.id == a.id and far.id != a.id and len(run.findings()) == 2


def test_reporter_summary_and_sarif(tmp_path):
    from scanner.adapter.store import Store
    from tests.fakes import A1, A2
    store = Store(str(tmp_path / "s.db"))
    run = store.start_run("/t")
    run.save_anchors([A1, A2])
    run.put_artifact("threat_model", {"intent": "sample", "threats": []})
    run.report(Finding(anchor_id="a_1", cwe="CWE-89", file="main.go", line=22, title="sqli", status=CONFIRMED, evidence=["q"]))
    run.report(Finding(anchor_id="a_2", cwe="CWE-78", file="main.go", line=30, title="cmd", status=REJECTED))
    summary = json.loads(run.write_summary(tmp_path).read_text())
    assert summary["intent"] == "sample" and summary["confirmed"] == 1 and summary["rejected"] == 1
    assert all("score" in f["calibration"] for f in summary["findings"])
    sarif = json.loads(run.write_report(tmp_path).read_text())
    results = sarif["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == ["CWE-89"] and "score" in results[0]["properties"]["calibration"]
    run.set_status("f_1", "uncertain", ["critic: safe"])  # disprove → reflected in the summary
    assert json.loads(run.write_summary(tmp_path).read_text())["uncertain"] == 1
    store.close()


def test_annotate_merges_fields_and_refuses_verdict_fields(tmp_path):
    """Card 45: review/viability/confirm write annotations; the verdict (status/evidence/confidence) only through the gates."""
    import pytest

    run = Store(str(tmp_path / "s.db")).start_run("/t")
    f = run.report(Finding(anchor_id="a1", cwe="CWE-89", file="m.go", line=3, title="sqli", status=CONFIRMED, confidence=0.9))
    out = run.annotate(f.id, review={"status": "PROVISIONALLY_VALID", "checklist": {"hypothetical_misuse": {"outcome": "PASS", "reason": ""}}},
                       viability="CONDITIONAL_VIABLE")
    assert out.review["status"] == "PROVISIONALLY_VALID" and out.viability == "CONDITIONAL_VIABLE" and out.status == CONFIRMED
    again = run.annotate(f.id, repro_status="statically_confirmed")
    assert again.review["status"] == "PROVISIONALLY_VALID" and again.repro_status == "statically_confirmed"  # merge, not replace
    assert run.findings()[0].repro_status == "statically_confirmed"
    assert run.annotate("f_nope", viability="VIABLE") is None
    for bad in ("status", "evidence", "confidence", "id", "anchor_id"):
        with pytest.raises(ValueError):
            run.annotate(f.id, **{bad: "x"})
    with pytest.raises(ValueError):
        run.annotate(f.id, not_a_field="x")


def test_annotations_land_in_sarif_properties(tmp_path):
    run = Store(str(tmp_path / "s.db")).start_run("/t")
    f = run.report(Finding(anchor_id="a1", cwe="CWE-89", file="m.go", line=3, title="sqli", status=CONFIRMED, confidence=0.9))
    run.annotate(f.id, review={"status": "VALID"}, viability="VIABLE", repro_status="statically_confirmed")
    g = run.report(Finding(anchor_id="a2", cwe="CWE-79", file="v.js", line=8, title="xss", status=CONFIRMED, confidence=0.8))
    sarif = json.loads(run.write_report(tmp_path).read_text())
    props = {r["properties"]["finding_id"]: r["properties"] for r in sarif["runs"][0]["results"]}
    assert props[f.id]["review"] == {"status": "VALID"} and props[f.id]["viability"] == "VIABLE" and props[f.id]["repro_status"] == "statically_confirmed"
    assert "review" not in props[g.id] and "viability" not in props[g.id]  # empty annotations are not exported
    summary = json.loads(run.write_summary(tmp_path).read_text())
    assert summary["findings"][0]["viability"] == "VIABLE"
