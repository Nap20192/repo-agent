import json
import shutil
from pathlib import Path

import pytest

from scanner.adapter.static import (
    anchors_from_sarif,
    entry_points,
    has_symbol,
    read_lines,
    scan,
)

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "02-vulnshop"

SARIF = {"runs": [{
    "tool": {"driver": {"name": "gosec", "rules": [
        {"id": "G201", "properties": {"tags": ["CWE-89"]}},
        {"id": "G204", "relationships": [{"target": {"id": "78", "toolComponent": {"name": "CWE"}}}]},
    ]}},
    "results": [
        {"ruleId": "G201", "level": "error", "message": {"text": "sqli"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "./main.go"}, "region": {"startLine": 22}}}]},
        {"ruleIndex": 1, "level": "warning", "message": {"text": "cmd"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "main.go"}, "region": {"startLine": 30}}}]},
        {"ruleId": "G201", "message": {"text": "no location"}, "locations": [{"physicalLocation": {}}]},
    ],
}]}


def test_sarif_parse(tmp_path):
    a = anchors_from_sarif(json.dumps(SARIF), "gosec", tmp_path)
    assert [(x.rule_id, x.cwe, x.file, x.line, x.severity) for x in a] == [
        ("G201", "CWE-89", "main.go", 22, "high"), ("G204", "CWE-78", "main.go", 30, "medium")]
    assert a[0].id.startswith("a_") and a[0].id != a[1].id


def test_entry_points_symbol_reader(tmp_path):
    (tmp_path / "main.go").write_text('package main\nfunc main() {\n\thttp.HandleFunc("/x", xHandler)\n}\nfunc xHandler() {}\n')
    (tmp_path / "app.py").write_text('@app.route("/y")\ndef y():\n    pass\n')
    eps = entry_points(tmp_path)
    assert {(e.file, e.line, e.symbol) for e in eps} == {("main.go", 3, "xHandler"), ("app.py", 2, "y")}
    assert has_symbol(tmp_path, "main.xHandler") and has_symbol(tmp_path, "y") and not has_symbol(tmp_path, "nope")
    assert "HandleFunc" in read_lines(tmp_path, "main.go", 3, 1)
    with pytest.raises(FileNotFoundError):
        read_lines(tmp_path, "missing.go", 1)


def test_scan_missing_binary_never_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "")
    (tmp_path / "a.go").write_text("package main\n")
    res = scan(tmp_path)
    assert res.anchors == [] and "gosec" in res.failed and res.ran == []


@pytest.mark.skipif(shutil.which("gosec") is None or not SAMPLE.exists(), reason="gosec/sample missing")
def test_scan_vulnshop():
    res = scan(SAMPLE, skip_deps=True)
    assert "gosec" in res.ran
    cwes = {(a.cwe, a.file) for a in res.anchors}
    assert ("CWE-89", "main.go") in cwes and ("CWE-78", "main.go") in cwes


def test_js_route_with_named_handler_and_semicolon(tmp_path):
    (tmp_path / "s.js").write_text('const app = require("express")();\nfunction render(req, res) {}\napp.get("/r", render);\napp.post("/x", (req, res) => res.send(1));\n')
    eps = entry_points(tmp_path)
    assert [(c.file, c.line, c.symbol) for c in eps] == [("s.js", 3, "render")]  # inline arrow handlers are not entry points


def test_osv_anchors_aggregate_per_package(tmp_path, monkeypatch):
    from scanner.adapter import static as st
    data = {"results": [{"source": {"path": str(tmp_path / "package-lock.json")}, "packages": [
        {"package": {"name": "lodash", "version": "4.17.15"}, "vulnerabilities": [{"id": "CVE-1"}, {"id": "GHSA-a"}, {"id": "GHSA-b"}]},
        {"package": {"name": "express", "version": "4.17.1"}, "vulnerabilities": [{"id": "GHSA-x", "summary": "s"}]},
        {"package": {"name": "clean", "version": "1"}, "vulnerabilities": []}]}]}
    a = st.anchors_from_osv(data, tmp_path)
    assert [(x.snippet, x.rule_id, len(x.rule_ids)) for x in a] == [("lodash 4.17.15", "GHSA-a", 3), ("express 4.17.1", "GHSA-x", 1)]
    assert a[0].file == "package-lock.json" and "3 advisories" in a[0].message
    monkeypatch.setattr(st, "OSV_MAX", 1)
    assert len(st.anchors_from_osv(data, tmp_path)) == 1


def test_secret_class_anchor_snippets_are_redacted(tmp_path):
    from scanner.adapter import static as st
    key = "MIICXgIBAAKBgQCfn8uP4FuHaaAPrMkcl1fNMQM5EGMT4nnNSVoaEVdiDLc6P0mC"
    a = st.Anchor(id="x", tool="semgrep", rule_id="detected-private-key", cwe="CWE-798", file="k.pem", line=1,
                  snippet="-----BEGIN RSA PRIVATE KEY-----\n" + key, message="key " + key)
    res = st._run_jobs(tmp_path, [("fake", lambda t: [a])])
    assert key not in res.anchors[0].snippet and key not in res.anchors[0].message and "MIIC…" in res.anchors[0].snippet


def test_read_lines_refuses_symlink_escape(tmp_path):
    (tmp_path / "t").mkdir()
    (tmp_path / "outside.txt").write_text("secret\n")
    (tmp_path / "t" / "link").symlink_to(tmp_path / "outside.txt")
    with pytest.raises(FileNotFoundError):
        read_lines(tmp_path / "t", "link", 1)
