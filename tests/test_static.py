import json
import shutil
from pathlib import Path

import pytest

from scanner.adapter import static as st
from scanner.adapter.static import (
    anchors_from_sarif,
    entry_points,
    has_symbol,
    read_lines,
    scan,
)
from scanner.core import new_anchor_id

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
    assert [(c.file, c.line, c.symbol, c.route) for c in eps] == [("s.js", 3, "render", ["GET /r"]), ("s.js", 4, "", ["POST /x"])]  # inline handler: no symbol, route is the identity


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


def test_semgrep_packs_per_language_and_excludes(tmp_path, monkeypatch):
    from scanner.adapter import static as st
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.js").write_text("var y = 1;\n")
    seen = {}

    def fake_run(cmd, target, timeout=600):
        seen["cmd"] = cmd
        return '{"runs": []}'

    monkeypatch.setattr(st, "_run", fake_run)
    monkeypatch.delenv("SEMGREP_CONFIG", raising=False)
    st._semgrep(tmp_path)
    cmd = seen["cmd"]
    cfgs = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--config"]
    assert "p/python" in cfgs and "p/flask" in cfgs and "p/javascript" in cfgs and "p/nodejs" in cfgs and "auto" not in cfgs
    assert "--metrics=off" in cmd
    excl = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--exclude"]
    assert {".github", "docs", "artifacts", "*.md", "*.html", "*.yml", "node_modules", "*_test.go", "test_*.py"} <= set(excl)
    monkeypatch.setenv("SEMGREP_CONFIG", "p/custom")
    st._semgrep(tmp_path)
    assert [c for i, c in enumerate(seen["cmd"]) if seen["cmd"][i - 1] == "--config"] == ["p/custom"]


def test_entry_points_all_frameworks(tmp_path):
    (tmp_path / "s.ts").write_text('app.get("/x", (req, res) => { res.send(1); });\nrouter.route("/y").get(list);\napp.post("/z", async (req, res) => {\n')
    (tmp_path / "urls.py").write_text('urlpatterns = [\n    path("a/", views.index),\n    re_path(r"^b/$", views.show_b, name="b"),\n]\n')
    (tmp_path / "api.py").write_text('router = APIRouter()\n\n@router.get("/items")\nasync def items():\n    pass\n')
    (tmp_path / "web.php").write_text("<?php\nRoute::get('/u', [UserCtl::class, 'show']);\n")
    (tmp_path / "page.php").write_text("<?php\n$x = 1;\n$id = $_GET['id'];\n")
    (tmp_path / "r.go").write_text('package main\nfunc main() {\n\tr.Get("/c", chiHandler)\n\tg.GET("/d", ginHandler)\n\thttp.Handle("/e", eHandler)\n}\n')
    got = {(c.file, c.line, c.symbol, tuple(c.route)) for c in entry_points(tmp_path)}
    assert ("s.ts", 1, "", ("GET /x",)) in got
    assert ("s.ts", 2, "list", ("GET /y",)) in got
    assert ("s.ts", 3, "", ("POST /z",)) in got
    assert ("urls.py", 2, "index", ()) in got and ("urls.py", 3, "show_b", ()) in got
    assert ("api.py", 4, "items", ()) in got
    assert ("web.php", 2, "UserCtl.show", ("GET /u",)) in got
    assert ("page.php", 3, "", ("page.php",)) in got
    assert {("r.go", 3, "chiHandler", ()), ("r.go", 4, "ginHandler", ()), ("r.go", 5, "eHandler", ())} <= got


def test_js_route_detector_is_linear_on_adversarial_lines(tmp_path):
    import time
    evil = 'app.get("/x", ' + "a" * 5000 + " " * 5000 + ")"
    (tmp_path / "e.js").write_text(evil + "\n" + 'app.get("/y", (req, res) => res.send(1));\n')
    t0 = time.monotonic()
    eps = entry_points(tmp_path)
    assert time.monotonic() - t0 < 1.0
    assert [(c.line, c.route) for c in eps] == [(2, ["GET /y"])]  # the long line is skipped, the inline handler found


def test_gosec_runs_per_go_module(tmp_path, monkeypatch):
    """A go.mod in a subdirectory (Photoview: api/go.mod) is scanned from that directory and paths are re-rooted."""
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "go.mod").write_text("module x\n")
    (tmp_path / "api" / "main.go").write_text("package main\n")
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend" / "index.ts").write_text("export {}\n")
    calls = []

    def fake_run(cmd, cwd, timeout=600):
        calls.append(cwd)
        return json.dumps({"runs": [{"tool": {"driver": {"name": "gosec", "rules": []}}, "results": [
            {"ruleId": "G101", "level": "error", "message": {"text": "x"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "main.go"}, "region": {"startLine": 1}}}]}]}]})
    monkeypatch.setattr(st, "_run", fake_run)
    anchors = st._gosec(tmp_path)
    assert calls == [tmp_path / "api"]
    assert [(a.file, a.line, a.rule_id) for a in anchors] == [("api/main.go", 1, "G101")]
    assert anchors[0].id == new_anchor_id("gosec", "G101", "api/main.go", 1)


def test_gosec_without_go_mod_runs_at_the_root(tmp_path, monkeypatch):
    (tmp_path / "main.go").write_text("package main\n")
    calls = []
    monkeypatch.setattr(st, "_run", lambda cmd, cwd, timeout=600: calls.append(cwd) or "{}")
    assert st._gosec(tmp_path) == [] and calls == [tmp_path]
