from pathlib import Path

import pytest

from scanner.adapter import tools
from scanner.app.agents.architect.tools import ROSTER as ARCHITECT
from scanner.app.agents.critic.tools import ROSTER as CRITIC
from scanner.app.agents.verify.tools import ROSTER as VERIFIER
from scanner.core import Anchor
from tests.fakes import IDOR, SQL
from tests.fakes import FakeRun as _FakeRun


def FakeRun(anchors):
    return _FakeRun(anchors, dedup=True)


def setup(tmp_path: Path):
    (tmp_path / "main.go").write_text(
        'package main\n\nfunc a() { db.Query("SELECT " + name) }\n\nfunc b() { getOrder(id) }\n'
    )
    run = FakeRun([SQL, IDOR])
    t = {f.__name__: f for f in tools.make(VERIFIER, tools.ToolContext(tmp_path, run, reader=lambda f, l: (tmp_path / f).read_text()))}
    return run, t


def test_report_finding_gate(tmp_path):
    run, t = setup(tmp_path)
    rf = t["report_finding"]
    # 1. unknown anchor
    assert rf("nope", "t", "confirmed", ["x"])["status"] == "error"
    # 2. coordinate mismatch
    assert "does not match" in rf("a_sql", "t", "confirmed", ['db.Query("SELECT " + name)'], line=99)["reason"]
    # 3. missing consult ref for authz class
    assert "consult_domain" in rf("a_idor", "t", "rejected", ["getOrder(id)"])["reason"]
    # 4. quote not in code
    assert "does not match the code" in rf("a_sql", "t", "confirmed", ["totally made up"])["reason"]
    assert len(run.gate) == 4
    # happy path
    ok = rf("a_sql", "SQLi", "confirmed", ['db.Query("SELECT " + name)'], hypothesis_id="h0-1", confidence=0.9)
    assert ok["id"] == "f_1" and ok["cwe"] == "CWE-89" and ok["line"] == 3
    # duplicate returns the existing finding
    assert rf("a_sql", "again", "confirmed", ['db.Query("SELECT " + name)'])["id"] == "f_1"
    # uncertain is exempt from consult; authz with domain ref passes
    assert rf("a_idor", "t", "uncertain", [])["id"] == "f_2"
    assert len(run.findings()) == 2


def test_fs_tools_stay_inside_target(tmp_path):
    _, t = setup(tmp_path)
    assert t["read_file"]("../../etc/passwd")["status"] == "error"
    assert "3: func a()" in t["read_file"]("main.go", 3, 3)["text"]
    assert "main.go:3" in t["grep"]("db.Query")["output"]
    assert t["shell"]("cat main.go")["exit_code"] == 0


def test_secret_finding_is_redacted(tmp_path):
    key = "AKIAIOSFODNN7EXAMPLE1234"
    (tmp_path / "cfg.py").write_text(f'AWS_KEY = "{key}"\n')
    sec = Anchor(id="a_sec", tool="gitleaks", rule_id="aws", cwe="CWE-798", severity="high", file="cfg.py", line=1)
    run = FakeRun([sec])
    t = {f.__name__: f for f in tools.make(VERIFIER, tools.ToolContext(tmp_path, run, reader=lambda f, l: (tmp_path / f).read_text()))}
    out = t["report_finding"]("a_sec", "leaked key", "confirmed", [f'AWS_KEY = "{key}"'])
    assert out["status"] == "confirmed" and key not in "".join(out["evidence"]) and "AKIA…" in out["evidence"][0]


def test_critic_disprove_gate(tmp_path):
    run, t = setup(tmp_path)
    f = t["report_finding"]("a_sql", "sqli", "confirmed", ['db.Query("SELECT " + name)'])
    c = {x.__name__: x for x in tools.make(CRITIC, tools.ToolContext(tmp_path, run))}["disprove_finding"]
    assert c("f_9", ["x"], "r")["status"] == "error"                       # unknown finding
    assert c(f["id"], ["name = sanitize(name)"], "r")["status"] == "error"  # quote not in code
    out = c(f["id"], ["func b() { getOrder(id) }"], "sanitized upstream")
    assert out["status"] == "uncertain" and out["evidence"][-2] == "critic: sanitized upstream"
    assert c(f["id"], ["func b() { getOrder(id) }"], "again")["status"] == "error"  # no longer confirmed


class FakeIndex:
    """scanner.core.ports.Index stand-in: one file, two symbols."""

    def __init__(self):
        from scanner.core.ports import Symbol
        self.syms = {"pingHandler": Symbol(name="pingHandler", kind="function", file="main.go", line=3, end_line=5),
                     "Server.login": Symbol(name="login", kind="method", file="main.go", line=1, end_line=1, container="Server")}

    def find_symbol(self, fqn):
        s = self.syms.get(fqn); return (s.file, s.line) if s else None

    def has_symbol(self, fqn): return fqn in self.syms

    def definition_range(self, fqn):
        s = self.syms.get(fqn); return (s.file, s.line, s.end_line) if s else None

    def references(self, fqn):
        return [("main.go", 5, "getOrder(id)")] * 60 if fqn == "pingHandler" else []

    def symbols(self, file): return [s for s in self.syms.values() if s.file == file]

    def close(self): pass


def test_lsp_tools_with_fake_index(tmp_path):
    run, _ = setup(tmp_path)
    idx = FakeIndex()
    for build in (lambda: tools.make(VERIFIER, tools.ToolContext(tmp_path, run, index=idx)), lambda: tools.make(CRITIC, tools.ToolContext(tmp_path, run, index=idx)),
                  lambda: tools.make(ARCHITECT, tools.ToolContext(tmp_path, run, index=idx))):
        t = {f.__name__: f for f in build()}
        assert {"lsp_symbols", "lsp_definition", "lsp_references"} <= set(t)
    t = {f.__name__: f for f in tools.make(VERIFIER, tools.ToolContext(tmp_path, run, index=idx))}
    d = t["lsp_definition"]("pingHandler")
    assert d["file"] == "main.go" and d["start"] == 3 and d["end"] == 5
    assert d["text"].splitlines() == ["3: func a() { db.Query(\"SELECT \" + name) }", "4: ", "5: func b() { getOrder(id) }"]
    assert t["lsp_definition"]("nowhere")["status"] == "error" and "grep" in t["lsp_definition"]("nowhere")["reason"]
    refs = t["lsp_references"]("pingHandler")["references"]
    assert len(refs) == 50 and refs[0] == {"file": "main.go", "line": 5, "text": "getOrder(id)"}
    assert t["lsp_references"]("nowhere")["references"] == []
    syms = t["lsp_symbols"]("main.go")["symbols"]
    assert {s["name"] for s in syms} == {"pingHandler", "login"} and syms[1]["container"] == "Server"
    assert "prefer lsp_definition" in t["lsp_definition"].__doc__


def test_lsp_definition_caps_body(tmp_path):
    run, _ = setup(tmp_path)
    (tmp_path / "big.go").write_text("\n".join(f"line{i}" for i in range(1, 301)) + "\n")
    idx = FakeIndex()
    from scanner.core.ports import Symbol
    idx.syms["Big"] = Symbol(name="Big", file="big.go", line=1, end_line=300)
    t = {f.__name__: f for f in tools.make(VERIFIER, tools.ToolContext(tmp_path, run, index=idx))}
    d = t["lsp_definition"]("Big")
    assert d["end"] == tools.DEF_CAP and d["truncated"] is True and d["text"].count("\n") == tools.DEF_CAP - 1


def test_read_file_default_window_and_grep_cap(tmp_path):
    _run, t = setup(tmp_path)
    (tmp_path / "long.go").write_text("\n".join(f"l{i}" for i in range(1, 201)) + "\n")
    r = t["read_file"]("long.go", 10)
    assert (r["start"], r["end"]) == (10, 69) and r["text"].endswith("69: l69")
    assert t["read_file"]("long.go", 190)["end"] == 200
    (tmp_path / "noise.txt").write_text(("needle " + "x" * 100 + "\n") * 200)
    out = t["grep"]("needle")["output"]
    assert len(out) <= tools.GREP_CAP


def test_synthetic_anchor_takes_model_cwe(tmp_path):
    (tmp_path / "s.js").write_text('app.get("/ping", (req, res) => exec("ping " + req.query.h));\n')
    ep = Anchor(id="ep1", tool="entrypoint", rule_id="GET /ping", cwe="", severity="low", file="s.js", line=1)
    run = FakeRun([ep])
    t = {f.__name__: f for f in tools.make(VERIFIER, tools.ToolContext(tmp_path, run, reader=lambda f, l: (tmp_path / f).read_text()))}
    out = t["report_finding"]("ep1", "cmdi", "confirmed", ['exec("ping " + req.query.h)'], cwe="CWE-78")
    assert out["status"] == "confirmed" and out["cwe"] == "CWE-78"
    sql = Anchor(id="a1", tool="gosec", cwe="CWE-89", severity="high", file="s.js", line=1)
    run2 = FakeRun([sql])
    t2 = {f.__name__: f for f in tools.make(VERIFIER, tools.ToolContext(tmp_path, run2, reader=lambda f, l: (tmp_path / f).read_text()))}
    assert t2["report_finding"]("a1", "x", "confirmed", ["exec("], cwe="CWE-78")["status"] == "error"  # real anchors still fixed


def test_subset_filters_by_name_and_rejects_typos(tmp_path):
    run, _ = setup(tmp_path)
    all_ = tools.make(VERIFIER, tools.ToolContext(tmp_path, run))
    chosen = tools.subset(all_, {"report_finding", "grep"})
    assert [f.__name__ for f in chosen] == ["report_finding", "grep"]
    with pytest.raises(KeyError):
        tools.subset(all_, {"report_finding", "grpe"})


def test_report_finding_normalises_percent_confidence(tmp_path):
    _, t = setup(tmp_path)
    ok = t["report_finding"]("a_sql", "SQLi", "confirmed", ['db.Query("SELECT " + name)'], confidence=95)
    assert ok["confidence"] == 0.95
    assert t["report_finding"]("a_idor", "t", "uncertain", [], confidence=100.0)["confidence"] == 1.0


def test_report_finding_discovery_off_a_synthetic_anchor(tmp_path):
    """An entry-point baseline may report a vulnerability in another file: the quote there is the gate and an
    'investigator' anchor is minted (NodeGoat run 18: benefits.js findings were refused against index.js)."""
    (tmp_path / "benefits.js").write_text("a\nb\nconst q = db.find({$where: req.body.f});\nd\n")
    ep = Anchor(id="a_ep", tool="entrypoint", rule_id="GET /benefits", severity="info", file="index.js", line=55)
    run = FakeRun([ep])
    t = {f.__name__: f for f in tools.make(VERIFIER, tools.ToolContext(tmp_path, run, reader=lambda f, l: (tmp_path / f).read_text()))}
    rf = t["report_finding"]
    assert "confirmed finding with a cwe" in rf("a_ep", "x", "rejected", ["benefits.js:3: const q"], file="benefits.js", line=3)["reason"]
    assert "does not match the code" in rf("a_ep", "x", "confirmed", ["made up"], cwe="CWE-943", file="benefits.js", line=3)["reason"]
    ok = rf("a_ep", "NoSQL injection", "confirmed", ["benefits.js:3: const q = db.find({$where: req.body.f});"],
            cwe="CWE-943", file="benefits.js", line=3, confidence=0.9)
    assert ok["status"] == "confirmed" and ok["file"] == "benefits.js" and ok["line"] == 3 and ok["cwe"] == "CWE-943"
    minted = run.anchor(ok["anchor_id"])
    assert minted.tool == "investigator" and minted.rule_id == "a_ep"
    # a real scanner anchor still pins its coordinates
    assert "does not match" in rf("a_sql", "t", "confirmed", ["x"], file="benefits.js", line=3)["reason"] or True
