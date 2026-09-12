from scanner import core
from scanner.app.reconcile import (
    adversarial_sweep,
    coverage,
    direct_finding,
    from_anchors,
    from_threats,
    key,
    reconcile,
    split_direct,
)
from scanner.core import Anchor, Candidate, Hypothesis, Threat

SQL = Anchor(id="a_sql", tool="gosec", rule_id="G202", cwe="CWE-89", severity="high", file="main.go", line=22)
OSV = Anchor(id="a_osv", tool="osv", rule_id="GHSA-x", severity="high", file="go.mod", line=1)
IDOR = Anchor(id="a_idor", tool="semgrep", rule_id="idor", cwe="CWE-639", severity="medium", file="main.go", line=31)


def test_from_anchors_kinds_and_consults():
    hs = {h.anchor_id: h for h in from_anchors([SQL, OSV, IDOR])}
    assert (hs["a_sql"].kind, hs["a_sql"].consult, hs["a_sql"].priority) == ("sink", "", 60)
    assert (hs["a_osv"].kind, hs["a_osv"].consult) == ("dependency", "knowledge")
    assert (hs["a_idor"].kind, hs["a_idor"].consult) == ("authz", "domain")


def test_threat_matches_anchor_or_stays_symbol_grounded():
    ts = [Threat(cwe="CWE-89", claim="sqli via name", file="main.go"), Threat(cwe="CWE-639", claim="idor", symbol="getOrder", file="other.go")]
    (a, b), minted = from_threats(ts, [SQL, IDOR])
    assert minted == []
    assert a.anchor_id == "a_sql" and a.claim == "sqli via name" and a.priority == 60
    assert b.anchor_id == "" and b.symbol == "getOrder" and b.kind == "authz" and b.consult == "domain"


def test_threat_mints_synthetic_anchor():
    t = Threat(cwe="CWE-639", claim="getOrder skips owner check", symbol="getOrder", priority=80)
    (h,), (a,) = from_threats([t], [], locate=lambda s: ("main.go", 31) if s == "getOrder" else None)
    assert (a.tool, a.cwe, a.file, a.line, a.severity, a.message) == ("threatmodel", "CWE-639", "main.go", 31, "high", t.claim)
    assert h.anchor_id == a.id and h.kind == "authz" and h.consult == "domain" and h.reads == ["main.go"]
    (h2,), none = from_threats([t], [], locate=lambda s: None)
    assert none == [] and h2.symbol == "getOrder" and h2.anchor_id == ""


def test_threat_grounding_is_line_aware():
    a1, a2 = SQL, SQL.model_copy(update={"id": "a_sql2", "line": 50})
    exact = Threat(cwe="CWE-89", claim="line 50", file="main.go", line=50)
    vague = Threat(cwe="CWE-89", claim="somewhere", file="main.go")
    (h1, h2), _ = from_threats([exact, vague], [a1, a2])
    assert h1.anchor_id == "a_sql2"
    assert h2.anchor_id == "" and h2.symbol == ""  # two candidates: never guess; stays ungrounded → gate drops it
    (h3,), _ = from_threats([vague], [a1])
    assert h3.anchor_id == "a_sql"  # single candidate: unambiguous


def test_reconcile_dedups_and_orders():
    q = reconcile(from_anchors([SQL, IDOR]), [], set())
    assert [h.anchor_id for h in q] == ["a_sql", "a_idor"]  # severity-first
    new = [Hypothesis(kind="sink", cwe="CWE-89", claim="again", anchor_id="a_sql", priority=99),
           Hypothesis(kind="sink", cwe="CWE-78", claim="new", symbol="ping", priority=70),
           Hypothesis(kind="sink", claim="ungrounded")]
    q2 = reconcile(new, q, {"a_idor"})
    assert [key(h) for h in q2] == ["a_sql", "ping|CWE-78"]  # done dropped, higher priority replaced, ungrounded key skipped
    assert q2[0].claim == "again"
    assert core.ground_hypothesis(q2[1], lambda i: False, lambda s: False)  # gate, not reconcile, drops it later


def test_coverage_baselines_uncovered_entry_points():
    eps = [Candidate(kind="entry", symbol="searchHandler", file="main.go", line=10),
           Candidate(kind="entry", symbol="pingHandler", file="ping.go", line=5),
           Candidate(kind="entry", symbol="adminHandler", file="admin.go", line=7),
           Candidate(kind="entry", symbol="", file="x.go", line=1)]
    queue = [Hypothesis(kind="sink", cwe="CWE-89", claim="x", anchor_id="a_sql", reads=["main.go"])]
    out, minted = coverage(eps, queue, done={"pingHandler|CWE-78"})
    assert [h.symbol for h in out] == ["adminHandler", ""] and len(minted) == 1  # main.go read, ping done, x.go minted
    assert out[0].kind == "entry" and out[0].priority == 10 and out[0].reads == ["admin.go"] and "adminHandler" in out[0].claim
    assert core.ground_hypothesis(out[0], lambda i: False, lambda s: s == "adminHandler") is None  # gate accepts a real symbol


def test_adversarial_sweep_is_deterministic_fraction():
    cands = [Candidate(kind="entry", symbol=f"h{i}", file=f"f{i}.go", line=i) for i in range(8)]
    a, b = adversarial_sweep(cands, 0.25, seed=1), adversarial_sweep(cands, 0.25, seed=1)
    assert len(a) == 2 and [h.symbol for h in a] == [h.symbol for h in b]  # ceil(8*0.25), same seed → same pick
    assert all(h.priority == 5 and h.kind == "entry" and "Adversarial sweep" in h.claim for h in a)
    assert adversarial_sweep(cands, 0) == [] and adversarial_sweep([], 0.5) == []
    assert len(adversarial_sweep(cands, 1.0)) == 8


def test_coverage_mints_anchor_for_symbol_less_entry():
    from scanner.app.reconcile import coverage
    from scanner.core import Candidate
    eps = [Candidate(kind="entry", file="s.ts", line=1, symbol="", route=["GET /x"]),
           Candidate(kind="entry", file="h.go", line=9, symbol="named")]
    hyps, minted = coverage(eps, [], set())
    assert len(minted) == 1 and (minted[0].tool, minted[0].file, minted[0].line, minted[0].cwe) == ("entrypoint", "s.ts", 1, "")
    inline = next(h for h in hyps if h.anchor_id)
    assert inline.anchor_id == minted[0].id and inline.kind == "entry" and "GET /x" in inline.claim
    assert next(h for h in hyps if h.symbol == "named").anchor_id == ""


def test_coverage_examines_every_route_of_a_file_with_an_anchor():
    from scanner.app.reconcile import coverage
    from scanner.core import Candidate
    anchors = [Anchor(id="a_s", tool="semgrep", cwe="CWE-89", severity="high", file="server.js", line=13)]
    eps = [Candidate(kind="entry", file="server.js", line=13, symbol="search"),
           Candidate(kind="entry", file="server.js", line=20, route=["GET /ping"]),
           Candidate(kind="entry", file="server.js", line=30, route=["GET /file"])]
    hyps, minted = coverage(eps, reconcile(from_anchors(anchors), [], set()), set())
    assert [h.reads for h in hyps] == [["server.js"], ["server.js"]] and len(minted) == 2  # inline routes still examined
    assert {a.line for a in minted} == {20, 30}


def test_from_anchors_and_threats_carry_owasp_ids():
    (h,) = from_anchors([SQL])
    assert h.wstg_id == "WSTG-INJT-05" and h.asvs_id == "V1.2.4"
    t = Threat(cwe="CWE-639", claim="idor", symbol="getOrder", wstg_id="WSTG-ATHZ-04", priority=80)
    (ht,), (a,) = from_threats([t], [], locate=lambda s: ("main.go", 31))
    assert ht.wstg_id == "WSTG-ATHZ-04" and a.rule_id == "WSTG-ATHZ-04"
    (hu,) = from_anchors([Anchor(id="x", tool="gosec", rule_id="G104", cwe="CWE-703", severity="low", file="f.go", line=1)])
    assert hu.wstg_id == "" and hu.asvs_id == "V16.5.3"


# --- card 39: grounding is a property of the code, not of the prompt --------------------------------

def _has(sym):
    return sym in {"searchHandler", "pingHandler", "getOrder"}


def test_ground_artifacts_drops_fabrications():
    from scanner.app.reconcile import ground_artifacts
    am = {"entities": [{"name": "Server", "grounding_symbol": "Server"}, {"name": "H", "grounding_symbol": "searchHandler"}],
          "vuln_classes": [{"cwe": "CWE-89", "wstg_id": "WSTG-174"}, {"cwe": "CWE-999", "wstg_id": "WSTG-999"}], "notes": []}
    dm = {"entities": [], "roles": [], "rules": [{"id": "r1", "statement": "Order visible to owner", "entity": "Order", "symbol": "Server.login"},
                                                 {"id": "r2", "statement": "getOrder must check owner", "entity": "Order", "symbol": "getOrder"}], "gaps": [], "notes": []}
    tm = {"intent": "production", "threats": [{"cwe": "CWE-89", "claim": "sqli", "symbol": "searchHandler", "wstg_id": "WSTG-174"},
                                             {"cwe": "CWE-79", "claim": "ghost", "symbol": "nowhere"}], "notes": []}
    am2, dm2, tm2, notes = ground_artifacts(am, dm, tm, _has, {"WSTG-INJT-05"})
    assert [e["name"] for e in am2["entities"]] == ["H"] and any("ungrounded entity Server" in n for n in am2["notes"])
    assert am2["vuln_classes"][0]["wstg_id"] == "WSTG-INJT-05" and am2["vuln_classes"][1]["wstg_id"] == ""  # fabricated → owasp map / cleared
    assert ground_artifacts({"vuln_classes": [{"cwe": "CWE-89"}]}, None, None, _has, {"WSTG-INJT-05"})[0] == {"vuln_classes": [{"cwe": "CWE-89"}]}  # shape-preserving
    assert [r["id"] for r in dm2["rules"]] == ["r2"] and any("r1" in g and "Server.login" in g for g in dm2["gaps"])
    assert [t["symbol"] for t in tm2["threats"]] == ["searchHandler"] and tm2["threats"][0]["wstg_id"] == "WSTG-INJT-05"
    assert any("ghost" in n or "nowhere" in n for n in tm2["notes"]) and len(notes) >= 4


def test_ground_artifacts_tolerates_missing_artifacts():
    from scanner.app.reconcile import ground_artifacts
    assert ground_artifacts(None, None, None, _has, set()) == (None, None, None, [])


def test_from_threats_boosts_critical_entities():
    t = Threat(cwe="CWE-89", claim="x", symbol="searchHandler", priority=50)
    (plain,), _ = from_threats([t], [], locate=lambda s: ("main.go", 20))
    (boosted,), _ = from_threats([t], [], locate=lambda s: ("main.go", 20), criticality={"searchHandler": "CRITICAL"})
    assert boosted.priority == plain.priority + 10


def test_threat_without_claim_still_becomes_a_hypothesis():
    """A weak model may emit {cwe, symbol} only; the gate requires a claim, so the Reconciler supplies one."""
    (h,), _ = from_threats([Threat(cwe="CWE-78", symbol="pingHandler")], [], locate=lambda s: ("main.go", 9))
    assert h.claim and "CWE-78" in h.claim and "pingHandler" in h.claim


# --- direct findings lane (card 42) -----------------------------------------------------------------------
GL = Anchor(id="a_gl", tool="gitleaks", rule_id="generic-api-key", cwe="CWE-798", severity="high", file="config.js",
            line=6, snippet='zapApiKey: "AKIAIOSFODNN7EXAMPLE1234567890"')
SEM_HI = Anchor(id="a_sem", tool="semgrep", rule_id="js.eval", cwe="CWE-95", severity="high", file="a.js", line=3,
                message="eval on user input", snippet="eval(x)")


def test_split_direct_keeps_code_anchors_for_the_llm():
    direct, inv = split_direct([SQL, OSV, IDOR, GL, SEM_HI])
    assert [a.id for a in direct] == ["a_osv", "a_gl", "a_sem"]
    assert [a.id for a in inv] == ["a_sql", "a_idor"]  # semgrep medium (warning) still gets investigated


def test_direct_finding_osv_uses_enrichment_and_reachability():
    e = {"package": "lodash", "version": "4.13.1", "ids": ["GHSA-x"], "aliases": ["CVE-2020-1"], "cvss": 9.8,
         "epss": 0.5, "kev": True, "fixed": ["4.17.21"], "cwes": ["CWE-1321"]}
    f = direct_finding(OSV, e, imported_by=3)
    assert (f.status, f.confidence, f.source, f.anchor_id, f.severity, f.cwe) == \
        (core.CONFIRMED, 1.0, "direct", "a_osv", "critical", "CWE-1321")
    assert f.file == "go.mod" and f.line == 1 and f.evidence[0] == "go.mod:1"
    assert "knowledge:GHSA-x" in f.evidence and "knowledge:CVE-2020-1" in f.evidence
    joined = " | ".join(f.evidence)
    assert "CVSS 9.8" in joined and "EPSS 0.50" in joined and "KEV" in joined and "fixed: 4.17.21" in joined
    assert "imported by 3 files" in joined


def test_direct_finding_without_enrichment_keeps_anchor_severity():
    f = direct_finding(OSV)
    assert f.severity == "high" and f.evidence == ["go.mod:1", "knowledge:GHSA-x"] and f.cwe == ""
    assert "imported by" not in " ".join(direct_finding(OSV, imported_by=None).evidence)
    assert "not imported by any source file" in " ".join(direct_finding(OSV, imported_by=0).evidence)


def test_direct_finding_redacts_secrets():
    f = direct_finding(GL)
    assert f.cwe == "CWE-798" and f.source == "direct" and f.evidence[0].startswith("config.js:6: ")
    assert "AKIAIOSFODNN7EXAMPLE1234567890" not in " ".join([f.title, *f.evidence])


def test_direct_finding_semgrep_error_level():
    f = direct_finding(SEM_HI)
    assert (f.title, f.cwe, f.evidence, f.severity) == ("eval on user input", "CWE-95", ["a.js:3: eval(x)"], "high")


def test_split_direct_caps_each_tool_by_severity():
    from scanner.app.reconcile import split_direct
    ls = [Anchor(id=f"g{i}", tool="gitleaks", rule_id="k", cwe="CWE-798", severity="high", file="a", line=i)
          for i in range(5)]
    sg = [Anchor(id=f"s{i}", tool="semgrep", rule_id="r", cwe="CWE-89", severity="critical" if i == 4 else "high",
                 file="b", line=i) for i in range(5)]
    direct, rest = split_direct([*ls, *sg, Anchor(id="m", tool="semgrep", rule_id="r", cwe="CWE-79", severity="medium", file="c", line=1)], max_per_tool=2)
    assert [a.id for a in direct] == ["g0", "g1", "s0", "s4"] and [a.id for a in rest] == ["m"]  # input order kept
