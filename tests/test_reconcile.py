from scanner import core
from scanner.app.reconcile import (
    adversarial_sweep,
    coverage,
    from_anchors,
    from_threats,
    key,
    reconcile,
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
    out = coverage(eps, queue, done={"pingHandler|CWE-78"})
    assert [h.symbol for h in out] == ["adminHandler"]  # main.go read by a queued item, ping done, no-symbol skipped
    assert out[0].kind == "entry" and out[0].priority == 10 and out[0].reads == ["admin.go"] and "adminHandler" in out[0].claim
    assert core.ground_hypothesis(out[0], lambda i: False, lambda s: s == "adminHandler") is None  # gate accepts a real symbol


def test_adversarial_sweep_is_deterministic_fraction():
    cands = [Candidate(kind="entry", symbol=f"h{i}", file=f"f{i}.go", line=i) for i in range(8)]
    a, b = adversarial_sweep(cands, 0.25, seed=1), adversarial_sweep(cands, 0.25, seed=1)
    assert len(a) == 2 and [h.symbol for h in a] == [h.symbol for h in b]  # ceil(8*0.25), same seed → same pick
    assert all(h.priority == 5 and h.kind == "entry" and "Adversarial sweep" in h.claim for h in a)
    assert adversarial_sweep(cands, 0) == [] and adversarial_sweep([], 0.5) == []
    assert len(adversarial_sweep(cands, 1.0)) == 8
