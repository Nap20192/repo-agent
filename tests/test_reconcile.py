from scanner import core
from scanner.app.graph.reconcile import (
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
    # ping done; searchHandler is NOT covered by an anchor merely living in main.go (symbol rule); every
    # baseline gets an entrypoint anchor (NodeGoat run 18: symbol-only baselines had nothing to report from)
    assert [h.symbol for h in out] == ["searchHandler", "adminHandler", ""] and len(minted) == 3
    assert all(h.anchor_id and h.anchor_id == a.id for h, a in zip(out, minted, strict=True))
    assert out[1].kind == "entry" and out[1].priority == 10 and out[1].reads == ["admin.go"] and "adminHandler" in out[1].claim
    assert core.ground_hypothesis(out[1], lambda i: i == out[1].anchor_id, lambda s: False) is None  # grounded on its own anchor



def test_coverage_mints_anchor_for_symbol_less_entry():
    from scanner.app.graph.reconcile import coverage
    from scanner.core import Candidate
    eps = [Candidate(kind="entry", file="s.ts", line=1, symbol="", route=["GET /x"]),
           Candidate(kind="entry", file="h.go", line=9, symbol="named")]
    hyps, minted = coverage(eps, [], set())
    assert len(minted) == 2 and (minted[0].tool, minted[0].file, minted[0].line, minted[0].cwe) == ("entrypoint", "s.ts", 1, "")
    inline = next(h for h in hyps if h.anchor_id)
    assert inline.anchor_id == minted[0].id and inline.kind == "entry" and "GET /x" in inline.claim
    assert next(h for h in hyps if h.symbol == "named").anchor_id == minted[1].id  # symbol handlers are anchored too (card 44)


def test_coverage_examines_every_route_of_a_file_with_an_anchor():
    from scanner.app.graph.reconcile import coverage
    from scanner.core import Candidate
    anchors = [Anchor(id="a_s", tool="semgrep", cwe="CWE-89", severity="high", file="server.js", line=13)]
    eps = [Candidate(kind="entry", file="server.js", line=13, symbol="search"),
           Candidate(kind="entry", file="server.js", line=20, route=["GET /ping"]),
           Candidate(kind="entry", file="server.js", line=30, route=["GET /file"])]
    hyps, minted = coverage(eps, reconcile(from_anchors(anchors), [], set()), set())
    assert [h.reads for h in hyps] == [["server.js"]] * 3 and len(minted) == 3  # the handler and both inline routes examined
    assert {a.line for a in minted} == {13, 20, 30}


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
    from scanner.app.graph.reconcile import ground_artifacts
    am = {"entities": [{"name": "Server", "grounding_symbol": "Server"}, {"name": "H", "grounding_symbol": "searchHandler"}],
          "vuln_classes": [{"cwe": "CWE-89", "wstg_id": "WSTG-174"}, {"cwe": "CWE-999", "wstg_id": "WSTG-999"}], "notes": []}
    dm = {"entities": [], "roles": [], "rules": [{"id": "r1", "statement": "Order visible to owner", "entity": "Order", "symbol": "Server.login"},
                                                 {"id": "r2", "statement": "getOrder must check owner", "entity": "Order", "symbol": "getOrder"}], "gaps": [], "notes": []}
    tm = {"threats": [{"cwe": "CWE-89", "claim": "sqli", "symbol": "searchHandler", "wstg_id": "WSTG-174"},
                                             {"cwe": "CWE-79", "claim": "ghost", "symbol": "nowhere"}], "notes": []}
    am2, dm2, tm2, notes = ground_artifacts(am, dm, tm, _has, {"WSTG-INJT-05"})
    assert [e["name"] for e in am2["entities"]] == ["H"] and any("ungrounded entity Server" in n for n in am2["notes"])
    assert am2["vuln_classes"][0]["wstg_id"] == "WSTG-INJT-05" and am2["vuln_classes"][1]["wstg_id"] == ""  # fabricated → owasp map / cleared
    assert ground_artifacts({"vuln_classes": [{"cwe": "CWE-89"}]}, None, None, _has, {"WSTG-INJT-05"})[0] == {"vuln_classes": [{"cwe": "CWE-89"}]}  # shape-preserving
    assert [r["id"] for r in dm2["rules"]] == ["r2"] and any("r1" in g and "Server.login" in g for g in dm2["gaps"])
    assert [t["symbol"] for t in tm2["threats"]] == ["searchHandler"] and tm2["threats"][0]["wstg_id"] == "WSTG-INJT-05"
    assert any("ghost" in n or "nowhere" in n for n in tm2["notes"]) and len(notes) >= 4


def test_ground_artifacts_tolerates_missing_artifacts():
    from scanner.app.graph.reconcile import ground_artifacts
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


def test_direct_finding_osv_cites_the_advisory_and_reachability():
    f = direct_finding(OSV, imported_by=3)
    assert (f.status, f.confidence, f.source, f.anchor_id, f.severity) == (core.CONFIRMED, 1.0, "direct", "a_osv", "high")
    assert f.file == "go.mod" and f.line == 1 and f.evidence == ["go.mod:1", "knowledge:GHSA-x", "imported by 3 files"]
    assert direct_finding(OSV).evidence == ["go.mod:1", "knowledge:GHSA-x"]
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
    from scanner.app.graph.reconcile import split_direct
    ls = [Anchor(id=f"g{i}", tool="gitleaks", rule_id="k", cwe="CWE-798", severity="high", file="a", line=i)
          for i in range(5)]
    sg = [Anchor(id=f"s{i}", tool="semgrep", rule_id="r", cwe="CWE-89", severity="critical" if i == 4 else "high",
                 file="b", line=i) for i in range(5)]
    direct, rest = split_direct([*ls, *sg, Anchor(id="m", tool="semgrep", rule_id="r", cwe="CWE-79", severity="medium", file="c", line=1)], max_per_tool=2)
    assert [a.id for a in direct] == ["g0", "g1", "s0", "s4"] and [a.id for a in rest] == ["m"]  # input order kept


def test_coverage_examines_every_handler_of_a_file_with_an_anchor():
    """NodeGoat run 17: one open-redirect anchor in routes/index.js must not mark its 20 handlers as covered."""
    from scanner.app.graph.reconcile import coverage
    from scanner.core import Candidate
    anchors = [Anchor(id="a_r", tool="semgrep", cwe="CWE-601", severity="medium", file="index.js", line=72)]
    eps = [Candidate(kind="entry", file="index.js", line=34, symbol="handleLoginRequest", route=["POST /login"]),
           Candidate(kind="entry", file="index.js", line=48, symbol="handleProfileUpdate", route=["POST /profile"])]
    hyps, _ = coverage(eps, reconcile(from_anchors(anchors), [], set()), set())
    assert [h.symbol for h in hyps] == ["handleLoginRequest", "handleProfileUpdate"]


def test_direct_osv_title_keeps_advisory_ids_and_gitleaks_is_redacted():
    from scanner.app.graph.reconcile import direct_finding
    osv = Anchor(id="o", tool="osv", rule_id="GHSA-23hp-3jrh-7fpw", rule_ids=["GHSA-23hp-3jrh-7fpw"], severity="high",
                 file="package-lock.json", line=1, snippet="tar 4.4.8", message="tar@4.4.8: 1 advisories (GHSA-23hp-3jrh-7fpw)")
    assert "GHSA-23hp-3jrh-7fpw" in direct_finding(osv).title
    leak = Anchor(id="g", tool="gitleaks", rule_id="generic-api-key", cwe="CWE-798", severity="high", file="cfg.js", line=6,
                  snippet='apiKey: "v9dnABCDEFGHIJKLMNOPQRSTUV"')
    f = direct_finding(leak)
    assert "v9dnABCDEFGHIJKLMNOPQRSTUV" not in f.evidence[0] and "v9dn" in f.evidence[0]


def test_bare_quote_strips_location_prefix_and_html_entities():
    from scanner.core import bare_quote
    assert bare_quote("app/routes/c.js:33:        const afterTax = eval(req.body.afterTax);") == "const afterTax = eval(req.body.afterTax);"
    assert bare_quote("    app.get(\"/learn\", isLoggedIn, (req, res) =&gt; {") == 'app.get("/learn", isLoggedIn, (req, res) => {'
    assert bare_quote("owasp:WSTG-INJT-11") == "owasp:WSTG-INJT-11"


# --- card 44: planner ---------------------------------------------------------------------------------------

def test_hunt_classes_by_route_file_and_symbol():
    from scanner.app.graph.reconcile import DEFAULT_HUNT, hunt_classes
    assert hunt_classes("POST /login", "session.js", "handleLoginRequest")[:3] == ["CWE-287", "CWE-307", "CWE-522"]
    assert hunt_classes("POST /profile", "profile.js", "handleProfileUpdate")[:2] == ["CWE-79", "CWE-639"]
    assert hunt_classes("GET /allocations/:userId", "allocations.js", "")[:2] == ["CWE-639", "CWE-862"]
    assert hunt_classes("GET /admin", "", "")[:2] == ["CWE-862", "CWE-285"]
    assert hunt_classes("GET /search", "", "")[:2] == ["CWE-89", "CWE-943"]
    assert hunt_classes("GET /download", "", "")[0] == "CWE-22"
    assert hunt_classes("GET /learn?url=", "", "displayLearn") == ["CWE-601"]
    assert hunt_classes("", "", "renderTemplate")[:2] == ["CWE-95", "CWE-1336"]
    assert hunt_classes("", "validators.js", "")[0] == "CWE-1333"
    assert hunt_classes("GET /", "index.js", "displayWelcomePage") == list(DEFAULT_HUNT)


def test_baselines_name_classes_by_route():
    eps = [Candidate(kind="entry", file="s.js", line=53, symbol="handleLoginRequest", route=["POST /login"]),
           Candidate(kind="entry", file="p.js", line=40, symbol="handleProfileUpdate", route=["POST /profile"]),
           Candidate(kind="entry", file="a.js", line=8, symbol="displayAllocations", route=["GET /allocations/:userId"]),
           Candidate(kind="entry", file="i.js", line=30, symbol="displayWelcomePage", route=["GET /"])]
    hyps, _ = coverage(eps, [], set())
    login = next(h for h in hyps if h.symbol == "handleLoginRequest")
    assert login.cwe == "CWE-287" and "CWE-307" in login.claim and login.kind == "entry" and login.priority == 10
    assert next(h for h in hyps if h.symbol == "handleProfileUpdate").cwe == "CWE-79"
    assert next(h for h in hyps if h.symbol == "displayAllocations").cwe == "CWE-639"  # an id in the route → IDOR first



def test_coverage_one_handler_under_two_routes_is_one_baseline():
    from scanner.app.graph.reconcile import coverage
    from scanner.core import Candidate
    eps = [Candidate(kind="entry", file="routes.js", line=10, symbol="handleThing", route=["GET /a"]),
           Candidate(kind="entry", file="routes.js", line=15, symbol="handleThing", route=["POST /a"])]
    hyps, minted = coverage(eps, [], set())
    assert len(hyps) == 1 and len(minted) == 1 and hyps[0].symbol == "handleThing"
    assert hyps[0].route == ["GET /a"]  # the route reaches triage (review LOW)
