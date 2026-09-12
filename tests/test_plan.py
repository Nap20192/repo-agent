"""Card 45 wave 1 (agent C): the deterministic plan/fold/route/dedupe/calibrate functions the graph nodes wrap."""

from scanner.app import plan
from scanner.core import Finding, Hypothesis


def _h(id_, file, kind="entry", cwe="CWE-79", claim="baseline"):
    return Hypothesis(id=id_, kind=kind, cwe=cwe, reads=[file], claim=claim, anchor_id=f"a_{id_}")


# --- batches -----------------------------------------------------------------------------------------------

def test_batch_files_is_stable_deduped_and_sized():
    files = ["b.js", "a.js", "b.js", "c.js", "d.js", "e.js"]
    assert plan.batch_files(files, 2) == [["a.js", "b.js"], ["c.js", "d.js"], ["e.js"]]
    assert plan.batch_files([], 3) == [] and plan.batch_files(["x"], 0) == [["x"]]


def test_plan_state_carries_queue_done_and_batches():
    q = [_h("h1", "a.js"), _h("h2", "b.js", kind="sink", cwe="CWE-89")]
    st = plan.plan_state(q, {"k1"}, ["b.js", "a.js"], 10)
    assert [h.id for h in st["queue"]] == ["h1", "h2"] and st["done"] == ["k1"] and st["batches"] == [["a.js", "b.js"]]


# --- fold_triage ---------------------------------------------------------------------------------------------

def test_fold_triage_flagged_unflagged_and_missing():
    q = [_h("h1", "a.js"), _h("h2", "b.js"), _h("h3", "c.js"), _h("h4", "d.js", kind="sink", cwe="CWE-89")]
    outs = [{"classifications": [
        {"file": "a.js", "flagged": True, "classes": ["CWE-943"], "why": "raw $where"},
        {"file": "b.js", "flagged": False, "classes": [], "why": "static page"},
        {"file": "b.js", "flagged": True, "classes": ["CWE-79"], "why": "dup ignored"},   # second for b.js: not usable
        {"file": "zz.js", "flagged": True, "classes": [], "why": "not planned"},          # not assigned: not usable
        {"file": "c.js", "flagged": "yes", "classes": [], "why": "malformed"},            # flagged not a bool: not usable
    ]}]
    queue, rejected, cov = plan.fold_triage(outs, ["a.js", "b.js", "c.js"], q)
    assert [h.id for h in queue] == ["h1", "h3", "h4"]              # b.js baseline left; sink h4 untouched; c.js stays (fail open)
    assert queue[0].cwe == "CWE-943" and queue[0].claim.endswith("Triage: raw $where")
    assert queue[1].claim == "baseline"                             # missing file: claim untouched
    assert rejected == [{"hypothesis_id": "h2", "verdict": "rejected", "notes": "triage: static page", "specialist": "triage"}]
    assert cov == {"considered": 3, "classified": 2, "missing": ["c.js"], "flagged": ["a.js"], "coverage": "reduced"}


def test_fold_triage_complete_coverage_and_no_batches():
    q = [_h("h1", "a.js")]
    queue, rejected, cov = plan.fold_triage([{"classifications": [{"file": "a.js", "flagged": True, "classes": [], "why": ""}]}], ["a.js"], q)
    assert [h.id for h in queue] == ["h1"] and rejected == [] and cov["coverage"] == "complete" and cov["missing"] == []
    queue, rejected, cov = plan.fold_triage([], ["a.js"], q)   # sweep never ran: everything missing, queue intact
    assert [h.id for h in queue] == ["h1"] and cov == {"considered": 1, "classified": 0, "missing": ["a.js"], "flagged": [], "coverage": "reduced"}


def test_fold_triage_ignores_non_cwe_classes_and_bad_batches():
    q = [_h("h1", "a.js")]
    outs = ["garbage", {"classifications": "nope"}, {"classifications": [{"file": "a.js", "flagged": True, "classes": ["xss", "CWE-79"], "why": ""}]}]
    queue, _, cov = plan.fold_triage(outs, ["a.js"], q)
    assert queue[0].cwe == "CWE-79" and cov["classified"] == 1


# --- routes --------------------------------------------------------------------------------------------------

def test_routes():
    assert plan.route_plan([]) == "empty" and plan.route_plan([_h("h1", "a.js")]) == "default"
    assert plan.route_research(0, False) == "none" and plan.route_research(3, True) == "budget" and plan.route_research(3, False) == "default"
    assert plan.route_survivors(0) == "none" and plan.route_survivors(1) == "default"
    assert plan.route_intent(None) == "default" and plan.route_intent({"intent": "production"}) == "default"
    assert plan.route_intent({"intent": "sample"}) == "sample" and plan.route_intent({"intent": "SAMPLE_OR_TEST_ONLY"}) == "sample"


# --- dedupe --------------------------------------------------------------------------------------------------

def _f(id_, file, line, title, cwe="CWE-95", conf=0.9, anchor="a"):
    return Finding(id=id_, anchor_id=anchor, cwe=cwe, file=file, line=line, title=title, status="confirmed", confidence=conf)


def test_dedupe_pairs_near_same_class_similar_titles_keeps_the_stronger():
    fs = [_f("f_1", "c.js", 32, "Code injection via eval() on preTax", conf=0.8, anchor="a1"),
          _f("f_2", "c.js", 34, "Code injection via eval() on afterTax", conf=0.95, anchor="a2"),   # near + similar → dup of the stronger
          _f("f_3", "c.js", 90, "Code injection via eval() on roth", anchor="a3"),                 # far → separate
          _f("f_4", "c.js", 33, "Open redirect via req.query.url", cwe="CWE-601", anchor="a4"),    # other class
          _f("f_5", "c.js", 35, "Missing rate limit on login", anchor="a5")]                       # near, same class, unrelated title
    assert plan.dedupe(fs) == [("f_2", "f_1")]
    assert plan.dedupe([]) == [] and plan.dedupe(fs[:1]) == []


def test_dedupe_skips_direct_and_non_confirmed():
    a = _f("f_1", "package-lock.json", 1, "Vulnerable dependency tar@4.4.8", cwe="CWE-22", anchor="a1")
    b = _f("f_2", "package-lock.json", 1, "Vulnerable dependency tar@4.4.9", cwe="CWE-22", anchor="a2")
    a.source = b.source = "direct"
    assert plan.dedupe([a, b]) == []
    c = _f("f_3", "x.js", 1, "eval one", anchor="a3"); d = _f("f_4", "x.js", 2, "eval two", anchor="a4"); d.status = "rejected"
    assert plan.dedupe([c, d]) == []


# --- calibrate -----------------------------------------------------------------------------------------------

def test_calibrate_all_matches_core_calibrate_per_finding():
    from scanner.core import calibrate, exposure_for
    fs = [_f("f_1", "app.js", 10, "eval", cwe="CWE-95"), _f("f_2", "app.js", 20, "sqli", cwe="CWE-89", conf=0.5)]
    am = {"entities": [{"name": "web", "exposure": "public", "files": ["app.js"]}]}
    out = plan.calibrate_all(fs, "production", am, None)
    assert set(out) == {"f_1", "f_2"}
    for f in fs:
        exp, rules = exposure_for(f, am)
        assert out[f.id] == calibrate(f, "production", exposure=exp, knowledge={}, extra_rules=rules)
