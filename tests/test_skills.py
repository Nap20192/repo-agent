from scanner.adapter.skills import SKILLS, list_skills, load_skill, skill_for


def test_corpus_and_lookup():
    assert len(SKILLS) >= 30 and all(d for _, (d, _) in SKILLS.items())  # every skill has name + description
    body = load_skill("sql-injection")["body"]
    assert "concatenation" in body.lower() and "## False Positives" in body and "Testing Methodology" not in body  # DAST stripped
    assert load_skill("nope")["status"] == "error"
    assert skill_for("CWE-89", "sink") == "sql-injection"
    assert skill_for("CWE-639", "authz") == "authz-idor"
    assert skill_for("", "dependency") == "dependency-advisory"
    assert skill_for("CWE-862", "authz") == "broken-function-level-authorization"
    names79 = [s["name"] for s in list_skills(cwe="CWE-79")["skills"]]
    assert "xss" in names79 and "wstg-injt-01-reflected-xss" in names79 and not any(n.startswith("control-") for n in names79)
    assert len(list_skills()["skills"]) == len(SKILLS)


def test_wstg_and_control_skill_corpus():
    """Card 40: WSTG verdict skills + control skills, parsed frontmatter, routed by skills_for()."""
    import json
    from pathlib import Path

    from scanner.adapter.skills import META, list_skills, skills_for

    wstg = [n for n in SKILLS if n.startswith("wstg-")]
    ctrl = [n for n in SKILLS if n.startswith("control-")]
    assert len(wstg) >= 25 and len(ctrl) >= 12
    for n in wstg:
        m = META[n]
        assert m["cwes"] and m["wstg"].startswith("WSTG-") and m["top10"].endswith(":2025"), n
        body = load_skill(n)["body"]
        assert "## Evidence you must find" in body and "## Counter-facts that reject" in body and "## Not enough to confirm" in body, n
    for n in ctrl:
        assert META[n]["role"] == "critic" and META[n]["cwes"], n
        body = load_skill(n)["body"]
        assert "## Dominates when" in body and "## Not a control" in body, n
    checklist = Path.home() / "tmp/repos/owasp-wstg/checklists/checklist.json"
    if checklist.exists():
        ids = set()
        def walk(o):
            if isinstance(o, dict):
                if str(o.get("id", "")).startswith("WSTG-"):
                    ids.add(o["id"])
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for x in o:
                    walk(x)
        walk(json.loads(checklist.read_text()))
        assert all(META[n]["wstg"] in ids for n in wstg), [n for n in wstg if META[n]["wstg"] not in ids]
    inv = skills_for("CWE-89", "sink")
    assert inv[0] == "wstg-injt-05-sqli" and "sql-injection" in inv and inv[-1] in ("verifier-proof", "source-aware-discovery")
    crit = skills_for("CWE-89", "sink", "critique")
    assert crit[0] == "control-parameterization" and "counterevidence" in crit
    assert skills_for("CWE-639", "authz")[0] == "wstg-athz-04-idor" and skills_for("CWE-639", "authz", "critique")[0] == "control-authz-ownership"
    assert skills_for("", "dependency") == ["dependency-advisory"]
    assert next(s["name"] for s in list_skills(cwe="CWE-352", role="critique")["skills"]) == "control-csrf"
    assert {s["name"] for s in list_skills(cwe="CWE-352")["skills"]} >= {"wstg-sess-05-csrf", "csrf"}
    assert len(load_skill.__doc__) < 1600
