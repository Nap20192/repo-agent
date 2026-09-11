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
    assert [s["name"] for s in list_skills(cwe="CWE-79")["skills"]] == ["xss"]
    assert len(list_skills()["skills"]) == len(SKILLS)
