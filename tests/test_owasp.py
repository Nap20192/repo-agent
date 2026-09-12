from scanner.adapter.owasp import consult, consult_owasp


def test_consult_owasp():
    g = consult_owasp("CWE-89")
    assert (g["ref"], g["top10"]) == ("owasp:WSTG-INJT-05", "A03:2021") and "SQL_Injection" in g["cheat_sheet"]
    assert consult_owasp(wstg_id="WSTG-ATHZ-04")["cwe"] == "CWE-639"
    assert consult_owasp(text="command injection")["wstg_id"] == "WSTG-INJT-12"
    assert consult_owasp("CWE-1")["status"] == "error"
    assert consult_owasp(text="testing")["status"] == "error"  # ambiguous free text is a miss, not a guess


def test_consult_returns_top10_both_editions_asvs_and_remediation():
    g = consult("CWE-89")
    assert (g["top10_2021"], g["top10_2025"]) == ("A03:2021", "A05:2025")
    assert (g["asvs_id"], g["asvs_level"]) == ("V1.2.4", 1)
    assert g["remediation"] and g["remediation_url"].startswith("https://cheatsheetseries.owasp.org/")
    idor = consult("CWE-639")
    assert idor["asvs_id"] == "V8.2.2" and idor["top10_2025"] == "A01:2025" and idor["wstg_id"] == "WSTG-ATHZ-04"


def test_consult_knows_the_cwes_our_scanners_emit():
    prng = consult("CWE-338")
    assert prng["wstg_id"] == "WSTG-CRYP-04" and prng["top10_2021"] == "A02:2021" and prng["top10_2025"] == "A04:2025"
    cookie = consult("CWE-614")
    assert cookie["wstg_id"] == "WSTG-SESS-02" and cookie["asvs_id"] == "V3.3.1"
    assert consult("CWE-611")["top10_2021"] == "A05:2021"  # XXE is misconfiguration, not injection
    assert consult("CWE-88")["wstg_id"] == "WSTG-INJT-19"
    # hygiene classes without a WSTG test still get a category, a remediation and a citable ref
    unhandled = consult("CWE-703")
    assert unhandled["wstg_id"] == "" and unhandled["top10_2025"] == "A10:2025" and unhandled["ref"] == "owasp:A10:2025"
    assert consult("CWE-798")["wstg_id"] == "WSTG-ATHN-02"


def test_ref_never_empty():
    assert consult_owasp("CWE-190")["ref"] != "owasp:"
