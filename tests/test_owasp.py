from scanner.adapter.owasp import consult_owasp


def test_consult_owasp():
    g = consult_owasp("CWE-89")
    assert (g["ref"], g["top10"]) == ("owasp:WSTG-INJT-05", "A03:2021") and "SQL_Injection" in g["cheat_sheet"]
    assert consult_owasp(wstg_id="WSTG-ATHZ-04")["cwe"] == "CWE-639"
    assert consult_owasp(text="command injection")["wstg_id"] == "WSTG-INJT-12"
    assert consult_owasp("CWE-1")["status"] == "error"
    assert consult_owasp(text="testing")["status"] == "error"  # ambiguous free text is a miss, not a guess
