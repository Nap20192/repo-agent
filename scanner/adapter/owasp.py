"""OWASP methodology lookup by CWE: WSTG test id, Top10 2021 category, Cheat Sheet.

ponytail: curated static tables (mirrors git-agent3 internal/adapter/owasp/mapping.go); clone the
WSTG/CheatSheetSeries corpus when agents need "how to test" excerpts. A miss is an error, never a guess.
"""

from __future__ import annotations

_WSTG = {  # cwe → (WSTG id, test name)
    "CWE-89": ("WSTG-INJT-05", "Testing for SQL Injection"),
    "CWE-78": ("WSTG-INJT-12", "Testing for Command Injection"),
    "CWE-79": ("WSTG-INJT-01", "Testing for Reflected Cross Site Scripting"),
    "CWE-918": ("WSTG-INJT-19", "Testing for Server-Side Request Forgery"),
    "CWE-22": ("WSTG-ATHZ-01", "Testing Directory Traversal File Include"),
    "CWE-611": ("WSTG-INJT-07", "Testing for XML Injection"),
    "CWE-91": ("WSTG-INJT-07", "Testing for XML Injection"),
    "CWE-502": ("WSTG-INJT-23", "Testing for Insecure Deserialization"),
    "CWE-94": ("WSTG-INJT-11", "Testing for Code Injection"),
    "CWE-95": ("WSTG-INJT-11", "Testing for Code Injection"),
    "CWE-639": ("WSTG-ATHZ-04", "Testing for Insecure Direct Object References"),
    "CWE-284": ("WSTG-ATHZ-02", "Testing for Bypassing Authorization Schema"),
    "CWE-285": ("WSTG-ATHZ-02", "Testing for Bypassing Authorization Schema"),
    "CWE-862": ("WSTG-ATHZ-02", "Testing for Bypassing Authorization Schema"),
    "CWE-863": ("WSTG-ATHZ-02", "Testing for Bypassing Authorization Schema"),
    "CWE-601": ("WSTG-CLNT-04", "Testing for Client-side URL Redirect"),
    "CWE-352": ("WSTG-SESS-05", "Testing for Cross Site Request Forgery"),
    "CWE-798": ("WSTG-CONF-04", "Review Old Backup and Unreferenced Files for Sensitive Information"),
}
_CHEAT = {
    "CWE-89": "SQL_Injection_Prevention_Cheat_Sheet", "CWE-78": "OS_Command_Injection_Defense_Cheat_Sheet",
    "CWE-79": "Cross_Site_Scripting_Prevention_Cheat_Sheet", "CWE-918": "Server_Side_Request_Forgery_Prevention_Cheat_Sheet",
    "CWE-611": "XML_External_Entity_Prevention_Cheat_Sheet", "CWE-502": "Deserialization_Cheat_Sheet",
    "CWE-639": "Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet", "CWE-284": "Authorization_Cheat_Sheet",
    "CWE-285": "Authorization_Cheat_Sheet", "CWE-862": "Authorization_Cheat_Sheet", "CWE-863": "Authorization_Cheat_Sheet",
    "CWE-601": "Unvalidated_Redirects_and_Forwards_Cheat_Sheet", "CWE-352": "Cross-Site_Request_Forgery_Prevention_Cheat_Sheet",
    "CWE-798": "Secrets_Management_Cheat_Sheet", "CWE-22": "File_Upload_Cheat_Sheet",
}
_TOP10 = {
    "A01:2021": ("Broken Access Control", {"CWE-22", "CWE-639", "CWE-284", "CWE-285", "CWE-862", "CWE-863", "CWE-601", "CWE-352"}),
    "A03:2021": ("Injection", {"CWE-89", "CWE-78", "CWE-79", "CWE-611", "CWE-91", "CWE-94", "CWE-95"}),
    "A07:2021": ("Identification and Authentication Failures", {"CWE-798"}),
    "A08:2021": ("Software and Data Integrity Failures", {"CWE-502"}),
    "A10:2021": ("Server-Side Request Forgery", {"CWE-918"}),
}


def consult(cwe: str = "", wstg_id: str = "", text: str = "") -> dict:
    """Guidance for a vulnerability class; {"status": "error"} when nothing matches."""
    cwe = cwe.strip().upper()
    if not cwe and wstg_id:
        cwe = next((c for c, (w, _) in _WSTG.items() if w == wstg_id.strip().upper()), "")
    if not cwe and text:
        words = [w for w in text.lower().split() if w not in ("testing", "for", "test")]
        hits = {w for c, (w, n) in _WSTG.items() if words and all(x in n.lower() for x in words)}
        if len(hits) != 1:
            return {"status": "error", "reason": f"text {text!r} matches {len(hits)} WSTG tests; give a CWE or a more specific name"}
        cwe = next(c for c, (w, _) in _WSTG.items() if w in hits)
    if cwe not in _WSTG:
        return {"status": "error", "reason": f"no OWASP guidance for {cwe or wstg_id or text!r}; do not invent a test id"}
    wid, name = _WSTG[cwe]
    top = next(((tid, tname) for tid, (tname, cwes) in _TOP10.items() if cwe in cwes), ("", ""))
    sheet = _CHEAT.get(cwe, "")
    return {
        "ref": f"owasp:{wid}", "cwe": cwe, "wstg_id": wid, "wstg_name": name,
        "top10": top[0], "top10_name": top[1],
        "cheat_sheet": f"https://cheatsheetseries.owasp.org/cheatsheets/{sheet}.html" if sheet else "",
        "reference": f"https://owasp.org/www-project-web-security-testing-guide/latest/ (search {wid})",
    }


def consult_owasp(cwe: str = "", wstg_id: str = "", text: str = "") -> dict:
    """Look up OWASP methodology for a vulnerability class by CWE (preferred), WSTG test id, or free
    text: the WSTG test (how to test), the Top 10 2021 category and the Cheat Sheet (how to prevent).
    Deterministic: a miss returns an error — do not invent test ids. Cite the result as evidence
    'owasp:<WSTG id>'."""
    return consult(cwe, wstg_id, text)
