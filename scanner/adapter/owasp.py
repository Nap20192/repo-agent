"""OWASP methodology lookup by CWE: WSTG test, Top 10 (2021 and 2025), ASVS 5.0 requirement, Cheat Sheet, remediation.

ponytail: curated static tables (ids, titles and URLs only — texts are CC BY-SA 4.0, see THIRD_PARTY_NOTICES.md);
clone the corpus (scripts/owasp_rnd.py) when agents need "how to test" excerpts. A miss is an error, never a guess.
Coverage = every CWE gosec / semgrep packs / gitleaks / osv-scanner emit on our samples (docs/rnd/owasp/wstg.md §2).
"""

from __future__ import annotations

_WSTG = {  # cwe → (WSTG id, test name); verified against owasp-wstg checklists/checklist.json
    "CWE-89": ("WSTG-INJT-05", "SQL Injection"),
    "CWE-943": ("WSTG-INJT-05", "SQL Injection"),  # NoSQL is INJT-05.6
    "CWE-90": ("WSTG-INJT-06", "LDAP Injection"),
    "CWE-78": ("WSTG-INJT-12", "Command Injection"),
    "CWE-77": ("WSTG-INJT-12", "Command Injection"),
    "CWE-79": ("WSTG-INJT-01", "Reflected Cross Site Scripting"),
    "CWE-80": ("WSTG-INJT-01", "Reflected Cross Site Scripting"),
    "CWE-918": ("WSTG-INJT-19", "Server-Side Request Forgery"),
    "CWE-88": ("WSTG-INJT-19", "Server-Side Request Forgery"),  # gosec G107: variable URL in http request
    "CWE-22": ("WSTG-ATHZ-01", "Directory Traversal File Include"),
    "CWE-611": ("WSTG-INJT-07", "XML Injection"),
    "CWE-91": ("WSTG-INJT-07", "XML Injection"),
    "CWE-113": ("WSTG-INJT-15", "HTTP Response Splitting"),
    "CWE-502": ("WSTG-INJT-23", "Insecure Deserialization"),
    "CWE-94": ("WSTG-INJT-11", "Code Injection"),
    "CWE-95": ("WSTG-INJT-11", "Code Injection"),
    "CWE-1336": ("WSTG-INJT-18", "Server-side Template Injection"),
    "CWE-915": ("WSTG-INJT-20", "Mass Assignment"),
    "CWE-1321": ("WSTG-INJT-22", "Prototype Pollution"),
    "CWE-20": ("WSTG-BUSL-01", "Business Logic Data Validation"),
    "CWE-639": ("WSTG-ATHZ-04", "Insecure Direct Object References"),
    "CWE-284": ("WSTG-ATHZ-02", "Bypassing Authorization Schema"),
    "CWE-285": ("WSTG-ATHZ-02", "Bypassing Authorization Schema"),
    "CWE-862": ("WSTG-ATHZ-02", "Bypassing Authorization Schema"),
    "CWE-863": ("WSTG-ATHZ-02", "Bypassing Authorization Schema"),
    "CWE-601": ("WSTG-CLNT-04", "Client-side URL Redirect"),
    "CWE-352": ("WSTG-SESS-05", "Cross Site Request Forgery"),
    "CWE-384": ("WSTG-SESS-03", "Session Fixation"),
    "CWE-522": ("WSTG-SESS-01", "Session Management Schema"),
    "CWE-614": ("WSTG-SESS-02", "Cookies Attributes"),
    "CWE-1004": ("WSTG-SESS-02", "Cookies Attributes"),
    "CWE-798": ("WSTG-ATHN-02", "Default Credentials"),  # committed credentials; key files are CONF-04 territory
    "CWE-287": ("WSTG-ATHN-04", "Bypassing Authentication Schema"),
    "CWE-295": ("WSTG-CRYP-01", "Weak Transport Layer Security"),
    "CWE-322": ("WSTG-CRYP-01", "Weak Transport Layer Security"),
    "CWE-319": ("WSTG-CRYP-03", "Sensitive Information Sent via Unencrypted Channels"),
    "CWE-310": ("WSTG-CRYP-04", "Weak Cryptographic Primitives"),
    "CWE-326": ("WSTG-CRYP-04", "Weak Cryptographic Primitives"),
    "CWE-327": ("WSTG-CRYP-04", "Weak Cryptographic Primitives"),
    "CWE-328": ("WSTG-CRYP-04", "Weak Cryptographic Primitives"),
    "CWE-338": ("WSTG-CRYP-04", "Weak Cryptographic Primitives"),
    "CWE-916": ("WSTG-CRYP-04", "Weak Cryptographic Primitives"),
    "CWE-200": ("WSTG-ERRH-01", "Improper Error Handling"),
    "CWE-209": ("WSTG-ERRH-02", "Stack Traces"),
    "CWE-276": ("WSTG-CONF-09", "File Permission"),
    "CWE-548": ("WSTG-CONF-04", "Review Old Backup and Unreferenced Files for Sensitive Information"),
    "CWE-732": ("WSTG-CONF-02", "Application Platform Configuration"),
    "CWE-693": ("WSTG-CONF-14", "Other HTTP Security Header Misconfigurations"),
    "CWE-1021": ("WSTG-CLNT-09", "Clickjacking"),
    "CWE-346": ("WSTG-CLNT-07", "Cross Origin Resource Sharing"),
    "CWE-942": ("WSTG-CLNT-07", "Cross Origin Resource Sharing"),
    "CWE-434": ("WSTG-BUSL-08", "Upload of Unexpected File Types"),
    "CWE-400": ("WSTG-BUSL-05", "Number of Times a Function Can Be Used Limits"),
    "CWE-409": ("WSTG-BUSL-05", "Number of Times a Function Can Be Used Limits"),
}
# classes our scanners emit that have no WSTG test (hygiene, memory, supply chain): still categorised below
_NO_WSTG = {"CWE-703", "CWE-676", "CWE-242", "CWE-118", "CWE-770", "CWE-1333", "CWE-1357", "CWE-353", "CWE-117", "CWE-190", "CWE-697"}

_CHEAT = {  # cwe → Cheat Sheet Series page
    "CWE-89": "SQL_Injection_Prevention_Cheat_Sheet", "CWE-943": "Injection_Prevention_Cheat_Sheet",
    "CWE-90": "LDAP_Injection_Prevention_Cheat_Sheet",
    "CWE-78": "OS_Command_Injection_Defense_Cheat_Sheet", "CWE-77": "OS_Command_Injection_Defense_Cheat_Sheet",
    "CWE-79": "Cross_Site_Scripting_Prevention_Cheat_Sheet", "CWE-80": "Cross_Site_Scripting_Prevention_Cheat_Sheet",
    "CWE-918": "Server_Side_Request_Forgery_Prevention_Cheat_Sheet", "CWE-88": "Server_Side_Request_Forgery_Prevention_Cheat_Sheet",
    "CWE-22": "Input_Validation_Cheat_Sheet", "CWE-611": "XML_External_Entity_Prevention_Cheat_Sheet",
    "CWE-91": "XML_Security_Cheat_Sheet", "CWE-502": "Deserialization_Cheat_Sheet",
    "CWE-94": "Injection_Prevention_Cheat_Sheet", "CWE-95": "Injection_Prevention_Cheat_Sheet",
    "CWE-1336": "Injection_Prevention_Cheat_Sheet", "CWE-915": "Mass_Assignment_Cheat_Sheet",
    "CWE-1321": "Prototype_Pollution_Prevention_Cheat_Sheet", "CWE-20": "Input_Validation_Cheat_Sheet",
    "CWE-639": "Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet", "CWE-284": "Authorization_Cheat_Sheet",
    "CWE-285": "Authorization_Cheat_Sheet", "CWE-862": "Authorization_Cheat_Sheet", "CWE-863": "Authorization_Cheat_Sheet",
    "CWE-601": "Unvalidated_Redirects_and_Forwards_Cheat_Sheet", "CWE-352": "Cross-Site_Request_Forgery_Prevention_Cheat_Sheet",
    "CWE-384": "Session_Management_Cheat_Sheet", "CWE-522": "Session_Management_Cheat_Sheet",
    "CWE-614": "Session_Management_Cheat_Sheet", "CWE-1004": "Session_Management_Cheat_Sheet",
    "CWE-798": "Secrets_Management_Cheat_Sheet", "CWE-287": "Authentication_Cheat_Sheet",
    "CWE-295": "Transport_Layer_Security_Cheat_Sheet", "CWE-322": "Transport_Layer_Security_Cheat_Sheet",
    "CWE-319": "Transport_Layer_Security_Cheat_Sheet", "CWE-310": "Cryptographic_Storage_Cheat_Sheet",
    "CWE-326": "Cryptographic_Storage_Cheat_Sheet", "CWE-327": "Cryptographic_Storage_Cheat_Sheet",
    "CWE-328": "Cryptographic_Storage_Cheat_Sheet", "CWE-338": "Cryptographic_Storage_Cheat_Sheet",
    "CWE-916": "Password_Storage_Cheat_Sheet", "CWE-200": "Error_Handling_Cheat_Sheet", "CWE-209": "Error_Handling_Cheat_Sheet",
    "CWE-732": "Docker_Security_Cheat_Sheet", "CWE-693": "HTTP_Headers_Cheat_Sheet", "CWE-1021": "Clickjacking_Defense_Cheat_Sheet",
    "CWE-434": "File_Upload_Cheat_Sheet", "CWE-400": "Denial_of_Service_Cheat_Sheet", "CWE-409": "Denial_of_Service_Cheat_Sheet",
    "CWE-1333": "Denial_of_Service_Cheat_Sheet", "CWE-703": "Error_Handling_Cheat_Sheet",
    "CWE-117": "Logging_Cheat_Sheet", "CWE-1357": "Vulnerable_Dependency_Management_Cheat_Sheet",
    "CWE-676": "Denial_of_Service_Cheat_Sheet",
}
_TOP10 = {  # 2021 edition; CWE lists from owasp-Top10/2021 "List of Mapped CWEs"
    "A01:2021": ("Broken Access Control", {"CWE-22", "CWE-200", "CWE-276", "CWE-284", "CWE-285", "CWE-352", "CWE-548", "CWE-601", "CWE-639", "CWE-862", "CWE-863"}),
    "A02:2021": ("Cryptographic Failures", {"CWE-310", "CWE-319", "CWE-322", "CWE-326", "CWE-327", "CWE-328", "CWE-338", "CWE-916"}),
    "A03:2021": ("Injection", {"CWE-20", "CWE-77", "CWE-78", "CWE-79", "CWE-80", "CWE-88", "CWE-89", "CWE-90", "CWE-91", "CWE-94", "CWE-95", "CWE-113", "CWE-943", "CWE-1336"}),
    "A04:2021": ("Insecure Design", {"CWE-209", "CWE-434", "CWE-522", "CWE-1021", "CWE-1321"}),
    "A05:2021": ("Security Misconfiguration", {"CWE-611", "CWE-614", "CWE-942", "CWE-1004", "CWE-693", "CWE-732", "CWE-676", "CWE-770", "CWE-1333", "CWE-703"}),
    "A06:2021": ("Vulnerable and Outdated Components", {"CWE-1035", "CWE-1104", "CWE-1357"}),
    "A07:2021": ("Identification and Authentication Failures", {"CWE-287", "CWE-295", "CWE-346", "CWE-384", "CWE-798"}),
    "A08:2021": ("Software and Data Integrity Failures", {"CWE-353", "CWE-502", "CWE-915"}),
    "A09:2021": ("Security Logging and Monitoring Failures", {"CWE-117"}),
    "A10:2021": ("Server-Side Request Forgery", {"CWE-918"}),
}
_TOP10_2025 = {  # 2025 edition; CWE lists from owasp-Top10/2025
    "A01:2025": ("Broken Access Control", {"CWE-22", "CWE-200", "CWE-276", "CWE-284", "CWE-285", "CWE-352", "CWE-548", "CWE-601", "CWE-639", "CWE-732", "CWE-862", "CWE-863", "CWE-918"}),
    "A02:2025": ("Security Misconfiguration", {"CWE-611", "CWE-614", "CWE-942", "CWE-1004"}),
    "A03:2025": ("Software Supply Chain Failures", {"CWE-1035", "CWE-1104", "CWE-1357"}),
    "A04:2025": ("Cryptographic Failures", {"CWE-319", "CWE-322", "CWE-326", "CWE-327", "CWE-328", "CWE-338", "CWE-916", "CWE-310"}),
    "A05:2025": ("Injection", {"CWE-20", "CWE-77", "CWE-78", "CWE-79", "CWE-80", "CWE-88", "CWE-89", "CWE-90", "CWE-91", "CWE-94", "CWE-95", "CWE-113", "CWE-943", "CWE-1336"}),
    "A06:2025": ("Insecure Design", {"CWE-434", "CWE-522", "CWE-676", "CWE-693", "CWE-1021", "CWE-1321", "CWE-770", "CWE-1333"}),
    "A07:2025": ("Authentication Failures", {"CWE-287", "CWE-295", "CWE-346", "CWE-384", "CWE-798"}),
    "A08:2025": ("Software or Data Integrity Failures", {"CWE-353", "CWE-502", "CWE-915"}),
    "A09:2025": ("Security Logging & Alerting Failures", {"CWE-117"}),
    "A10:2025": ("Mishandling of Exceptional Conditions", {"CWE-209", "CWE-703"}),
}
_ASVS = {  # cwe → (ASVS 5.0 requirement, level); curated (docs/rnd/owasp/asvs-top10.md), no official CWE map exists
    "CWE-89": ("V1.2.4", 1), "CWE-943": ("V1.2.4", 1), "CWE-78": ("V1.2.5", 1), "CWE-77": ("V1.2.5", 1),
    "CWE-79": ("V1.2.1", 1), "CWE-80": ("V1.2.1", 1), "CWE-95": ("V1.3.2", 1), "CWE-94": ("V1.3.7", 2),
    "CWE-1336": ("V1.3.7", 2), "CWE-90": ("V1.2.6", 2), "CWE-91": ("V1.5.1", 1), "CWE-611": ("V1.5.1", 1),
    "CWE-502": ("V1.5.2", 2), "CWE-918": ("V1.3.6", 2), "CWE-88": ("V1.3.6", 2), "CWE-113": ("V1.2.2", 2),
    "CWE-20": ("V2.2.1", 1), "CWE-22": ("V5.3.2", 1), "CWE-434": ("V5.2.2", 1),
    "CWE-639": ("V8.2.2", 1), "CWE-285": ("V8.2.1", 1), "CWE-862": ("V8.2.1", 1), "CWE-863": ("V8.2.1", 1),
    "CWE-284": ("V8.2.1", 1), "CWE-352": ("V3.5.1", 1), "CWE-601": ("V3.7.2", 2), "CWE-942": ("V3.5.2", 1),
    "CWE-346": ("V3.5.2", 1), "CWE-1021": ("V3.4.3", 2), "CWE-693": ("V3.4.1", 2),
    "CWE-614": ("V3.3.1", 1), "CWE-1004": ("V3.3.4", 2), "CWE-384": ("V7.2.1", 1), "CWE-522": ("V7.2.2", 1),
    "CWE-798": ("V13.3.1", 2), "CWE-287": ("V6.2.1", 1), "CWE-338": ("V11.5.1", 2), "CWE-310": ("V11.3.2", 1),
    "CWE-326": ("V11.3.2", 1), "CWE-327": ("V11.3.2", 1), "CWE-328": ("V11.4.1", 1), "CWE-916": ("V6.2.8", 1),
    "CWE-319": ("V12.2.1", 1), "CWE-295": ("V12.3.2", 2), "CWE-322": ("V12.3.2", 2), "CWE-732": ("V13.2.4", 2),
    "CWE-276": ("V5.3.1", 1), "CWE-548": ("V13.4.1", 2), "CWE-200": ("V16.5.1", 2), "CWE-117": ("V16.4.1", 2),
    "CWE-209": ("V16.5.1", 2), "CWE-703": ("V16.5.3", 2), "CWE-1357": ("V15.2.1", 1), "CWE-915": ("V15.3.3", 2),
    "CWE-1321": ("V15.3.6", 2), "CWE-676": ("V15.2.2", 2), "CWE-400": ("V15.2.2", 2), "CWE-409": ("V15.2.2", 2),
}
_REMEDIATION = {  # own words, one line per class family; the URL is the Cheat Sheet
    "CWE-89": "Use parameterized queries or the ORM's bound parameters; never build SQL from user input.",
    "CWE-943": "Never pass user input into query operators; validate types and use the driver's parameterized filters.",
    "CWE-90": "Escape LDAP metacharacters and build filters from an allow-list of attributes.",
    "CWE-78": "Call the program with an argv list, no shell; allow-list the arguments you pass.",
    "CWE-77": "Call the program with an argv list, no shell; allow-list the arguments you pass.",
    "CWE-79": "Encode output for its HTML/JS/URL context (or use an auto-escaping template) before rendering user data.",
    "CWE-80": "Encode output for its HTML/JS/URL context (or use an auto-escaping template) before rendering user data.",
    "CWE-918": "Resolve and allow-list the destination host, block private ranges and redirects before fetching.",
    "CWE-88": "Resolve and allow-list the destination host, block private ranges and redirects before fetching.",
    "CWE-22": "Join with a fixed base directory, canonicalize, and reject paths that leave it.",
    "CWE-611": "Disable DTDs and external entities in the XML parser.",
    "CWE-91": "Disable DTDs and external entities in the XML parser; escape user data in XML.",
    "CWE-113": "Strip CR/LF from values placed into headers, or use the framework's header API.",
    "CWE-502": "Do not deserialize untrusted data; use a format without code execution or a strict allow-list of types.",
    "CWE-94": "Never eval user-controlled strings; use a data format and a fixed dispatch table.",
    "CWE-95": "Never eval user-controlled strings; use a data format and a fixed dispatch table.",
    "CWE-1336": "Never render user input as a template; pass it as template data only.",
    "CWE-915": "Bind only an explicit allow-list of fields from the request to the model.",
    "CWE-1321": "Reject __proto__/constructor/prototype keys when merging user-controlled objects; use null-prototype maps.",
    "CWE-20": "Validate input against an allow-list of expected type, length and format at the trust boundary.",
    "CWE-639": "Load the object through the current user's scope (owner or tenant check) before returning it.",
    "CWE-284": "Enforce the permission check server-side on every entry point, deny by default.",
    "CWE-285": "Enforce the permission check server-side on every entry point, deny by default.",
    "CWE-862": "Enforce the permission check server-side on every entry point, deny by default.",
    "CWE-863": "Enforce the permission check server-side on every entry point, deny by default.",
    "CWE-601": "Redirect only to an allow-list of relative paths or trusted hosts.",
    "CWE-352": "Require a per-session anti-CSRF token or same-site/origin check on state-changing requests.",
    "CWE-384": "Issue a new session id at login and invalidate the old one.",
    "CWE-522": "Store credentials with a slow salted hash and protect session cookies with Secure/HttpOnly/SameSite.",
    "CWE-614": "Set Secure, HttpOnly and SameSite on session cookies.",
    "CWE-1004": "Set HttpOnly on session cookies.",
    "CWE-798": "Move the secret to a vault or environment, rotate it, and remove it from history.",
    "CWE-287": "Authenticate on the server for every protected entry point; never trust client-supplied identity.",
    "CWE-295": "Verify the server certificate chain and hostname; never disable verification.",
    "CWE-322": "Verify host keys against a known-hosts store instead of ignoring them.",
    "CWE-319": "Use TLS for every channel that carries credentials or session tokens.",
    "CWE-310": "Use approved algorithms (AES-GCM, SHA-256+, argon2/bcrypt) with adequate key sizes.",
    "CWE-326": "Use approved algorithms (AES-GCM, SHA-256+, argon2/bcrypt) with adequate key sizes.",
    "CWE-327": "Replace the weak cipher or mode with an approved one (AES-GCM, ChaCha20-Poly1305).",
    "CWE-328": "Replace MD5/SHA-1 with SHA-256 or better; use HMAC for integrity.",
    "CWE-338": "Use the OS CSPRNG (crypto/rand, secrets, crypto.randomBytes) for anything security-relevant.",
    "CWE-916": "Hash passwords with argon2id, scrypt or bcrypt with a per-user salt.",
    "CWE-200": "Return generic error messages to clients; log details server-side only.",
    "CWE-209": "Return generic error messages to clients; log details server-side only.",
    "CWE-276": "Create files and directories with least-privilege modes (0600/0750).",
    "CWE-548": "Disable directory listing and remove backup or unreferenced files from the web root.",
    "CWE-732": "Run containers and services with least privilege (no-new-privileges, non-root user).",
    "CWE-693": "Set the security headers (CSP, HSTS, X-Content-Type-Options, frame options) on every response.",
    "CWE-1021": "Send a frame-ancestors CSP or X-Frame-Options header.",
    "CWE-346": "Allow-list exact origins for CORS; never reflect the Origin header with credentials.",
    "CWE-942": "Allow-list exact origins for CORS; never reflect the Origin header with credentials.",
    "CWE-434": "Validate upload type and size server-side, store outside the web root under a generated name.",
    "CWE-400": "Bound the size and rate of what a request can consume (limits, timeouts, quotas).",
    "CWE-409": "Bound decompressed size and nesting when expanding archives.",
    "CWE-676": "Set read/write/idle timeouts on servers and clients.",
    "CWE-703": "Handle every error path explicitly and fail closed.",
    "CWE-117": "Encode or strip newlines and control characters from user data before logging.",
    "CWE-1333": "Avoid nested quantifiers on user input or use a linear-time regex engine with a length cap.",
    "CWE-1357": "Pin dependencies and actions to immutable versions and update on advisories.",
    "CWE-353": "Verify integrity (signature or hash) of data and artifacts before trusting them.",
    "CWE-770": "Bound the size and rate of what a request can consume (limits, timeouts, quotas).",
    "CWE-242": "Avoid unsafe memory access in Go; use bounded, typed operations.",
    "CWE-118": "Keep slice and index arithmetic within checked bounds.",
    "CWE-190": "Check integer conversions and arithmetic for overflow before use.",
    "CWE-697": "Use strict comparison and the language's constant-time compare for secrets.",
}
_SHEET_URL = "https://cheatsheetseries.owasp.org/cheatsheets/{}.html"


def known(cwe: str) -> bool:
    return cwe in _WSTG or cwe in _NO_WSTG or cwe in _ASVS or cwe in _REMEDIATION


def _category(table: dict, cwe: str) -> tuple[str, str]:
    return next(((tid, tname) for tid, (tname, cwes) in table.items() if cwe in cwes), ("", ""))


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
    if not known(cwe):
        return {"status": "error", "reason": f"no OWASP guidance for {cwe or wstg_id or text!r}; do not invent a test id"}
    wid, name = _WSTG.get(cwe, ("", ""))
    t21, t25 = _category(_TOP10, cwe), _category(_TOP10_2025, cwe)
    asvs_id, asvs_level = _ASVS.get(cwe, ("", 0))
    sheet = _CHEAT.get(cwe, "")
    url = _SHEET_URL.format(sheet) if sheet else ""
    return {
        "ref": f"owasp:{wid or t25[0] or asvs_id or cwe}", "cwe": cwe, "wstg_id": wid, "wstg_name": name,
        "top10": t21[0], "top10_name": t21[1], "top10_2021": t21[0], "top10_2025": t25[0], "top10_2025_name": t25[1],
        "asvs_id": asvs_id, "asvs_level": asvs_level,
        "cheat_sheet": url, "remediation": _REMEDIATION.get(cwe, ""), "remediation_url": url,
        "reference": f"https://owasp.org/www-project-web-security-testing-guide/latest/ (search {wid})" if wid else url,
    }


def consult_owasp(cwe: str = "", wstg_id: str = "", text: str = "") -> dict:
    """Look up OWASP methodology for a vulnerability class by CWE (preferred), WSTG test id, or free text:
    the WSTG test (how to test), the Top 10 category (2021 and 2025 editions), the ASVS 5.0 requirement and
    level, the Cheat Sheet (how to prevent) and a one-line remediation. Deterministic: a miss returns an
    error — do not invent test ids. Cite the result as evidence 'owasp:<WSTG id>' (or the returned `ref`)."""
    return consult(cwe, wstg_id, text)


def taxon_name(component: str, taxon_id: str) -> str:
    """Human name of a taxon for SARIF taxonomy descriptors; the id itself when unknown."""
    if component == "WSTG":
        return next((name for wid, name in _WSTG.values() if wid == taxon_id), taxon_id)
    if component == "OWASP Top 10 2021":
        return _TOP10.get(taxon_id, (taxon_id,))[0]
    if component == "OWASP Top 10 2025":
        return _TOP10_2025.get(taxon_id, (taxon_id,))[0]
    if component == "ASVS":
        return next((f"ASVS {rid} (L{lvl})" for rid, lvl in _ASVS.values() if rid == taxon_id), taxon_id)
    return taxon_id
