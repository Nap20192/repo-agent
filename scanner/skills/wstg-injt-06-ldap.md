---
name: wstg-injt-06-ldap
description: Use for CWE-90 (LDAP Injection): the static evidence that confirms it and the controls that reject it (WSTG WSTG-INJT-06)
cwes: [CWE-90]
wstg: WSTG-INJT-06
top10: A05:2025
---
# WSTG-INJT-06 — LDAP Injection (static verification)

Objective: find LDAP filters or DNs built from request data.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: username, search term, group name from the request.
2. **Sink**: a filter/DN string built by concatenation and passed to search/bind: `ldap.Search(...)` with `fmt.Sprintf("(uid=%s)", u)`, `conn.search_s(base, scope, f"(uid={u})")`, `client.search(base, {filter: `(uid=${u})`})`.
3. **Missing control**: no filter-escaping of `( ) * \\ NUL` and no DN escaping; no allow-list on the attribute value.

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- `ldap.EscapeFilter` / `escape_filter_chars` / `ldapjs` escape applied to the tainted value before the filter is built.
- the value is validated against a strict pattern (e.g. `^[a-z0-9._-]{1,32}$`) that excludes filter metacharacters.
- the filter is a prepared template where the value is bound by the library.

## Not enough to confirm
- LDAP use alone is not a finding; you need the untrusted fragment in the filter.
- escaping the DN but not the filter (or vice versa) leaves the other path open — cite which.

## Sinks by language
- Go: `go-ldap` `NewSearchRequest(` filter built with `Sprintf`.
- Python: `ldap.search_s`, `ldap3` `search(` with f-string filter.
- Node/TS: `ldapjs` `client.search(` with template literal filter.

## False-positive traps
- an LDAP bind with user password is authentication, not injection, unless the DN is built from input.

Cite `owasp:WSTG-INJT-06` in evidence. Reference: OWASP WSTG WSTG-INJT-06; prevention: https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
