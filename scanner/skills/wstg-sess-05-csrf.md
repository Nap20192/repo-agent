---
name: wstg-sess-05-csrf
description: Use for CWE-352 (Cross Site Request Forgery): the static evidence that confirms it and the controls that reject it (WSTG WSTG-SESS-05)
cwes: [CWE-352]
wstg: WSTG-SESS-05
top10: A01:2025
---
# WSTG-SESS-05 — Cross Site Request Forgery (static verification)

Objective: check whether state-changing requests can be forged from another origin.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: a state-changing route (POST/PUT/DELETE, or GET with side effects) authenticated by a cookie.
2. **Sink**: the handler mutates state (write, transfer, settings, password change) — the anchor is the mutation or the route registration.
3. **Missing control**: no CSRF middleware/token on that route, no Origin/Sec-Fetch-Site check, or the route is exempted (`@csrf_exempt`).

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- framework CSRF protection wraps the route (`CsrfViewMiddleware`, `csurf`/`csrf-csrf`, `gorilla/csrf`, `nosurf`, Go ≥1.25 `http.CrossOriginProtection`) and the route is not exempted.
- authentication is a bearer token in a header (not a cookie) — browsers cannot forge it.
- SameSite=Strict/Lax on the session cookie AND no state-changing GET AND no shared registrable domain — only then SameSite alone suffices.

## Not enough to confirm
- GET routes that only read are not CSRF.
- a token generated in the template but never verified server-side is not a control.

## Sinks by language
- Go: handlers on `POST` without csrf middleware in the chain.
- Python: views with `@csrf_exempt`, DRF with `SessionAuthentication` and no CSRF, Flask forms without `CSRFProtect`.
- Node/TS: `app.post` without `csrfProtection`, `cookie-session` without a token check.

## False-positive traps
- middleware mounted after the route registration does not protect it (Express order matters).

Cite `owasp:WSTG-SESS-05` in evidence. Reference: OWASP WSTG WSTG-SESS-05; prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
