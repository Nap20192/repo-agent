---
name: wstg-athn-04-bypass-authentication
description: Use for CWE-287/CWE-306/CWE-288 (Bypassing Authentication Schema): the static evidence that confirms it and the controls that reject it (WSTG WSTG-ATHN-04)
cwes: [CWE-287, CWE-306, CWE-288]
wstg: WSTG-ATHN-04
top10: A07:2025
---
# WSTG-ATHN-04 — Bypassing Authentication Schema (static verification)

Objective: check that authentication is enforced on every route that needs it and cannot be skipped.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: an entry point that reads/changes user data; the auth middleware chain for that route.
2. **Sink**: the handler serves protected data without the auth check, trusts a client-supplied identity (`X-User-Id` header, `user_id` in the body), or has an alternate path (`/api/v1/` vs `/api/v2/`) without the guard.
3. **Missing control**: no authentication middleware on the route, identity taken from the request instead of the verified session/token, debug bypass (`if token == 'test'`).

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- an auth middleware dominates the handler (`ensureAuthenticated`, `@login_required`, `Authenticator.Authenticate`) and the identity used downstream comes from it.
- the endpoint is intentionally public (Domain Map) and serves no user-specific data.

## Not enough to confirm
- a missing auth check on a public read endpoint is not a finding.
- JWT decoded without verification is CWE-347 territory: cite `jwt.decode(..., verify=False)` / `jwt.Parse` with `nil` key func.

## Sinks by language
- Go: handlers reading `r.Header.Get("X-User")` as identity, missing middleware in `r.Group`.
- Python: views without `@login_required`, `request.GET['user_id']` used as the principal.
- Node/TS: routes missing the auth middleware argument, `req.body.userId` as identity.

## False-positive traps
- a global `app.use(auth)` placed after some routes leaves the earlier ones unprotected.

Cite `owasp:WSTG-ATHN-04` in evidence. Reference: OWASP WSTG WSTG-ATHN-04; prevention: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
