---
name: wstg-sess-07-session-timeout
description: Use for CWE-613 (Session Timeout): the static evidence that confirms it and the controls that reject it (WSTG WSTG-SESS-07)
cwes: [CWE-613]
wstg: WSTG-SESS-07
top10: A07:2025
---
# WSTG-SESS-07 — Session Timeout (static verification)

Objective: check that sessions and tokens expire and that logout invalidates them.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: session creation / token issuance code.
2. **Sink**: a session or JWT created without expiry (`MaxAge: 0` forever, `expiresIn` absent, `exp` claim missing) or a logout that only clears the client cookie.
3. **Missing control**: no absolute/idle timeout; no server-side invalidation on logout; refresh tokens without rotation.

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- the session store sets an idle and absolute lifetime (`SESSION_COOKIE_AGE`, `cookie.maxAge`, `sessions.Options.MaxAge`) and logout deletes the server record.
- JWTs carry `exp` and are checked; logout revokes via a denylist or short-lived tokens with rotating refresh.

## Not enough to confirm
- a long but finite lifetime is a policy question, not a finding — report uncertain with the value.
- stateless JWT without revocation is a known trade-off: report as low unless tokens are long-lived.

## Sinks by language
- Go: `jwt.NewWithClaims` without `ExpiresAt`, `sessions.Options{MaxAge: 0}`.
- Python: `jwt.encode` without `exp`, `SESSION_EXPIRE_AT_BROWSER_CLOSE=False` with huge age.
- Node/TS: `jwt.sign(payload, secret)` without `expiresIn`, `express-session` without `cookie.maxAge`.

## False-positive traps
- `MaxAge: 0` in Go means session cookie (browser close), not forever; `-1` deletes — read the semantics of the library.

Cite `owasp:WSTG-SESS-07` in evidence. Reference: OWASP WSTG WSTG-SESS-07; prevention: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
