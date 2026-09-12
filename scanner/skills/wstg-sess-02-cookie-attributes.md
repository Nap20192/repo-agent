---
name: wstg-sess-02-cookie-attributes
description: Use for CWE-614/CWE-1004 (Cookies Attributes): the static evidence that confirms it and the controls that reject it (WSTG WSTG-SESS-02)
cwes: [CWE-614, CWE-1004]
wstg: WSTG-SESS-02
top10: A02:2025
---
# WSTG-SESS-02 — Cookies Attributes (static verification)

Objective: check that session cookies carry Secure, HttpOnly and an appropriate SameSite.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: the cookie is set by application code (not a static asset): cite the `SetCookie`/`set_cookie`/`res.cookie` line.
2. **Sink**: a session/auth cookie created without `Secure`, without `HttpOnly`, or with `SameSite=None` unintentionally.
3. **Missing control**: the flags are absent, hard-coded false, or `Secure` depends on a debug flag that production keeps.

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- the flags are set on the same cookie (`Secure: true, HttpOnly: true, SameSite: Lax|Strict`) or the session library sets them by default (`SESSION_COOKIE_SECURE=True`, `express-session` `cookie: {secure: true, httpOnly: true}`).
- the cookie is not sensitive (theme, locale) — reject with the reason.
- `Secure` is derived from the request scheme behind a trusted TLS terminator (`trust proxy`) — note it.

## Not enough to confirm
- a missing `SameSite` alone is not a finding when a CSRF token exists (see SESS-05).
- cookies set only in tests/dev settings files.

## Sinks by language
- Go: `http.SetCookie(w, &http.Cookie{...})`, gorilla `sessions.Options`.
- Python: `response.set_cookie(`, Django `SESSION_COOKIE_*`, Flask `SESSION_COOKIE_*`.
- Node/TS: `res.cookie(`, `express-session` options, `cookie-session`.

## False-positive traps
- `Secure: r.TLS != nil` is fine only if TLS terminates at the app; behind a proxy it is always false.

Cite `owasp:WSTG-SESS-02` in evidence. Reference: OWASP WSTG WSTG-SESS-02; prevention: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
