---
name: wstg-conf-05-admin-interfaces
description: Use for CWE-306/CWE-749 (Enumerate Infrastructure and Application Admin Interfaces): the static evidence that confirms it and the controls that reject it (WSTG WSTG-CONF-05)
cwes: [CWE-306, CWE-749]
wstg: WSTG-CONF-05
top10: A02:2025
---
# WSTG-CONF-05 — Enumerate Infrastructure and Application Admin Interfaces (static verification)

Objective: find administrative or debug endpoints that are reachable without authentication.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: route registrations for `/admin`, `/debug`, `/metrics`, `/pprof`, `/actuator`, `/console`, `/graphql` introspection, framework debug toolbars.
2. **Sink**: the endpoint exposes privileged functionality or internals — the registration line or the handler.
3. **Missing control**: no authentication/role gate, no network restriction expressed in code, debug mode enabled in production settings.

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- the route group is wrapped by an auth+role middleware, or the endpoint is registered only when `DEBUG`/`dev` is true and that flag cannot be enabled in production.
- the endpoint is bound to localhost only in code (`127.0.0.1:6060`).
- the interface is intentionally internal behind a network boundary (deploy config, bind address — cite `domain:<entity>`).

## Not enough to confirm
- `/health` and `/version` are not admin interfaces unless they leak internals.
- the presence of an admin UI is not a finding; the missing gate is.

## Sinks by language
- Go: `net/http/pprof` import, `expvar`, gin `debug` routes, `/metrics` without auth.
- Python: Django admin without `ADMINS` restriction, `DEBUG=True`, `flask-debugtoolbar`, `werkzeug` debugger.
- Node/TS: `express-status-monitor`, `/graphql` with introspection, `app.use('/admin', ...)` without guard.

## False-positive traps
- `_ = pprof` imported for profiling behind a build tag is out of scope if the tag is not default.

Cite `owasp:WSTG-CONF-05` in evidence. Reference: OWASP WSTG WSTG-CONF-05; prevention: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
