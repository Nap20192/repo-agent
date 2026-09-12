---
name: wstg-conf-06-http-methods
description: Use for CWE-650 (HTTP Methods): the static evidence that confirms it and the controls that reject it (WSTG WSTG-CONF-06)
cwes: [CWE-650]
wstg: WSTG-CONF-06
top10: A02:2025
---
# WSTG-CONF-06 — HTTP Methods (static verification)

Objective: check that handlers only accept the methods they are designed for.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: a route registered without a method restriction (`http.HandleFunc(path, h)`, `app.all(`, `@app.route` default GET, `router.route(path)`).
2. **Sink**: the handler mutates state or reads sensitive data regardless of method, or a GET performs a write (making it forgeable and cacheable).
3. **Missing control**: no `if r.Method != http.MethodPost` check, no `methods=[...]`, `app.use(path, handler)` catching every method.

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- the handler checks the method or is registered with a method-specific helper (`r.Post(`, `app.post(`, `methods=['POST']`).
- the handler is read-only and idempotent for every method.

## Not enough to confirm
- a missing method restriction on a pure read handler is hygiene, not a finding.
- `OPTIONS`/`HEAD` support is expected, not a weakness.

## Sinks by language
- Go: `http.HandleFunc` / `mux.HandleFunc` without `.Methods(`.
- Python: `@app.route('/x')` performing writes (default GET), Django views without `require_POST`.
- Node/TS: `app.all(`, `app.use(path, fn)`, `router.route(path).all(`.

## False-positive traps
- frameworks that route by method (`r.Post`) make this test moot: only flag catch-all registrations.

Cite `owasp:WSTG-CONF-06` in evidence. Reference: OWASP WSTG WSTG-CONF-06; prevention: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
