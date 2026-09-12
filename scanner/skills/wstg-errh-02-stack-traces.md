---
name: wstg-errh-02-stack-traces
description: Use for CWE-209/CWE-703 (Stack Traces): the static evidence that confirms it and the controls that reject it (WSTG WSTG-ERRH-02)
cwes: [CWE-209, CWE-703]
wstg: WSTG-ERRH-02
top10: A10:2025
---
# WSTG-ERRH-02 — Stack Traces (static verification)

Objective: check that errors reaching the client do not expose internals.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: an error/exception path in a handler; the framework's debug configuration.
2. **Sink**: the error text/stack is written to the response (`http.Error(w, err.Error(), 500)`, `return str(e), 500`, `res.status(500).send(err.stack)`), or `DEBUG=True` / Express default error handler in production.
3. **Missing control**: no generic error page/message for 5xx, no central error handler, exceptions propagate unhandled.

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- a central error handler maps exceptions to generic messages and logs the details server-side.
- the detailed message is intentionally returned only for 4xx validation errors without internals.
- `DEBUG` is bound to a non-production setting that production cannot enable.

## Not enough to confirm
- `err.Error()` in a response for a validation error (`invalid id`) is fine — cite what the error can contain.
- unhandled errors (CWE-703 from gosec) are hygiene unless the path reaches the client or drops a security check.

## Sinks by language
- Go: `http.Error(w, err.Error()`, `fmt.Fprint(w, err)`, `panic` without recovery middleware.
- Python: `DEBUG = True`, `return str(e)`, Flask `PROPAGATE_EXCEPTIONS`.
- Node/TS: `res.send(err.stack)`, missing 4-arg error middleware, `NODE_ENV` unset.

## False-positive traps
- stack traces in logs are not this test (that is CWE-532 if they contain secrets).

Cite `owasp:WSTG-ERRH-02` in evidence. Reference: OWASP WSTG WSTG-ERRH-02; prevention: https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
