---
name: wstg-athz-02-bypass-authz
description: Use for CWE-862/CWE-285/CWE-284 (Bypassing Authorization Schema): the static evidence that confirms it and the controls that reject it (WSTG WSTG-ATHZ-02)
cwes: [CWE-862, CWE-285, CWE-284]
wstg: WSTG-ATHZ-02
top10: A01:2025
---
# WSTG-ATHZ-02 — Bypassing Authorization Schema (static verification)

Objective: check whether every privileged function/route is guarded, horizontally and vertically.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: an entry point (route/handler) reachable without a role or with a lower role — cite the route registration.
2. **Sink**: the handler performs a privileged action (admin CRUD, user management, export) — the anchor is the action line.
3. **Missing control**: no authorization middleware/decorator on that route, or the check compares the wrong subject (self-declared role from the request).

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- a role/permission check dominates the action (`RequireRole`, `@permission_required`, `ensureAdmin`) or the router group is wrapped by it.
- the action is intentionally public per the Domain Map (cite `domain:<entity>`).
- the route is not registered anywhere (dead code).

## Not enough to confirm
- authentication alone (`login_required`) is not authorization for admin functions — but it is enough for user-scoped actions.
- a check present on the sibling POST route does not cover the GET/PUT one — cite the exact route.

## Sinks by language
- Go: chi/gin groups without `Use(auth)`, handlers registered on `http.HandleFunc` directly.
- Python: views without `@permission_required`/`@user_passes_test`, DRF views without `permission_classes`.
- Node/TS: `app.get(route, handler)` without the auth middleware argument, admin routers mounted without a guard.

## False-positive traps
- a global middleware applied to the app does not prove per-route roles: check what the middleware enforces.

Cite `owasp:WSTG-ATHZ-02` in evidence. Reference: OWASP WSTG WSTG-ATHZ-02; prevention: https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
