---
name: wstg-athz-04-idor
description: Use for CWE-639/CWE-863 (Insecure Direct Object References): the static evidence that confirms it and the controls that reject it (WSTG WSTG-ATHZ-04)
cwes: [CWE-639, CWE-863]
wstg: WSTG-ATHZ-04
top10: A01:2025
---
# WSTG-ATHZ-04 — Insecure Direct Object References (static verification)

Objective: find lookups keyed by a request-supplied object id with no ownership check.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: the object identifier comes from path/query/body, not from the session principal.
2. **Sink**: the id is the whole key of a read/update/delete: `WHERE id = $1` without an owner predicate, `Order.get(id)`, `findById(req.params.id)`, `os.Open(base + name)`.
3. **Missing control**: no comparison of the object's owner with the caller, no query scoped by the principal, no policy middleware for this object type — read the entity's ownership check yourself (grep / lsp_references from the handler to the query) and cite it as `domain:<entity>`.

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- the query is scoped by the principal (`AND user_id = $2`, `current_user.orders.find(id)`) or the id is derived from the session.
- an ownership check dominates the sink (`if obj.Owner != me { 403 }` before any use).
- the object is public by design — no owner field anywhere in its model or queries (cite `domain:<entity>`) — a business rule, not a hole.

## Not enough to confirm
- a missing check on a resource that is public for every authenticated user.
- an admin-only route: a role gate replaces the owner check (that is ATHZ-02 territory).
- random/unguessable ids do not create a check; sequential ids do not remove one.

## Sinks by language
- Go: `chi.URLParam`/`mux.Vars`/`c.Param` → `repo.Get(id)`.
- Python: `Model.objects.get(pk=request.GET['id'])`, `db.session.get(Model, id)`.
- Node/TS: `req.params.id` → `Model.findById`, `collection.findOne({_id})`.

## False-positive traps
- the owner check in a sibling handler (`getMyOrder`) does not cover this one.

Cite `owasp:WSTG-ATHZ-04` in evidence. Reference: OWASP WSTG WSTG-ATHZ-04; prevention: https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
