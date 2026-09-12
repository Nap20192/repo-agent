---
name: wstg-injt-20-mass-assignment
description: Use for CWE-915 (Mass Assignment): the static evidence that confirms it and the controls that reject it (WSTG WSTG-INJT-20)
cwes: [CWE-915]
wstg: WSTG-INJT-20
top10: A08:2025
---
# WSTG-INJT-20 — Mass Assignment (static verification)

Objective: find request bodies bound straight into persisted models.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: the whole request body or query object.
2. **Sink**: `json.Unmarshal(body, &model)` then `Save`, `Model(**request.json)`, `Model.update(req.body)`, `findByIdAndUpdate(id, req.body)`, `Object.assign(entity, req.body)`.
3. **Missing control**: no explicit field allow-list (DTO/schema/`pick`), sensitive fields (`role`, `is_admin`, `balance`, `owner_id`) writable.

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- binding goes through a DTO/schema that lists only safe fields, or the model excludes sensitive fields from binding (`json:"-"`, `read_only_fields`, `strict()` schemas).
- sensitive fields are overwritten from the session after binding.

## Not enough to confirm
- mass assignment of only harmless fields is hygiene; the finding needs a sensitive writable field — name it.
- Mongoose `strict: true` blocks unknown paths but not declared sensitive ones.

## Sinks by language
- Go: `c.ShouldBindJSON(&user)` on the DB struct, gorm `Updates(map[string]any)` from request.
- Python: `serializer(data=request.data)` with `fields='__all__'`, `Model(**data)`.
- Node/TS: `new User(req.body)`, `Model.update(req.body)`, spread into entities.

## False-positive traps
- an allow-list on the frontend form is not a control.

Cite `owasp:WSTG-INJT-20` in evidence. Reference: OWASP WSTG WSTG-INJT-20; prevention: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
