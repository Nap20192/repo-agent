---
name: wstg-athz-03-privilege-escalation
description: Use for CWE-269/CWE-915 (Privilege Escalation): the static evidence that confirms it and the controls that reject it (WSTG WSTG-ATHZ-03)
cwes: [CWE-269, CWE-915]
wstg: WSTG-ATHZ-03
top10: A01:2025
---
# WSTG-ATHZ-03 — Privilege Escalation (static verification)

Objective: find places where the user can raise their own privileges or role.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: a request field that names a role, group, plan, `is_admin`, or a user id other than the caller's.
2. **Sink**: the field is bound straight into the model/update (`json.Unmarshal(body, &user)`, `User(**request.json)`, `Model.update(req.body)`, `Object.assign(user, req.body)`) or into a role assignment.
3. **Missing control**: no allow-list of writable fields (DTO), no server-side derivation of role/owner from the session.

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- a DTO/schema with an explicit field allow-list is used for binding (`binding:"-"` on the role field, pydantic model without `role`, `pick(req.body, [...])`).
- the privileged field is overwritten from the session after binding (`user.Role = current.Role`).
- the update endpoint is admin-only and the Domain Map says role changes are an admin action.

## Not enough to confirm
- mass assignment of harmless fields (display name) is not escalation: the finding needs a privileged field.
- a role check on read endpoints does not protect the write path.

## Sinks by language
- Go: `json.Decode(&user)` into the persisted struct, gorm `Updates(map)` from request.
- Python: `Model(**data)`, `serializer` without `fields=`, `setattr(user, k, v)` loops.
- Node/TS: `Object.assign`, spread `{...req.body}`, Mongoose `findByIdAndUpdate(id, req.body)`.

## False-positive traps
- `readOnly` in an OpenAPI spec does not enforce anything at runtime.

Cite `owasp:WSTG-ATHZ-03` in evidence. Reference: OWASP WSTG WSTG-ATHZ-03; prevention: https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
