---
name: authz-idor
description: How to decide "hole or business rule" for object ownership by reading the owner check yourself (owner field / owner check / owner source) and what evidence the gate needs
---

# Authorization / IDOR: hole or business rule

An IDOR claim is never proven by reading one handler. It is proven against three facts you
establish from the code: who owns the object, where that ownership is checked, and where
the caller's identity comes from. There is no consultant for this — grep, read_file,
lsp_definition and lsp_references are how you find them.

## The three facts

| owner field | owner check | Verdict |
|---|---|---|
| set | none found | **hole**: the entity has an owner and nobody compares it to the caller. Confirm CWE-639 (or CWE-862 for a missing function-level check). |
| none | any | **business rule**: the entity is shared or public by design. Do not report as IDOR; reject or mark uncertain and say why. |
| set | `file:line` | **check exists**: open that line. Confirm only if the check is bypassable (wrong field, wrong caller identity, only on some paths); otherwise reject. |

The owner source tells where the owner id comes from. `params:`/`query:`/`body:` means the
client chose it. `session:`/`jwt:` means the server did. A hole needs a client-chosen id
that reaches the data layer without a comparison against the session identity.

## Steps for the Verifier

1. Name the entity the hypothesis is about (`Allocation`, `Order`, `Profile`) and find its
   model / table / DAO: grep for the type, its owner-looking fields (`userId`, `owner`, `tenant`,
   `account_id`) and every query that selects it by id.
2. Follow the id from the handler to that query by the call graph (`lsp_references`,
   `lsp_callers`, `lsp_path_to_entry`); note whether the id comes from the request or the session.
3. Look for the comparison: in the handler, its middleware / decorators, and the DAO it reaches.
   A check in a sibling route does not count; a check on one branch only is a hole on the others.
4. Decide with the table above and cite what you read as `domain:<entity>`.

## Evidence the gate accepts

`report_finding` for an authz CWE is refused without a `domain:` reference. Evidence
must contain:

- `domain:<entity>` (e.g. `domain:allocations`) naming the ownership check you read;
- the exact line where the client-chosen id is read;
- the exact line where it reaches the query without a check, or the line of the
  bypassable check.

## Worked example: NodeGoat allocations

- Entity `allocations`, owner field `userId`, evidence `data/allocations-dao.js:82`.
- Route `GET /allocations/:userId`, handler `displayAllocations` at
  `routes/allocations.js:11`.
- owner source `params:routes/allocations.js:18`, owner check none (the session
  comparison at lines 13–14 is commented out).

Verdict: hole. Evidence: `domain:allocations`, the `req.params.userId` line, and the
DAO query keyed by that id. CWE-639, high.
