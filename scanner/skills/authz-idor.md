---
name: authz-idor
description: How to decide "hole or business rule" for object ownership using the Domain Map (OwnerField / OwnerCheck / OwnerSource) and what evidence the gate needs
---

# Authorization / IDOR via the Domain Map

An IDOR claim is never proven by reading one handler. It is proven against the Domain
Map: who owns the object, where that ownership is checked, and where the caller's
identity comes from. Ask `consult_domain` with a concrete question, e.g.
"does displayAllocations check the allocation belongs to the caller?".

## Reading the answer

`consult_domain` returns `entity`, `owner_field`, `owner_check`, `owner_source`,
`expected_check`, `is_multitenant`, `roles_required`, `evidence_refs`.

| OwnerField | OwnerCheck | Verdict |
|---|---|---|
| set | empty | **hole**: the entity has an owner and nobody compares it to the caller. Confirm CWE-639 (or CWE-862 for missing function-level check). |
| empty | any | **business rule**: the entity is shared or public by design. Do not report as IDOR; reject or mark uncertain and say why. |
| set | `file:line` | **check exists**: open that line. Confirm only if the check is bypassable (wrong field, wrong caller identity, only on some paths); otherwise reject. |

`OwnerSource` tells where the owner id comes from. `params:`/`query:`/`body:` means the
client chose it. `session:`/`jwt:` means the server did. A hole needs a client-chosen
id that reaches the data layer without a comparison against the session identity.

## Steps for the Verifier

1. Call `consult_domain` for the entity or handler named in the hypothesis.
2. Open `evidence_refs` and the handler `ref`. Follow the id from `OwnerSource` to the
   query or mutation by the call graph (`build_paths` on Go, `lsp_references` elsewhere).
3. Look for the comparison the map says is missing. Search the handler, its middleware,
   and the DAO it reaches. A check in a sibling route does not count.
4. Decide with the table above.

## Evidence the gate accepts

`report_finding` for an authz CWE is refused without a `domain:` reference. Evidence
must contain:

- `domain:<entity>` (e.g. `domain:allocations`) proving you consulted the map;
- the exact line where the client-chosen id is read;
- the exact line where it reaches the query without a check, or the line of the
  bypassable check.

## Worked example: NodeGoat allocations

- Entity `allocations`, owner field `userId`, evidence `data/allocations-dao.js:82`.
- Route `GET /allocations/:userId`, handler `displayAllocations` at
  `routes/allocations.js:11`.
- OwnerSource `params:routes/allocations.js:18`, OwnerCheck empty (the session
  comparison at lines 13–14 is commented out).

Verdict: hole. Evidence: `domain:allocations`, the `req.params.userId` line, and the
DAO query keyed by that id. CWE-639, high.
