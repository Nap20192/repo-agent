---
name: wstg-busl-01-data-validation
description: Use for CWE-20/CWE-840 (Business Logic Data Validation): the static evidence that confirms it and the controls that reject it (WSTG WSTG-BUSL-01)
cwes: [CWE-20, CWE-840]
wstg: WSTG-BUSL-01
top10: A05:2025
---
# WSTG-BUSL-01 — Business Logic Data Validation (static verification)

Objective: check that business values are validated server-side against the rules of the domain.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: a request field that carries a business value: price, quantity, amount, discount, state transition, recipient.
2. **Sink**: the value is used in a calculation, a transfer or a state change without a range/ownership/state check (`total = price * qty` from the body, `balance -= amount` with negative amount, `status = req.body.status`).
3. **Missing control**: no server-side validation of range/sign/enum, trust in client-computed totals, no state-machine check — read the business rule in the code (validators, state machine, pricing) and cite `domain:<rule>`.

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- the value is recomputed server-side from trusted data (price from the catalog, not the request).
- a validator/schema enforces range and enum before the sink, or the state transition is checked against allowed transitions.
- the code documents the behaviour as intended (a comment, a test, a config — cite it as `domain:<rule>`).

## Not enough to confirm
- client-side validation alone is not a control.
- a missing check on a value with no business impact is hygiene.

## Sinks by language
- Go: `json.Decode` then arithmetic on fields without validation, `switch` missing on `status`.
- Python: `request.json['amount']` used directly, `Model.status = data['status']`.
- Node/TS: `req.body.price` in totals, `order.status = req.body.status`.

## False-positive traps
- a database constraint (`CHECK (amount > 0)`) is a control only if the sink writes to that table.

Cite `owasp:WSTG-BUSL-01` in evidence. Reference: OWASP WSTG WSTG-BUSL-01; prevention: https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
