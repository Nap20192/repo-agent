---
name: control-authz-ownership
description: What a real control for CWE-639/CWE-284/CWE-285/CWE-862/CWE-863 looks like (object-level authorization) and when it dominates the sink — for the Critic
cwes: [CWE-639, CWE-284, CWE-285, CWE-862, CWE-863]
role: critic
---
# Control: object-level authorization

## Control
Every request checks the caller's right to the specific object: the query is scoped by the principal, or an ownership/role comparison dominates the use of the object; deny by default; enforced by a centralized middleware/decorator applied to the route.

## Grep
- Go: `WHERE .* user_id\s*=\s*\$`, `if .*\.UserID != .*UserID`, `Authorize|RequireRole|PolicyEnforce`
- Python: `@login_required|@permission_required`, `get_object_or_404\([^,]+,\s*[^)]*user=`, `owner=request\.user`, `has_object_permission`
- Node/TS: `req\.user\.id` in the query filter, `if \(.*\.owner.*!==.*req\.user`, `ensureOwner|can\('`

## Dominates when
1. the check uses the verified principal (session/token), not a request field.
2. it precedes every use of the object on the traced path.
3. the object type matches the finding's entity (cite `domain:<entity>`).

## Not a control
- authentication alone.
- a check on a sibling route.
- an owner check after the sensitive read/write.
- a role check when the flaw is horizontal (same role, other user).

## Cite as
Call `check_dominance(file, sink_line, control_line)` first; only if it returns `dominates: true`, call `disprove_finding(finding_id, counter_evidence=[the control line(s) exactly as read], reason="<control> dominates the sink")`. Otherwise keep the finding and note why the control does not cover the path.

## Remediation
Scope every object access by the authenticated principal; centralize the check. https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
