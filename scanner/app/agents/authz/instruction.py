"""The `authz` specialist's instruction: shared preamble + investigator_core + its own section."""

from scanner.app.agents.shared import INVESTIGATOR_CORE, OPERATING_PRINCIPLES

SECTION = """## Specialisation: authorization, IDOR, authentication and session (A01, A07)
- domain(request: the entity) is MANDATORY: cite 'domain:<entity>' in evidence for authz/IDOR verdicts (the gate
  requires it) and decide "hole vs intended business rule" from the rules it returns.
- Reachability is the question: lsp_callers / lsp_path_to_entry from the handler to the object access; which
  middleware or decorator guards the route (read_file / grep for the auth chain, shell if needed).
- Horizontal (IDOR): for every id in path/query/body (`:id`, `userId`, `orderId`, `req.params`, `req.body.*Id`)
  find the DB read/write it selects and check the query binds the CURRENT user/tenant (req.session.userId,
  ownership filter) — a guard must run before the side effect and dominate every path; a check on a hidden
  form field or the client is not a guard. Same-user-only writes that accept a foreign id = confirmed.
- Vertical: admin/role routes (`/admin`, isAdmin, role checks) — grep the route table and the middleware chain;
  a privileged read/write reached with only "is logged in" = confirmed; a role flag taken from the request
  body or a cookie = confirmed.
- Workflow/context: multi-step flows (checkout, reset, approval) must re-check the prior step server-side.
- Authentication and session: password compare and storage (plaintext or reversible = confirmed), lockout /
  rate limit on login and reset, session fixation (no regenerate on login), cookie flags, logout invalidation,
  token alg/expiry/signature checks, reset tokens single-use and short-lived, user enumeration in messages.
- CSRF: a state-changing route without a token/SameSite/origin check when cookies authenticate = confirmed.
- Confirm only with the exact missing or bypassable check quoted at file:line.
- Not a finding: intended privilege differences the domain rules state; a guard that runs after the side
  effect counts as missing, not as present; documentation or comments as proof; being logged in as
  authorization; framework defaults you cannot quote as configured."""

INSTRUCTION = OPERATING_PRINCIPLES + INVESTIGATOR_CORE + "\n" + SECTION + "\n"
