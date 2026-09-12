---
name: control-csrf
description: What a real control for CWE-352 looks like (CSRF token / origin check) and when it dominates the sink — for the Critic
cwes: [CWE-352]
role: critic
---
# Control: CSRF token / origin check

## Control
Framework CSRF middleware or a synchronizer/signed double-submit token verified on every unsafe method of the route; or a Fetch-Metadata/Origin check; SameSite alone counts only with Strict (or Lax + `__Host-`), no state-changing GET and no shared registrable domain.

## Grep
- Go: `nosurf\.New|csrf\.Protect|CrossOriginProtection`
- Python: `CsrfViewMiddleware|csrf_token|@csrf_protect` and no `@csrf_exempt` on the sink route
- Node/TS: `csurf\(|csrfProtection|doubleCsrf\(|Sec-Fetch-Site`

## Dominates when
1. the middleware is applied to the route that owns the sink (group/router/decorator), not just imported.
2. the route is not exempted.
3. the token is verified server-side, not only rendered.

## Not a control
- SameSite=Lax alone with state-changing GET routes.
- a token in the template with no server verification.
- checking `Referer` presence only.
- middleware mounted after the route.

## Cite as
Call `check_dominance(file, sink_line, control_line)` first; only if it returns `dominates: true`, call `disprove_finding(finding_id, counter_evidence=[the control line(s) exactly as read], reason="<control> dominates the sink")`. Otherwise keep the finding and note why the control does not cover the path.

## Remediation
Enable the framework's CSRF protection on every state-changing route. https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
