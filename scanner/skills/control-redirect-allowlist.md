---
name: control-redirect-allowlist
description: What a real control for CWE-601 looks like (redirect target validation) and when it dominates the sink — for the Critic
cwes: [CWE-601]
role: critic
---
# Control: redirect target validation

## Control
The redirect target is an internal id/token mapped server-side, or a relative path that starts with `/` and not `//`, or a host compared against a literal allow-list after parsing.

## Grep
- Go: `url\.Parse` + `u\.IsAbs\(\)|u\.Host != ""`, `HasPrefix\(next, "/"\) && !HasPrefix\(next, "//"\)`
- Python: `url_has_allowed_host_and_scheme`, `urlparse\(` + netloc check, `is_safe_url`
- Node/TS: `new URL\(next, base\)` + `origin ===`, `startsWith\('/'\) && !startsWith\('//'\)`

## Dominates when
1. the check runs on the parsed URL before `redirect`.
2. protocol-relative (`//`) and backslash variants are rejected.

## Not a control
- a `startswith('/')` check alone.
- a deny-list of known bad hosts.
- checking `Referer`.

## Cite as
Call `check_dominance(file, sink_line, control_line)` first; only if it returns `dominates: true`, call `disprove_finding(finding_id, counter_evidence=[the control line(s) exactly as read], reason="<control> dominates the sink")`. Otherwise keep the finding and note why the control does not cover the path.

## Remediation
Redirect only to allow-listed or relative targets. https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
