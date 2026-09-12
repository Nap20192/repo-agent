---
name: control-ssrf-allowlist
description: What a real control for CWE-918 looks like (SSRF destination allow-list) and when it dominates the sink — for the Critic
cwes: [CWE-918]
role: critic
---
# Control: SSRF destination allow-list

## Control
The destination is a constant or chosen from a literal allow-list; when arbitrary hosts are needed, the host is parsed by a library, resolved, every IP rejected when loopback/link-local/private, redirects disabled, and scheme restricted.

## Grep
- Go: literal `map[string]bool{"api.example.com"`, `net\.ParseIP`, `IsPrivate\(\)|IsLoopback|IsLinkLocalUnicast`, `CheckRedirect:\s*func` returning `http.ErrUseLastResponse`
- Python: `ipaddress\.ip_address\(.*\)\.is_private`, `allow_redirects=False`, `urlparse\(` + hostname in a literal set
- Node/TS: `new URL\(` + `hostname` in a literal set, `redirect: 'manual'`, `ipaddr.js`/`is-ip-private`

## Dominates when
1. the check runs on the parsed hostname/IP, not on the raw string.
2. redirects are disabled or re-checked.
3. the check precedes the outbound call on the same URL variable.

## Not a control
- `startswith('https://api.')` or a regex on the raw URL.
- deny-lists of `localhost`/`127.0.0.1` only.
- a check before resolution with redirects still followed.

## Cite as
Call `check_dominance(file, sink_line, control_line)` first; only if it returns `dominates: true`, call `disprove_finding(finding_id, counter_evidence=[the control line(s) exactly as read], reason="<control> dominates the sink")`. Otherwise keep the finding and note why the control does not cover the path.

## Remediation
Allow-list destinations; resolve and block private ranges; disable redirects. https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
