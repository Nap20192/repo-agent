---
name: wstg-injt-19-ssrf
description: Use for CWE-918 (Server-Side Request Forgery): the static evidence that confirms it and the controls that reject it (WSTG WSTG-INJT-19)
cwes: [CWE-918]
wstg: WSTG-INJT-19
top10: A01:2025
---
# WSTG-INJT-19 — Server-Side Request Forgery (static verification)

Objective: find outbound requests whose destination is influenced by request data.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: URL, host, port, path, callback or webhook field from the request; XML entities; document/image URLs to render.
2. **Sink**: `http.Get(u)`, `http.NewRequest(m, u)`, `requests.get(u)`, `urlopen(u)`, `fetch(u)`, `axios.get(u)`, `net.Dial`, and indirect: PDF/image fetchers, `curl`/`wget` via exec, redirect following.
3. **Missing control**: no allow-list of scheme/host, no resolve-then-check of the IP (loopback, link-local 169.254.169.254, RFC1918), redirects followed.

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- the destination is a constant or selected from a literal allow-list; user input only picks an entry.
- the host is parsed with a library, resolved, and every IP is rejected when private/loopback/link-local; redirects are disabled (`CheckRedirect`, `allow_redirects=False`, `redirect: 'manual'`).
- the URL is only used for display/logging, never fetched.

## Not enough to confirm
- a substring/regex check on the raw URL string (`startswith('https://api.')`) is bypassable (`@`, userinfo, redirects): not a control.
- DNS rebinding cannot be proven statically: mention, do not claim.
- an internal service fetching from config values is not SSRF.

## Sinks by language
- Go: `net/http` client calls with variable URL, `net.Dial`, `url.Parse(user)` then `Get`.
- Python: `requests.*`, `httpx.*`, `urllib.request.urlopen`, `aiohttp` with user URL.
- Node/TS: `fetch`, `axios`, `got`, `http.request`, `needle` with user URL.

## False-positive traps
- an allow-list of hosts compared before resolution is fine only if redirects are also disabled.

Cite `owasp:WSTG-INJT-19` in evidence. Reference: OWASP WSTG WSTG-INJT-19; prevention: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
