---
name: open-redirect
description: Open redirect testing for phishing pivots, OAuth token theft, and allowlist bypass
---

# Open Redirect

Open redirects enable phishing, OAuth/OIDC code and token theft, and allowlist bypass in server-side fetchers that follow redirects. Treat every redirect target as untrusted: canonicalize and enforce exact allowlists per scheme, host, and path.

## Attack Surface

**Server-Driven Redirects**
- HTTP 3xx Location

**Client-Driven Redirects**
- `window.location`, meta refresh, SPA routers

**OAuth/OIDC/SAML Flows**
- `redirect_uri`, `post_logout_redirect_uri`, `RelayState`, `returnTo`/`continue`/`next`

**Multi-Hop Chains**
- Only first hop validated

## High-Value Targets

- Login/logout, password reset, SSO/OAuth flows
- Payment gateways, email links, invite/verification
- Unsubscribe, language/locale switches
- `/out` or `/r` redirectors

## Key Vulnerabilities

### Allowlist Evasion

**Common Mistakes**
- Substring/regex contains checks: allows `trusted.com.evil.com`
- Wildcards: `*.trusted.com` also matches `attacker.trusted.com.evil.net`
- Missing scheme pinning: `data:`, `javascript:`, `file:`, `gopher:` accepted
- Case/IDN drift between validator and browser

**Robust Validation**
- Canonicalize with a single modern URL parser (WHATWG URL)
- Compare exact scheme, hostname (post-IDNA), and an explicit allowlist with optional exact path prefixes
- Require absolute HTTPS; reject protocol-relative `//` and unknown schemes

### OAuth/OIDC/SAML

**Redirect URI Abuse**
- Using an open redirect on a trusted domain for redirect_uri enables code interception
- Weak prefix/suffix checks: `https://trusted.com` → `https://trusted.com.evil.com`
- Path traversal/canonicalization: `/oauth/../../@evil.com`
- `post_logout_redirect_uri` often less strictly validated

### Client-Side Vectors

**JavaScript Redirects**
- `location.href`/`assign`/`replace` using user input
- Meta refresh `content=0;url=USER_INPUT`
- SPA routers: `router.push(searchParams.get('next'))`

### Reverse Proxies and Gateways

- Host/X-Forwarded-* may change absolute URL construction
- CDNs that follow redirects for link checking can leak tokens when chained

### SSRF Chaining

- Server-side fetchers (web previewers, link unfurlers) follow 3xx
- Combine with an open redirect on an allowlisted domain to pivot to internal targets (169.254.169.254, localhost)

## Validation

1. Produce a minimal URL that navigates to an external domain via the vulnerable surface; include the full address bar capture
2. Show bypass of the stated validation (regex/allowlist) using canonicalization variants
3. Test multi-hop: prove only first hop is validated and second hop escapes constraints
4. For OAuth/SAML, demonstrate code/RelayState delivery to an attacker-controlled endpoint

## False Positives

- Redirects constrained to relative same-origin paths with robust normalization
- Exact pre-registered OAuth redirect_uri with strict verifier
- Validators using a single canonical parser and comparing post-IDNA host and scheme
- User prompts that show the exact final destination before navigating

## Impact

- Credential and token theft via phishing and OAuth/OIDC interception
- Internal data exposure when server fetchers follow redirects
- Policy bypass where allowlists are enforced only on the first hop
- Cross-application trust erosion and brand abuse

## Pro Tips

1. Always compare server-side canonicalization to real browser navigation; differences reveal bypasses
2. Try userinfo, protocol-relative, Unicode/IDN, and IP numeric variants early
3. In OAuth, prioritize `post_logout_redirect_uri` and less-discussed flows; they're often looser
4. Exercise multi-hop across distinct subdomains and paths
5. For SSRF chaining, target services known to follow redirects
6. Favor allowlists of exact origins plus optional path prefixes
7. Keep a curated suite of redirect payloads per runtime (Java, Node, Python, Go)

## Summary

Redirection is safe only when the final destination is constrained after canonicalization. Enforce exact origins, verify per hop, and treat client-provided destinations as untrusted across every stack.
