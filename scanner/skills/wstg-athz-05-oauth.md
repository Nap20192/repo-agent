---
name: wstg-athz-05-oauth
description: Use for CWE-346/CWE-1390 (OAuth Weaknesses): the static evidence that confirms it and the controls that reject it (WSTG WSTG-ATHZ-05)
cwes: [CWE-346, CWE-1390]
wstg: WSTG-ATHZ-05
top10: A07:2025
---
# WSTG-ATHZ-05 — OAuth Weaknesses (static verification)

Objective: check the OAuth/OIDC client or server code for the classic mistakes.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: the authorization code, `state`, `redirect_uri`, `id_token` or access token arriving in a callback.
2. **Sink**: the callback handler exchanges/accepts the token: `oauth2.Exchange(`, `requests.post(token_url)`, `passport` strategy callbacks, custom JWT decode of the id_token.
3. **Missing control**: no `state`/PKCE verification, `redirect_uri` not compared exactly against a registered value, `id_token` signature/`aud`/`iss`/`nonce` not verified, tokens accepted from the query string.

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- the library performs state/PKCE/nonce validation and the code passes the values through (`oauth2` with `SetAuthURLParam`, `authlib` `fetch_token(state=)`, `openid-client`).
- `redirect_uri` is matched exactly against a literal registry.
- the id_token is verified with the provider's JWKS and `aud` checked.

## Not enough to confirm
- using a mainstream library is not proof: cite the call that verifies `state` and `nonce`.
- implicit flow use is a weakness only if the app accepts tokens from the fragment/query.

## Sinks by language
- Go: `golang.org/x/oauth2` `Exchange` without state check, `jwt.Parse` unverified.
- Python: `authlib`/`requests-oauthlib` callbacks, `jwt.decode(..., verify=False)`.
- Node/TS: `passport-oauth2` verify callbacks, `jwt.decode` (no verify), custom `/callback` handlers.

## False-positive traps
- a `state` parameter generated but never compared on return is not a control.

Cite `owasp:WSTG-ATHZ-05` in evidence. Reference: OWASP WSTG WSTG-ATHZ-05; prevention: https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html
