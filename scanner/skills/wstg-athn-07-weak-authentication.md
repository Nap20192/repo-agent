---
name: wstg-athn-07-weak-authentication
description: Use for CWE-307/CWE-521/CWE-916 (Weak Authentication Methods): the static evidence that confirms it and the controls that reject it (WSTG WSTG-ATHN-07)
cwes: [CWE-307, CWE-521, CWE-916]
wstg: WSTG-ATHN-07
top10: A07:2025
---
# WSTG-ATHN-07 — Weak Authentication Methods (static verification)

Objective: check password policy, brute-force resistance and password storage.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: the login handler, the registration/password-change handler, the password hashing helper.
2. **Sink**: login without rate limiting/lockout, passwords accepted without minimum length, passwords hashed with MD5/SHA-1/unsalted SHA-256 or compared in plain text.
3. **Missing control**: no throttle/lockout/captcha on the login path, no length policy, no memory-hard or slow hash, non-constant-time compare.

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- a rate limiter or lockout dominates the login handler (`limiter.Allow`, `django-axes`, `express-rate-limit`), or auth is delegated to an IdP.
- passwords are hashed with bcrypt/argon2id/scrypt (`bcrypt.GenerateFromPassword`, `make_password`, `bcrypt.hash`) and compared with the library's compare.
- a policy enforces length ≥ 8 (or 12+) server-side.

## Not enough to confirm
- missing complexity rules are not a finding (WSTG and NIST prefer length over composition).
- a lockout policy implemented at the gateway (out of the repo) cannot be seen: say uncertain, do not confirm.

## Sinks by language
- Go: `md5.Sum(pw)`, `sha256.Sum256(pw)` for passwords, `==` compare of hashes.
- Python: `hashlib.md5(pw)`, `check_password` absent, `pbkdf2` with tiny iterations.
- Node/TS: `crypto.createHash('sha1')` for passwords, `password === stored`.

## False-positive traps
- a `sha256` used for a token fingerprint is not password storage.

Cite `owasp:WSTG-ATHN-07` in evidence. Reference: OWASP WSTG WSTG-ATHN-07; prevention: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
