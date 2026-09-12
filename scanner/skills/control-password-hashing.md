---
name: control-password-hashing
description: What a real control for CWE-287/CWE-521/CWE-916/CWE-307 looks like (password storage and login hardening) and when it dominates the sink — for the Critic
cwes: [CWE-287, CWE-521, CWE-916, CWE-307]
role: critic
---
# Control: password storage and login hardening

## Control
Passwords are hashed with argon2id, scrypt or bcrypt (cost ≥ 10) and compared with the library's constant-time verify; login is rate-limited or locks out; tokens are compared in constant time.

## Grep
- Go: `bcrypt\.GenerateFromPassword|argon2\.IDKey|scrypt\.Key`, `bcrypt\.CompareHashAndPassword`, `subtle\.ConstantTimeCompare`, `limiter`
- Python: `make_password|check_password`, `argon2\.PasswordHasher`, `bcrypt\.checkpw`, `hmac\.compare_digest`, `django-axes|ratelimit`
- Node/TS: `bcrypt\.hash|argon2\.hash`, `bcrypt\.compare`, `crypto\.timingSafeEqual`, `express-rate-limit`

## Dominates when
1. the hash function at the sink is the slow one (not `sha256` with a salt).
2. the compare is the library's verify.
3. the limiter wraps the login route.

## Not a control
- MD5/SHA-1/SHA-256 with a salt.
- PBKDF2 with a low iteration count.
- complexity rules instead of length.
- a limiter on a different route.

## Cite as
Call `check_dominance(file, sink_line, control_line)` first; only if it returns `dominates: true`, call `disprove_finding(finding_id, counter_evidence=[the control line(s) exactly as read], reason="<control> dominates the sink")`. Otherwise keep the finding and note why the control does not cover the path.

## Remediation
Hash with argon2id/bcrypt/scrypt; rate-limit login; compare in constant time. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
