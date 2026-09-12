---
name: wstg-cryp-04-weak-crypto
description: Use for CWE-327/CWE-328/CWE-338/CWE-326 (Weak Cryptographic Primitives): the static evidence that confirms it and the controls that reject it (WSTG WSTG-CRYP-04)
cwes: [CWE-327, CWE-328, CWE-338, CWE-326]
wstg: WSTG-CRYP-04
top10: A04:2025
---
# WSTG-CRYP-04 — Weak Cryptographic Primitives (static verification)

Objective: find weak or misused cryptographic primitives.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: the call site of the primitive and the data it protects (token, password, session id, file).
2. **Sink**: MD5/SHA-1 for integrity or signatures, DES/RC4/ECB modes, `math/rand`/`random`/`Math.random` for secrets, static IVs/nonces, keys shorter than 128 bits, `crypto/rsa` PKCS#1 v1.5 for new code.
3. **Missing control**: no modern primitive (AES-GCM/ChaCha20-Poly1305, SHA-256+, HMAC, argon2/bcrypt, `crypto/rand`), no key management.

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- the weak primitive protects nothing security-relevant (checksum for cache keys, ETag, dedup) — reject with the use cited.
- the value comes from a CSPRNG (`crypto/rand`, `secrets`, `crypto.randomBytes`) and the weak hash is only a fingerprint.
- the algorithm is imposed by an external protocol (cite the API contract) — report low, not confirmed.

## Not enough to confirm
- `md5` on a file for deduplication is not a finding.
- `math/rand` seeded from `crypto/rand` for non-security values is fine.

## Sinks by language
- Go: `crypto/md5`, `crypto/sha1`, `crypto/des`, `crypto/rc4`, `math/rand` for tokens, `cipher.NewCBCEncrypter` with fixed IV.
- Python: `hashlib.md5/sha1` for auth, `random.*` for tokens, `Crypto.Cipher.DES`, `AES.MODE_ECB`.
- Node/TS: `createHash('md5'|'sha1')` for auth, `Math.random()` for tokens, `createCipher` (deprecated), `aes-128-ecb`.

## False-positive traps
- the gosec rule fires on every `md5` import: the finding stands only when the output guards something.

Cite `owasp:WSTG-CRYP-04` in evidence. Reference: OWASP WSTG WSTG-CRYP-04; prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
