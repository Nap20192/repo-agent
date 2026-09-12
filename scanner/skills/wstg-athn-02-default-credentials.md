---
name: wstg-athn-02-default-credentials
description: Use for CWE-798/CWE-1392 (Default Credentials): the static evidence that confirms it and the controls that reject it (WSTG WSTG-ATHN-02)
cwes: [CWE-798, CWE-1392]
wstg: WSTG-ATHN-02
top10: A07:2025
---
# WSTG-ATHN-02 — Default Credentials (static verification)

Objective: find accounts, keys or passwords that ship with the code.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: a literal credential in source, config, migration/seed, or Dockerfile that reaches an authentication check or a client.
2. **Sink**: the literal is compared with user input (`if pass == "admin"`), used to seed a user, or used as an API/DB credential.
3. **Missing control**: no environment/secret-manager loading, no forced change on first login, the literal is not a placeholder.

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- the value is a documented placeholder (`changeme`, `<your-key>`) that fails validation, or is only in tests/examples.
- the literal is a public identifier (client id, algorithm name, public key), not a secret.
- credentials are loaded from the environment and the literal is a dev default that production overrides — cite the override.

## Not enough to confirm
- gitleaks anchors already carry the secret: prove it is used (compared/sent), otherwise it is a leaked but dead secret (still report, lower severity).
- algorithm names like `bcrypt` or key ids are not credentials.

## Sinks by language
- Go: `os.Getenv("X")` fallback to a literal, `password: "..."` in structs, seed migrations.
- Python: `SECRET_KEY = '...'`, `DATABASES` with literal passwords, `createsuperuser` scripts.
- Node/TS: `process.env.X || 'secret'`, `config.js` literals, seed scripts.

## False-positive traps
- a `.env.example` with a real-looking key is a finding only if the value is real — check entropy/format, then say uncertain.

Cite `owasp:WSTG-ATHN-02` in evidence. Reference: OWASP WSTG WSTG-ATHN-02; prevention: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
