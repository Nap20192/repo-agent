---
name: wstg-conf-04-sensitive-files
description: Use for CWE-538/CWE-312/CWE-530 (Review Old Backup and Unreferenced Files for Sensitive Information): the static evidence that confirms it and the controls that reject it (WSTG WSTG-CONF-04)
cwes: [CWE-538, CWE-312, CWE-530]
wstg: WSTG-CONF-04
top10: A02:2025
---
# WSTG-CONF-04 — Review Old Backup and Unreferenced Files for Sensitive Information (static verification)

Objective: find committed or served files that expose secrets, backups or internal data.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: the repository tree and static-file routes — cite the file path and the route that serves the directory.
2. **Sink**: a `.env`, `*.bak`, `*.sql` dump, private key, `config.*.json` with credentials inside a served directory or in the repo; a static handler mounted on a directory containing them.
3. **Missing control**: no ignore rules, the directory is served as a whole (`http.FileServer(http.Dir("."))`, `express.static(__dirname)`), or the secret is committed.

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- the file is a template/placeholder (`.env.example` with dummy values) — verify the values are not real.
- the served directory is a dedicated public folder without sensitive files.
- the secret is loaded from the environment and the committed file only documents keys.

## Not enough to confirm
- gitleaks anchors already cover literal secrets: do not duplicate — this test is about exposure paths (served/backup files).
- test fixtures with fake keys are not findings unless served.

## Sinks by language
- Go: `http.FileServer`, `http.ServeFile` on user-influenced paths, embedded `.env`.
- Python: `send_from_directory(app.root_path)`, `STATIC_ROOT` at project root.
- Node/TS: `express.static(path.join(__dirname))`, `serve-static` on the project root.

## False-positive traps
- a `.gitignore` entry does not un-commit a file already in history — check `git ls-files` when possible.

Cite `owasp:WSTG-CONF-04` in evidence. Reference: OWASP WSTG WSTG-CONF-04; prevention: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
