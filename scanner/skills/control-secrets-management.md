---
name: control-secrets-management
description: What a real control for CWE-798/CWE-312 looks like (secrets outside the code) and when it dominates the sink — for the Critic
cwes: [CWE-798, CWE-312]
role: critic
---
# Control: secrets outside the code

## Control
Secrets come from the environment or a secret manager; committed values are placeholders that fail validation; secrets are excluded from logs and responses.

## Grep
- Go: `os\.Getenv\(` without a literal fallback, `secretmanager|vault`
- Python: `os\.environ\[|environ\.get\(` without a literal default, `python-decouple|dotenv` with `.env` ignored
- Node/TS: `process\.env\.[A-Z_]+` without `\|\| '` literal fallback, `dotenv` with `.env` ignored

## Dominates when
1. the literal at the anchor is not used as a credential (placeholder, public id, example).
2. the real value is loaded from the environment on the same path.

## Not a control
- a `.gitignore` entry for a file already committed.
- base64-encoding the secret.
- a literal fallback after `os.Getenv`.

## Cite as
Call `check_dominance(file, sink_line, control_line)` first; only if it returns `dominates: true`, call `disprove_finding(finding_id, counter_evidence=[the control line(s) exactly as read], reason="<control> dominates the sink")`. Otherwise keep the finding and note why the control does not cover the path.

## Remediation
Load secrets from the environment or a secret manager; rotate anything committed. https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
