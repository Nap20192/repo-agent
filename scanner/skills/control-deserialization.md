---
name: control-deserialization
description: What a real control for CWE-502 looks like (safe deserialization) and when it dominates the sink — for the Critic
cwes: [CWE-502]
role: critic
---
# Control: safe deserialization

## Control
Untrusted data is parsed with a data-only format (JSON, XML DTO) or a loader that restricts classes (`yaml.safe_load`, `SafeLoader`, `RestrictedUnpickler` with an allow-list); native serializers only on data signed and verified first.

## Grep
- Go: `json\.Unmarshal` / `encoding/gob` only on trusted channels
- Python: `yaml\.safe_load|SafeLoader|json\.loads`, `RestrictedUnpickler`
- Node/TS: `JSON\.parse`

## Dominates when
1. the safe loader is the one at the sink (not a safe call elsewhere).
2. signature verification precedes the native deserialize on the same buffer.

## Not a control
- `pickle.loads` behind an HMAC that uses a hard-coded key.
- input length limits.
- try/except around the load.

## Cite as
Call `check_dominance(file, sink_line, control_line)` first; only if it returns `dominates: true`, call `disprove_finding(finding_id, counter_evidence=[the control line(s) exactly as read], reason="<control> dominates the sink")`. Otherwise keep the finding and note why the control does not cover the path.

## Remediation
Use data-only formats; if native serialization is required, sign and verify first. https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
