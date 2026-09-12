---
name: control-path-traversal
description: What a real control for CWE-22/CWE-98/CWE-434 looks like (path containment) and when it dominates the sink — for the Critic
cwes: [CWE-22, CWE-98, CWE-434]
role: critic
---
# Control: path containment

## Control
The full path is canonicalized (symlinks resolved) and then required to start with the base directory, before any open/read/send; or the user never supplies a path at all (id → path map).

## Grep
- Go: `filepath\.(Clean|Abs|EvalSymlinks)` followed by `strings\.HasPrefix\(.*base` or `filepath\.Rel`; `os\.OpenInRoot|os\.Root`; `http\.Dir\(`
- Python: `os\.path\.realpath\(` + `startswith\(`, `\.resolve\(\)\.is_relative_to\(`, `secure_filename\(`, `send_from_directory\(`
- Node/TS: `path\.resolve\(` + `startsWith\(.*path\.sep`, `express\.static\(`

## Dominates when
1. the containment check runs on the resolved path.
2. it runs before the sink on the same variable.
3. the base is a constant or config value.

## Not a control
- `filepath.Join(base, user)` / `path.join` alone.
- `strings.Contains(p, "..")`, `replace('..', '')`.
- checks done before URL-decoding.
- an extension allow-list without containment.

## Cite as
Call `check_dominance(file, sink_line, control_line)` first; only if it returns `dominates: true`, call `disprove_finding(finding_id, counter_evidence=[the control line(s) exactly as read], reason="<control> dominates the sink")`. Otherwise keep the finding and note why the control does not cover the path.

## Remediation
Resolve the path and reject anything outside the base directory; prefer id→path mapping. https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
