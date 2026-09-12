---
name: wstg-injt-11-code-injection
description: Use for CWE-94/CWE-95 (Code Injection): the static evidence that confirms it and the controls that reject it (WSTG WSTG-INJT-11)
cwes: [CWE-94, CWE-95]
wstg: WSTG-INJT-11
top10: A05:2025
---
# WSTG-INJT-11 — Code Injection (static verification)

Objective: find places where request data is evaluated as code.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: a request value, uploaded file content, or a stored user field.
2. **Sink**: `eval(`, `new Function(`, `vm.runInNewContext(`, `exec(`/`eval(` in Python, `compile(`, template compilation of user strings, dynamic `require(userPath)`, `importlib.import_module(user)`.
3. **Missing control**: no allow-list of accepted expressions, no safe evaluator (AST-restricted), no sandbox.

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- the evaluated string is a constant or chosen from a literal map.
- a restricted evaluator is used (`ast.literal_eval`, a whitelisted expression parser) instead of `eval`.
- the value is validated by a strict pattern that excludes code characters before evaluation.

## Not enough to confirm
- `eval` on a constant is hygiene, not a finding.
- `JSON.parse`/`json.loads` are not code execution.
- a sandbox (`vm.runInNewContext`) is not a control: escapes are known — report the finding, note the sandbox.

## Sinks by language
- Go: plugin loading from user paths, `otto`/`goja` `RunString(user)`, `text/template` `Parse(user)`.
- Python: `eval(`, `exec(`, `compile(`, `pickle.loads`, `__import__(user)`.
- Node/TS: `eval(`, `new Function(`, `vm.runIn*`, `setTimeout(str)`, `require(user)`.

## False-positive traps
- `eval` inside a test file or a build script is out of scope (production code only).

Cite `owasp:WSTG-INJT-11` in evidence. Reference: OWASP WSTG WSTG-INJT-11; prevention: https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html
