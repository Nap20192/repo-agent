---
name: wstg-athz-01-path-traversal
description: Use for CWE-22/CWE-98 (Directory Traversal File Include): the static evidence that confirms it and the controls that reject it (WSTG WSTG-ATHZ-01)
cwes: [CWE-22, CWE-98]
wstg: WSTG-ATHZ-01
top10: A01:2025
---
# WSTG-ATHZ-01 — Directory Traversal File Include (static verification)

Objective: find file operations whose path is built from request data.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: a filename, template name, language code or path segment from the request.
2. **Sink**: `os.Open(filepath.Join(base, name))`, `open(os.path.join(base, name))`, `fs.readFile(path.join(root, name))`, `res.sendFile(`, `send_file(`, `include`/`require(user)`.
3. **Missing control**: no canonicalization + base-directory check between source and sink; no id→path mapping; no filename allow-list.

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- the resolved path (`filepath.EvalSymlinks`/`Abs`, `os.path.realpath`, `path.resolve`) is checked to start with the base before the open.
- Go `os.OpenInRoot`/`os.Root`, `http.Dir`, Flask `send_from_directory`, `express.static` serve the file.
- the user value is an id looked up in a server-side map, not a path.

## Not enough to confirm
- `filepath.Join(base, user)` or `path.join` alone: `..` is normalised but the result may leave `base` — not a control.
- `strings.Contains(p, "..")` / `replace('..', '')` are bypassable (encoding, `....//`).
- reading a file from a constant path is not traversal.

## Sinks by language
- Go: `os.Open`, `os.ReadFile`, `http.ServeFile`, `template.ParseFiles` with user parts.
- Python: `open(`, `send_file`, `os.path.join(base, user)`, `pathlib` without `resolve()` check.
- Node/TS: `fs.readFile`, `res.sendFile`, `path.join(root, req.query.f)`, `require(user)`.

## False-positive traps
- `secure_filename` on a full path strips directories and returns a name — it is a control only if the base is then fixed.

Cite `owasp:WSTG-ATHZ-01` in evidence. Reference: OWASP WSTG WSTG-ATHZ-01; prevention: https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
