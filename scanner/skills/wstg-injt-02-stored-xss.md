---
name: wstg-injt-02-stored-xss
description: Use for CWE-79 (Stored Cross Site Scripting): the static evidence that confirms it and the controls that reject it (WSTG WSTG-INJT-02)
cwes: [CWE-79]
wstg: WSTG-INJT-02
top10: A05:2025
---
# WSTG-INJT-02 — Stored Cross Site Scripting (static verification)

Objective: find input that is persisted and later rendered to other users without encoding.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: a request value written to a store (DB insert/update, file, cache, queue) — cite the write.
2. **Sink**: a later read of the same field rendered into HTML/JS: the render line is the anchor; the storage write is the first hop.
3. **Missing control**: no encoding at render time; storage-time "sanitization" only (bypassable, and other readers may render raw).

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- the render sink auto-escapes for the context (see WSTG-INJT-01).
- a strict HTML sanitizer (DOMPurify / bluemonday / bleach) is applied at render time or the field is a plain-text type.
- the field is never rendered into a browser context (API-only, exported to CSV with quoting).

## Not enough to confirm
- storing raw HTML is not a finding by itself: you must cite the render sink.
- escaping on write does not prove safety: cite the read path that renders it.
- admin-only views still count (WSTG treats stored XSS in admin panels as high impact); note the audience.

## Sinks by language
- Go: `html/template` with `template.HTML(field)`, `w.Write(field)`.
- Python: `|safe` on model fields, `mark_safe(obj.bio)`.
- Node/TS: `res.send(row.comment)`, `innerHTML = data.text`, `{{{ body }}}`.

## False-positive traps
- a `rich text` field is not automatically a vulnerability: check the sanitizer allow-list, not its presence.

Cite `owasp:WSTG-INJT-02` in evidence. Reference: OWASP WSTG WSTG-INJT-02; prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
