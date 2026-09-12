---
name: wstg-injt-01-reflected-xss
description: Use for CWE-79/CWE-80 (Reflected Cross Site Scripting): the static evidence that confirms it and the controls that reject it (WSTG WSTG-INJT-01)
cwes: [CWE-79, CWE-80]
wstg: WSTG-INJT-01
top10: A05:2025
---
# WSTG-INJT-01 — Reflected Cross Site Scripting (static verification)

Objective: find request values that are written back into the response without context-aware encoding.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: a request value (query, body, header, path) or an upstream JSON field.
2. **Sink**: the value is written into HTML/JS/attribute output: `fmt.Fprintf(w, ...)`, `w.Write([]byte(x))`, `text/template`, `render_template_string` with an f-string, `res.send('<..' + x)`, `innerHTML =`.
3. **Missing control**: no encoding for the output context (HTML body, attribute, JS string, URL); or the template engine's auto-escape is bypassed (`template.HTML`, `|safe`, `mark_safe`, `{{{ }}}`, `<%- %>`).

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- the sink is a templating engine with auto-escape on for THIS context (`html/template`, Django/Jinja autoescape, Handlebars `{{ }}`).
- the value is escaped for the same context right before the sink (`template.HTMLEscapeString`, `markupsafe.escape`, `escape-html`).
- the response is not HTML (`res.json`, `application/json`, plain text) and the browser cannot render it.
- the reflected value is an integer/enum validated before use.

## Not enough to confirm
- a reflected value inside an HTML-escaped body: the classic `<script>` break is neutralised — report rejected unless another context (attribute/JS) is hit.
- CSP headers alone do not reject the finding (defense in depth, not the control).
- a value written to a log or a server-side file is not XSS (that is CWE-117/532).

## Sinks by language
- Go: `fmt.Fprint*`/`w.Write` with request data, `text/template` for HTML, `template.HTML(` / `template.JS(`.
- Python: `HttpResponse(x)`, `render_template_string`, `Markup(`, `mark_safe(`, `|safe`, `autoescape=False`.
- Node/TS: `res.send(str)`, `res.write(str)`, `innerHTML`, `document.write`, `dangerouslySetInnerHTML`, `<%- %>`, `{{{ }}}`.

## False-positive traps
- escaping for the wrong context (HTML-escape inside `<script>` or `href="javascript:`) looks like a control but is not.
- a sanitizer library on a different code path than the sink.

Cite `owasp:WSTG-INJT-01` in evidence. Reference: OWASP WSTG WSTG-INJT-01; prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
