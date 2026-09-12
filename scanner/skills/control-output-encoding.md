---
name: control-output-encoding
description: What a real control for CWE-79/CWE-80 looks like (context-aware output encoding) and when it dominates the sink — for the Critic
cwes: [CWE-79, CWE-80]
role: critic
---
# Control: context-aware output encoding

## Control
The value is encoded for the exact output context by a template engine with auto-escape or by an escaping call immediately before the sink; HTML-only content goes through a strict sanitizer.

## Grep
- Go: `html/template` `Execute`, `template.HTMLEscapeString\(`, no `template.HTML\(`/`template.JS\(` on the tainted value
- Python: Django templates / Jinja `autoescape=True|select_autoescape`, `markupsafe.escape\(`, `json_script`
- Node/TS: Handlebars `{{ }}`, EJS `<%= %>`, Pug `#{}`, `escape-html`, `res.json\(`, `DOMPurify.sanitize\(`, `textContent =`

## Dominates when
1. the encoding matches the context of the sink (HTML body vs attribute vs JS string vs URL).
2. no escape hatch is applied to the same value later (`|safe`, `{{{ }}}`, `<%- %>`, `innerHTML`).
3. the sanitizer is applied to the exact string that reaches the sink.

## Not a control
- CSP headers alone.
- HTML-escape inside a `<script>` block or a `javascript:` URL.
- client-side validation.
- escaping in a different handler than the one that renders.

## Cite as
Call `check_dominance(file, sink_line, control_line)` first; only if it returns `dominates: true`, call `disprove_finding(finding_id, counter_evidence=[the control line(s) exactly as read], reason="<control> dominates the sink")`. Otherwise keep the finding and note why the control does not cover the path.

## Remediation
Encode for the output context with the template engine; never bypass auto-escape for user data. https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
