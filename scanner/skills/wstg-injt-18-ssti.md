---
name: wstg-injt-18-ssti
description: Use for CWE-1336 (Server-side Template Injection): the static evidence that confirms it and the controls that reject it (WSTG WSTG-INJT-18)
cwes: [CWE-1336]
wstg: WSTG-INJT-18
top10: A05:2025
---
# WSTG-INJT-18 — Server-side Template Injection (static verification)

Objective: find templates whose source text (not just data) comes from the request.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: a request value, stored user field, or uploaded file used as the template body.
2. **Sink**: `template.New().Parse(userStr)`, `Template(userStr).render()`, `render_template_string(userStr)`, `Handlebars.compile(userStr)`, `ejs.render(userStr)`, `pug.compile(userStr)`.
3. **Missing control**: user data reaches the template source instead of the template context; no sandboxed engine.

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- the template source is a file or constant and user data is only passed as context variables.
- a logic-less/sandboxed engine is used for user templates (Mustache without helpers, Jinja2 `SandboxedEnvironment`) and the risk is documented.
- the string is escaped/wrapped as data before compilation (e.g. `{{ }}` around a variable, not the whole template).

## Not enough to confirm
- passing user data into `render(template_file, data)` is not SSTI.
- a sandboxed Jinja environment reduces impact but does not remove the finding: report uncertain with the sandbox cited.

## Sinks by language
- Go: `template.Parse(user)`, `template.Must(template.New(...).Parse(v))`.
- Python: `render_template_string`, `Template(user)`, `Environment().from_string(user)`.
- Node/TS: `ejs.render(user)`, `Handlebars.compile(user)`, `pug.compile(user)`, `nunjucks.renderString(user)`.

## False-positive traps
- an f-string that builds a template from user input before `render_template_string` is the sink line.

Cite `owasp:WSTG-INJT-18` in evidence. Reference: OWASP WSTG WSTG-INJT-18; prevention: https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html
