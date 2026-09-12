---
name: control-parameterization
description: What a real control for CWE-89/CWE-943 looks like (SQL/NoSQL query parameterization) and when it dominates the sink — for the Critic
cwes: [CWE-89, CWE-943]
role: critic
---
# Control: SQL/NoSQL query parameterization

## Control
A prepared statement or query builder binds the tainted value in the same call that executes the query; identifiers (table, column, sort direction) only come from a literal switch/map whose default rejects; for NoSQL the user value is coerced to a scalar so it cannot carry operators.

## Grep
- Go: `.Query|QueryRow|Exec(Context)?\(.*(\$\d|\?)`, `Where\("[^"]*\?"`, sqlc-generated `q.Method(ctx, arg)`
- Python: `execute\(\s*["'][^"']*%s[^"']*["']\s*,\s*[\(\[\{]`, `\.raw\([^,]+,\s*\[`, `text\(.*\)\.bindparams`, ORM `.filter(`
- Node/TS: `\.query\(\s*[`'"][^`'"]*\$\d[^`'"]*[`'"]\s*,\s*\[`, `\.execute\([^,]+,\s*\[`, `knex\.raw\([^,]+,\s*\[`, `String(req.query.x)` before a Mongo filter

## Dominates when
1. the placeholder query text and the parameter list are in the very call at the anchor line.
2. no `+`, `fmt.Sprintf`, f-string, `%`, or template literal touches the query text before that call.
3. identifier fragments come from a literal allow-list whose default branch rejects.

## Not a control
- escaping (`mysql_real_escape_string`, quote doubling, `sanitize`).
- a WAF or an ORM import without the bound call at the sink.
- a safe sibling query in the same file.
- `%s` inside an f-string later passed to `execute` without params.

## Cite as
Call `check_dominance(file, sink_line, control_line)` first; only if it returns `dominates: true`, call `disprove_finding(finding_id, counter_evidence=[the control line(s) exactly as read], reason="<control> dominates the sink")`. Otherwise keep the finding and note why the control does not cover the path.

## Remediation
Use prepared statements with bound parameters; allow-list identifiers. https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
