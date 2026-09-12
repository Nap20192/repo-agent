---
name: wstg-injt-05-sqli
description: Use for CWE-89/CWE-943 (SQL Injection): the static evidence that confirms it and the controls that reject it (WSTG WSTG-INJT-05)
cwes: [CWE-89, CWE-943]
wstg: WSTG-INJT-05
top10: A05:2025
---
# WSTG-INJT-05 — SQL Injection (static verification)

Objective: identify SQL/NoSQL injection points and how the query is built.

## Evidence you must find
Cite every line; all three are required for `confirmed`.
1. **Source**: request params/body/headers/cookies, path segments, upstream JSON, queue payloads — cite the ingress line.
2. **Sink**: the query text is assembled by string construction and executed: `db.Query(fmt.Sprintf(...))`, `+ name +`, `cursor.execute(f"...")`, `knex.raw(str)`, `sequelize.query(str)`, `$where`, `find(userObject)`.
3. **Missing control**: no bind parameter for the tainted fragment; identifiers (table/column/ORDER BY) not chosen from a literal allow-list; no query builder between source and sink.

## Counter-facts that reject
Any one of these, if it dominates the sink on the traced path, makes the claim false:
- placeholders bind the value in the very call at the sink (`$1`/`?`/`:name` + args, `execute(sql, (v,))`, `query(sql, [v])`, sqlc/sqlx named params, ORM `.where(col=v)`).
- the tainted fragment is an identifier chosen from a literal allow-list with a rejecting default.
- the value is converted to a number before concatenation (`strconv.Atoi`, `int()`, `parseInt` with NaN check).
- the "input" is a constant, config, or application-generated value that no request can reach.

## Not enough to confirm
- a raw query string with no untrusted source reaching it is hygiene: reject with that reason.
- a scanner hit on `Sprintf` that only builds the static part of the query.
- escaping helpers (`mysql.escape`, quote doubling) neutralise the quote-break path: report uncertain unless a second-order use exists.

## Sinks by language
- Go: `database/sql` `Query|QueryRow|Exec|Prepare`, `sqlx.*`, `gorm.Raw|Exec|Where(string)`, `pgx.*`.
- Python: `cursor.execute`, `executemany`, `sqlalchemy.text`, `session.execute(str)`, Django `raw()`, `extra()`.
- Node/TS: `knex.raw`, `sequelize.query`, `pool.query(str)`, Mongo `$where`, `collection.find(req.body)` (operator injection, CWE-943).

## False-positive traps
- ORM usage in the file does not prove the sink is parameterized: check the exact call.
- a safe sibling query next to the vulnerable one.

Cite `owasp:WSTG-INJT-05` in evidence. Reference: OWASP WSTG WSTG-INJT-05; prevention: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
