# OWASP WSTG → repo-agent2: integration design (R&D card 23, WSTG member)

*Sources read in place: `~/tmp/repos/owasp-wstg` (v4.2+ working tree, `checklists/checklist.json` = 113 tests,
`document/4-Web_Application_Security_Testing/*` = 139 pages, avg 8 KB, max 45 KB; LICENSE = CC BY-SA 4.0).
Our side: `scanner/adapter/owasp.py`, `scanner/app/instructions.py`, `scanner/skills/`, `scanner/core/rules.py`,
`scanner/adapter/tools.py`, `scanner/app/reconcile.py`, `scanner/adapter/store.py`.*

Premise: WSTG is written for a tester with a browser. We have no DAST. The only WSTG content that pays for itself
here is (a) the **taxonomy** (stable ids the whole pipeline can carry), (b) the **objectives** (what a test proves),
and (c) the parts of "How to Test" that translate into **static evidence** (a source, a sink, a missing control)
and **counter-facts** (a control that, when present, rejects the claim). Payload lists, tooling and exploitation
steps are noise for us and must not enter prompts.

## 1. Inventory: what is static-verifiable

| Category | Tests | Static from source | Notes |
|---|---|---|---|
| INFO (01) | 10 | 2 partial | INFO-06 entry points and INFO-10 architecture are what Architect already does; the rest is recon (DAST) |
| CONF (02) | 13 | 6 | CONF-04 unreferenced/backup files, CONF-06 HTTP methods (router config), CONF-07 HSTS, CONF-09 file permission (gosec G30x), CONF-11 cloud storage (IaC), CONF-12 CSP / CONF-14 headers (middleware config) — verifiable when config lives in code; CONF-01/02/05/10/13 need a live host |
| IDNT (03) | 5 | 2 | IDNT-01 role definitions (authz model), IDNT-04 enumeration (differing error messages in code); provisioning flows are business logic |
| ATHN (04) | 11 | 5 | ATHN-01 credentials over plaintext (http server / links), ATHN-02 default credentials (gitleaks + constants), ATHN-03 lockout (rate-limit code present?), ATHN-04 bypass (auth middleware ordering), ATHN-09 reset flow (token entropy, expiry), ATHN-11 MFA; the rest needs a browser |
| ATHZ (05) | 5 | 5 | all five: path traversal (ATHZ-01), bypass (ATHZ-02), privesc (ATHZ-03), IDOR (ATHZ-04), OAuth (ATHZ-05) — with the Domain-Map caveat: static proves the check is *absent*, a human decides it was *required* |
| SESS (06) | 11 | 5 | SESS-02 cookie attributes, SESS-03 fixation (session regenerated on login?), SESS-05 CSRF (middleware), SESS-07 timeout (config), SESS-10 JWT (alg none, key handling) |
| INJT (07) | 23 | 16 | everything with a sink: 01/02 XSS, 05 SQL (+ 05.6 NoSQL, 05.7 ORM), 06 LDAP, 07 XML/XXE, 08 SSI, 09 XPath, 10 IMAP/SMTP, 11 code (+ 11.1 file inclusion), 12 command, 13 format string, 15 response splitting, 17 host header, 18 SSTI, 19 SSRF, 20 mass assignment, 22 prototype pollution, 23 deserialization. DAST-only: 03 verb tampering, 04 HPP, 14 incubated, 16 smuggling, 21 CSV |
| ERRH (08) | 2 | 2 | verbose error handlers, stack traces in responses (config + code) |
| CRYP (09) | 4 | 3 | CRYP-01 TLS config in code, CRYP-03 unencrypted channels, CRYP-04 weak primitives (gosec G40x/G50x); CRYP-02 padding oracle is DAST |
| BUSL (10) | 10 | 3 partial | BUSL-01 data validation, BUSL-08/09 upload types — the rest is behavioural |
| CLNT (11) | 14 | 5 | CLNT-01 DOM XSS, 04 open redirect, 07 CORS (server config), 09 clickjacking (headers), 13 XSSI — with a JS index only |
| APIT (12) | 5 | 3 | APIT-02 BOLA (= ATHZ-04 for APIs), APIT-03 excessive data exposure (serializers), APIT-04 BFLA (= ATHZ-02); APIT-01/99 need traffic |

**~57 of 113 tests are static-verifiable**, 16 of them in INJT alone. That is the set worth turning into skills;
the other 56 are not "unsupported", they are simply not our product (no DAST — a documented stage-2 item).

## 2. CWE → WSTG map: additions to `owasp.py`

Today 18 entries. CWEs our scanners actually emit (gosec rule table, semgrep `auto` on bakery/NodeGoat/DVWA/mixed,
gitleaks, osv) and the proposed target. Confidence: **H** = WSTG names the class, **M** = closest test, **L** = best
effort, better than a miss.

| CWE | Emitted by | Proposed WSTG | Conf | Top10 2021 | Cheat sheet |
|---|---|---|---|---|---|
| CWE-20 | semgrep | WSTG-INJT-* by sink, else WSTG-BUSL-01 | M | A03 | Input_Validation |
| CWE-88 | gosec G107 | WSTG-INJT-19 (SSRF) | H | A10 | Server_Side_Request_Forgery_Prevention |
| CWE-90 | semgrep | WSTG-INJT-06 (LDAP) | H | A03 | LDAP_Injection_Prevention |
| CWE-113 | semgrep | WSTG-INJT-15 (response splitting) | H | A03 | — |
| CWE-118 | gosec G601/G602 | (memory safety, no WSTG test) | — | — | — (severity cap LOW in calibrate) |
| CWE-190 | gosec G109/G115 | WSTG-INJT-13 (closest: numeric handling) — better: none | L | A04 | — |
| CWE-200 | gosec G102/G108, semgrep | WSTG-ERRH-01 / WSTG-INFO-05 | M | A01 | Error_Handling |
| CWE-209 | semgrep | WSTG-ERRH-02 (stack traces) | H | A05 | Error_Handling |
| CWE-242 | gosec G103 (unsafe) | none | — | — | — |
| CWE-276 | gosec G301/302/306 | WSTG-CONF-09 (file permission) | H | A05 | — |
| CWE-295 | gosec G402, semgrep | WSTG-CRYP-01 (TLS) | H | A02 | Transport_Layer_Security |
| CWE-310/326/327/328 | gosec G401/G405/G50x, semgrep | WSTG-CRYP-04 (weak primitives) | H | A02 | Cryptographic_Storage |
| CWE-319 | semgrep (http links/servers) | WSTG-CRYP-03 (unencrypted channels), ATHN-01 for credentials | H | A02 | Transport_Layer_Security |
| CWE-322 | gosec G106 (InsecureIgnoreHostKey) | WSTG-CRYP-01 | M | A02 | — |
| CWE-338 | gosec G404 | WSTG-CRYP-04 | H | A02 | Cryptographic_Storage |
| CWE-346/942 | semgrep (CORS) | WSTG-CLNT-07 | H | A05 | — |
| CWE-384 | semgrep | WSTG-SESS-03 (fixation) | H | A07 | Session_Management |
| CWE-400/409 | gosec G110/G112 | WSTG-BUSL-05 / (DoS, no exact test) | L | A05 | Denial_of_Service |
| CWE-434 | semgrep | WSTG-BUSL-08/09 (uploads) | H | A04 | File_Upload |
| CWE-522 | semgrep (cookie name, creds) | WSTG-SESS-01 / ATHN-07 | M | A07 | Session_Management |
| CWE-548 | semgrep (dir listing) | WSTG-CONF-04 | M | A05 | — |
| CWE-614/1004 | semgrep (cookie flags) | WSTG-SESS-02 | H | A05 | Session_Management |
| CWE-676 | gosec G114 (no timeouts) | none (DoS hygiene) | — | A05 | — |
| CWE-693/1021 | semgrep (headers, clickjacking) | WSTG-CONF-12/14, WSTG-CLNT-09 | H | A05 | HTTP_Headers |
| CWE-697 | semgrep (loose comparison) | WSTG-ATHN-04 when in auth, else none | L | A07 | — |
| CWE-703 | gosec G104 | none (hygiene; cap LOW) | — | — | — |
| CWE-732 | semgrep (docker/no-new-privileges) | WSTG-CONF-02 | M | A05 | Docker_Security |
| CWE-770 | semgrep | none | — | A05 | — |
| CWE-915 | semgrep | WSTG-INJT-20 (mass assignment) | H | A08 | Mass_Assignment |
| CWE-916 | semgrep (weak hash for pw) | WSTG-CRYP-04 | H | A02 | Password_Storage |
| CWE-943 | semgrep | WSTG-INJT-05 (05.6 NoSQL) | H | A03 | — |
| CWE-1004 | semgrep | WSTG-SESS-02 | H | A05 | Session_Management |
| CWE-1321 | semgrep | WSTG-INJT-22 (prototype pollution) | H | A08 | Prototype_Pollution_Prevention |
| CWE-1333 | semgrep (ReDoS) | none (DoS) | — | A05 | Regular_Expression_Security |
| CWE-1336 | semgrep (SSTI) | WSTG-INJT-18 | H | A03 | Server_Side_Template_Injection |
| CWE-1357 | semgrep (mutable action tags) | none — supply chain, not an app test | — | A08 | — |
| osv (no CWE) | osv-scanner | WSTG-CONF-01 objective 2 "known vulnerabilities due to unmaintained software" | M | A06 | Vulnerable_Dependency_Management |
| CWE-798 | gitleaks, semgrep | keep WSTG-CONF-04? No: **WSTG-ATHN-02 (default credentials)** for creds, CONF-04 for committed key files | M | A07 | Secrets_Management |

Also fix existing entries: `CWE-22 → WSTG-ATHZ-01` is right (Directory Traversal File Include) but its cheat
sheet should be `Input_Validation` (path canonicalisation), not `File_Upload`; add `CWE-79 → WSTG-INJT-02`
when the sink is a stored write (leave 01 as default); `CWE-352 → WSTG-SESS-05` stays.

Second output the map should give (currently missing): **Top10 2025 ids**. The WSTG pages already reference
`A01:2025`; Top10 2021 is what our tables and `_TOP10` carry. Carry both, prefer 2025 in reports once
`owasp-Top10` corpus has the 2025 CWE lists (check `~/tmp/repos/owasp-Top10/2025/`).

## 3. WSTG "How to Test" → Investigator checklists (skill format)

What to extract per test, in this order, in our own words (see §4 on licence):

1. **Objective** — one sentence from `checklist.json[].objectives` (facts, safe to quote).
2. **Static evidence you must find** — the triple our gate already demands: *source* (where untrusted data
   enters), *sink* (the dangerous call at the anchor), *missing control* (the check WSTG says must exist).
3. **Counter-facts that reject** — controls whose presence *on the path* makes the claim false. These become
   the Critic's disproof routes and the Investigator's "rejected" reasons.
4. **Not enough to confirm** — traps WSTG warns about, restated as "this alone is not a finding".
5. **Language sinks** — a short sink list per language we index (Go / Python / JS-TS), so the Investigator
   knows what to grep and what `lsp_references` to open.

Proposed skill file layout (drop-in for `scanner/skills/`, parsed by `scanner/adapter/skills.py`; add the
`cwes:` and `wstg:` frontmatter keys the loader already anticipates — `skills.py:13` "add per-skill cwes
frontmatter if classes multiply"):

```markdown
---
name: wstg-injt-05-sqli
description: Use when a hypothesis is CWE-89/CWE-943 (SQL/NoSQL injection): what static evidence confirms it, which controls reject it
cwes: [CWE-89, CWE-943]
wstg: WSTG-INJT-05
top10: A03:2021
---
```

### Example 1 — `wstg-injt-05-sqli.md`

```markdown
---
name: wstg-injt-05-sqli
description: Use when a hypothesis is CWE-89/CWE-943 (SQL/NoSQL injection): what static evidence confirms it, which controls reject it
cwes: [CWE-89, CWE-943]
wstg: WSTG-INJT-05
top10: A03:2021
---
# WSTG-INJT-05 — SQL Injection (static verification)

Objective (WSTG): identify SQL injection points and assess the severity of the injection and the level of
access that can be achieved through it.

## Evidence you must find (all three, cite each line)
1. **Source**: untrusted input enters — request params/body/headers/cookies, path segments, upstream JSON,
   message-queue payloads. Cite the ingress line (`r.URL.Query().Get`, `request.args`, `req.body`, `ctx.Param`).
2. **Sink**: the query is built by *string construction* and executed — `db.Query/Exec/Raw(fmt.Sprintf|+)`,
   `cursor.execute(f"…")`, `knex.raw(...)`, `sequelize.query(...)`, `$where`, `collection.find({$where})`.
   The anchor line is the sink; quote it exactly.
3. **Missing control**: no parameter binding for the tainted fragment, no allowlist when the fragment is an
   identifier (table/column/ORDER BY), no ORM query builder between source and sink.

## Counter-facts that REJECT (any one, if it dominates the sink on the traced path)
- Placeholders bind the tainted value: `$1`/`?`/`:name` with the value passed as an argument, `sqlc`/`sqlx`
  named params, ORM `.where(col=val)`, `cursor.execute(sql, (val,))`.
- The tainted fragment is an identifier chosen from an allowlist (`if col not in ALLOWED: reject`).
- The value is cast to a number before concatenation (`strconv.Atoi`, `int()`, `parseInt` with NaN check).
- The "input" is a constant, config, or a value produced by the application itself (not attacker-reachable).

## Not enough to confirm
- A raw query string alone (no untrusted source reaches it) — hygiene, report `rejected` with the reason.
- A scanner match on `Sprintf` that builds only the *static* part of the query.
- Escaping helpers (`mysql.escape`, manual quote doubling): weaker than binding but they do neutralise the
  quote-break path — report `uncertain` unless a second-order use exists.

## Sinks by language (grep / lsp_references targets)
- Go: `database/sql` `Query|QueryRow|Exec|Prepare`, `sqlx.*`, `gorm.Raw|Exec|Where(string)`, `pgx.*`.
- Python: `cursor.execute`, `executemany`, `sqlalchemy.text`, `session.execute(str)`, Django `raw()`, `extra()`.
- JS/TS: `knex.raw`, `sequelize.query`, `pool.query(str)`, `mongoose` `$where`, `collection.find` with
  user-shaped objects (NoSQL operator injection, CWE-943).

Cite `owasp:WSTG-INJT-05` in evidence. Prevention reference for the report: SQL_Injection_Prevention_Cheat_Sheet.
```

### Example 2 — `wstg-athz-04-idor.md`

```markdown
---
name: wstg-athz-04-idor
description: Use when a hypothesis is CWE-639/CWE-284/CWE-862/CWE-863 (IDOR, missing object-level authorization): what static evidence confirms it, which controls reject it
cwes: [CWE-639, CWE-284, CWE-862, CWE-863]
wstg: WSTG-ATHZ-04
top10: A01:2021
---
# WSTG-ATHZ-04 — Insecure Direct Object References (static verification)

Objective (WSTG): identify points where object references occur and assess whether the access control
measures are vulnerable to IDOR.

WSTG's four shapes, restated for source reading:
1. a parameter is used directly to retrieve a **database record** (`invoice=12345`);
2. a parameter selects the **target of an operation** (`changepassword?user=`);
3. a parameter names a **file system resource** (`img=img00011`);
4. a parameter selects **application functionality** (`menuitem=12`).

## Evidence you must find
1. **Source**: the object identifier comes from the request (path param, query, body field), not from the
   session/principal.
2. **Sink**: the identifier is used *as the whole key* of a lookup/update/delete/read — `WHERE id = $1` with
   no tenant/owner predicate, `Order.get(id)`, `os.Open(base + name)`, `router[menuitem]`.
3. **Missing control**: between source and sink there is no comparison of the object's owner with the
   authenticated principal (`order.UserID != session.UserID`), no scoped query (`WHERE id=$1 AND user_id=$2`),
   no role gate for the operation, and no middleware that injects the scope.
   Call `consult_domain(<entity>)` and cite `domain:<entity>`: the gate requires it.

## Counter-facts that REJECT
- The lookup is scoped by the principal (`AND user_id = current`), or the id is *derived* from the session.
- An ownership check dominates the sink (`if obj.Owner != me { 403 }` before any use of the object).
- A policy/ABAC middleware wraps the route and its rule names this object type.
- The object is public by design (the Domain Map says no owner field) — that is a business rule, not a hole.

## Not enough to confirm
- A missing check on a *read* of a resource that is public for every authenticated user.
- An admin-only route: missing owner check is fine if a role gate exists (that is ATHZ-02, not 04).
- Sequential/guessable ids alone (WSTG notes ids may be split across parameters — indirect references do not
  fix the missing check, and random ids do not create one).

## Sinks by language
- Go: handlers reading `chi.URLParam|mux.Vars|c.Param` → `repo.Get(id)`; `os.Open(filepath.Join(dir, name))`.
- Python: `Model.objects.get(pk=request.GET['id'])`, `db.session.get(Model, id)`, `send_file(path)`.
- JS/TS: `req.params.id` → `Model.findById`, `collection.findOne({_id})`, `res.sendFile`.

Cite `owasp:WSTG-ATHZ-04` and `domain:<entity>` in evidence. Prevention: Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet, Authorization_Cheat_Sheet.
```

### Example 3 — `wstg-injt-19-ssrf.md`

```markdown
---
name: wstg-injt-19-ssrf
description: Use when a hypothesis is CWE-918/CWE-88 (server-side request forgery, variable URL): what static evidence confirms it, which controls reject it
cwes: [CWE-918, CWE-88]
wstg: WSTG-INJT-19
top10: A10:2021
---
# WSTG-INJT-19 — Server-Side Request Forgery (static verification)

Objective (WSTG): identify SSRF injection points, decide whether they are exploitable, assess severity.

## Evidence you must find
1. **Source**: a URL, host, port or path fragment comes from the request (`url=`, `callback=`, `webhook`,
   `image_url`, PDF/HTML render inputs, XML entities, OpenAPI `$ref`s).
2. **Sink**: the server opens a connection with it — `http.Get(u)`, `http.NewRequest(_, u)`, `requests.get(u)`,
   `urllib.request.urlopen`, `fetch(u)`, `axios.get(u)`, `net.Dial`, and indirect ones: PDF generators,
   `wget`/`curl` via `exec`, image fetchers, SSRF through redirects (client follows `Location`).
3. **Missing control**: no allowlist of hosts/schemes, no resolution-then-check of the IP (link-local
   169.254.169.254, loopback, RFC1918), redirects followed, or the check runs on the string but the client
   re-resolves (DNS rebinding — note, do not prove statically).

## Counter-facts that REJECT
- Destination is a constant or chosen from an allowlist; user input only selects among fixed entries.
- Scheme + host are validated against an allowlist *and* redirects are disabled (`CheckRedirect` returns
  `ErrUseLastResponse`, `allow_redirects=False`, `redirect: 'manual'`).
- Resolved IP is checked against private/link-local ranges *before* the connection (custom `DialContext`).
- Request goes through an egress proxy that enforces the policy (cite its config).

## Not enough to confirm
- A variable URL built from config/env only (gosec G107 fires on any variable; that is CWE-88 noise).
- A denylist of hosts: bypassable (decimal IPs, `0x7f000001`, IPv6 mapped), report `confirmed` only if the
  source is attacker-controlled; mention the bypass class, do not enumerate payloads.
- Requests to an *external* fixed API with a user-supplied *path* only: usually not SSRF, possibly
  path/parameter injection — different CWE.

## Sinks by language
- Go: `net/http` Get/Post/Do with non-constant URL, `net.Dial*`, `httputil.ReverseProxy` director.
- Python: `requests.*`, `httpx.*`, `urllib.request.urlopen`, `aiohttp.ClientSession.get`.
- JS/TS: `fetch`, `axios`, `http.request`, `got`, `node-fetch`; headless browsers / PDF renderers.

Cite `owasp:WSTG-INJT-19` in evidence. Prevention: Server_Side_Request_Forgery_Prevention_Cheat_Sheet.
```

Why this shape works with the gate: every bullet in "Evidence you must find" maps to an `evidence` line the
`report_finding` gate can check against code, and every "counter-fact" is exactly the `counter_evidence`
`disprove_finding` needs. The existing Strix skills stay (attack-surface knowledge); the WSTG skills are the
*verdict discipline* per class. `skill_for()` should return the WSTG skill first and the Strix one second
(payload key `skills: [...]` instead of a single `skill`).

## 4. Corpus-backed `consult_owasp`

**What to return** (size budget ≈ 1.5 KB per call, the model reads it once per hypothesis):
- `wstg_id`, `name`, `objectives` (from `checklist.json` — 1–3 lines), `top10` (2021 and 2025 when known),
  `cheat_sheet` URL, `reference` URL;
- `how_to_static`: **our** 5-line extract per test (from the skill's "Evidence you must find" section), not the
  page's How-to — the page is 5–45 KB of payloads and browser steps;
- `remediation`: the page's `## Remediation` paragraph, first 400 chars (SQLi's is three links, IDOR has none —
  fall back to the cheat-sheet name).

**Index**: parse `checklists/checklist.json` (113 tests: id, name, objectives, reference) deterministically at
import; map id → page path by the numeric prefix in the filename (`07-Injection/05-SQL_Injection.md` ⇐
`WSTG-INJT-05`; category codes → directories: INFO→01, CONF→02, IDNT→03, ATHN→04, ATHZ→05, SESS→06,
INJT→07, ERRH→08, CRYP→09, BUSL→10, CLNT→11, APIT→12). Note `checklist.md` names lag `checklist.json`
(e.g. INFO-04); use JSON only. Two ids have gaps (CONF-08, CLNT-08 retired) — never invent them.

**Vendor vs clone.** WSTG is CC BY-SA 4.0: any vendored extract must carry attribution (title, OWASP,
licence link, "changes made") and stays share-alike, i.e. the extract file itself is CC BY-SA. Objectives
and ids are short facts; the *How-to* prose is expressive. Decision:
- vendor **only** `checklist.json`-derived data (ids, names, objectives, references) as
  `scanner/owasp/wstg-checklist.json` + `NOTICE` line — ~40 KB, deterministic, no network;
- keep skills in our own words (ideas, not text) citing the WSTG id — no licence propagation into the
  skills corpus (which is Apache-2.0 via Strix);
- `OWASP_DIR` / `OWASP_CLONE_DIR` (as in git-agent3) optional for the `remediation` excerpt and Cheat Sheet
  bodies; without it, return the URL. Do not clone at scan time by default (network, 30 s, supply chain).

## 5. How WSTG ids flow today, and the gaps

| Step | Today | Gap |
|---|---|---|
| ThreatModeler | `Threat.wstg_id` filled by the model ("call consult_owasp to pin it") | `consult_owasp` only answers for the 18 mapped CWEs; unknown CWE → error → the model invents nothing but also carries no id |
| Reconciler | synthetic anchor `rule_id = wstg_id or "threat"` | scanner anchors (gosec/semgrep) have no WSTG id at all; the Hypothesis has no `wstg_id` field, so it is lost between anchor and Investigator payload |
| Investigator | instruction: consult refs `owasp:` allowed before code lines | `owasp:` is never required, so it is rarely cited; the skill it loads is the Strix class skill, not a WSTG checklist |
| Critic | loads `counterevidence`; disproof routes are Shannon's | no per-test counter-facts (the WSTG skill §3 would give them) |
| Reporter / SARIF | `ruleId = cwe`, `properties.calibration` | no `wstg`, no Top10 in SARIF; `summary.json` has none either |

Fix path (ordered by cheapness): (a) `anchors → wstg` derived from the CWE table at report time (pure
function, no model), (b) `Hypothesis.wstg_id` populated by Reconciler from the threat or the CWE table and
put in the verify payload, (c) SARIF `properties.wstg`, `properties.top10`, and SARIF **taxonomies** block
(SARIF has first-class `taxonomies` for exactly this: one `toolComponent` "OWASP WSTG" with `taxa` ids), (d)
make `owasp:` **required** only for classes where the WSTG test is the definition of done (authz, session,
config) — never for taint classes, where the code path is the proof.

## 6. Ranked proposals

| # | Proposal | Precision / recall effect | Effort | Files | Risk |
|---|---|---|---|---|---|
| 1 | WSTG verdict skills for the 16 static INJT tests + ATHZ-01/02/04 + SESS-02/03/05 + CRYP-04 (≈25 files, §3 format, `cwes:`/`wstg:` frontmatter), `skill_for` → list, payload `skills` | precision ↑ (explicit counter-facts → fewer confirmed FPs like the `/safe` case), recall ↔ | M | scanner/skills/wstg-*.md, scanner/adapter/skills.py, scanner/app/graph.py | low; prompt size +1.5 KB per hypothesis |
| 2 | Extend `owasp.py` map to every emitted CWE (§2 table, ≈35 rows) + Top10 2025 | recall of *methodology* refs ↑, fewer `consult_owasp` errors for ThreatModeler | S | scanner/adapter/owasp.py, tests/test_owasp.py | low |
| 3 | `wstg_id` end-to-end: Hypothesis field, Reconciler fill, SARIF `properties.wstg/top10` + `taxonomies` | reporting quality; enables coverage-by-WSTG metric | S | core/types.py, app/reconcile.py, adapter/store.py | low |
| 4 | Vendor `checklist.json` extract + `consult_owasp` returns objectives/how_to_static/remediation | ThreatModeler grounds threats on real test ids (fewer invented ids); Critic gets remediation for "expected control" | S | scanner/owasp/wstg-checklist.json, adapter/owasp.py, NOTICE | licence: attribution file required |
| 5 | Coverage report: which static-verifiable WSTG tests had ≥1 hypothesis (from anchors + threats) vs none — the Reconciler `coverage()` idea at the WSTG level; surfaces the classes scanners never see (NodeGoat IDOR/NoSQL) | recall ↑ where it matters (design flaws); explains "what we did not look at" in summary | M | app/reconcile.py, adapter/store.py | the ThreatModeler must be asked to cover uncovered *tests*, not only entry points → prompt change |
| 6 | Critic disproof routes per WSTG test (counter-facts from the skills) instead of the generic five | precision ↑ | S once #1 exists | app/instructions.py | none |
| 7 | Semgrep rule packs by WSTG category instead of `--config auto` (`p/owasp-top-ten`, `p/sql-injection`, `p/xss`, `p/command-injection`, `p/secrets`) — cuts the CONF/CI noise seen on NodeGoat (`.github` tags, django-csrf on Express) | precision of anchors ↑, pre-pass faster (no metrics/registry auto) | S | adapter/static.py | rules registry download still needs network |
| 8 | `OWASP_DIR` runtime corpus for remediation/cheat-sheet excerpts | report readability | S | adapter/owasp.py | network / supply chain if auto-cloned — keep opt-in |

Leave out: WSTG DAST-only tests (56), INFO recon, payload lists, "Tools" sections, tool-driven fingerprinting;
generating skills automatically from page text (licence + quality: the how-to prose is browser-oriented).

## Handoff (top 3)
1. **WSTG verdict skills** (#1): ≈25 skill files in the §3 format (three are written above, drop-in), frontmatter
   `cwes:`/`wstg:`, `skill_for` returns `[wstg-skill, strix-skill]`, verify payload carries `skills`. This is the
   change that moves precision — the counter-facts are exactly what `disprove_finding` needs.
2. **CWE→WSTG/Top10 map to every emitted CWE** (#2, §2 table) — one hour, removes the `consult_owasp` misses that
   currently leave ThreatModeler threats without ids; fix `CWE-22` cheat sheet, split CWE-798 (creds vs key files).
3. **wstg_id end-to-end + SARIF taxonomy** (#3): Hypothesis.wstg_id, Reconciler fills it from threat/CWE, SARIF
   `properties.wstg/top10` and a `taxonomies` entry — makes WSTG coverage measurable and feeds proposal #5.
Licence: vendor only `checklist.json`-derived ids/objectives with a CC BY-SA 4.0 NOTICE; skills stay in our words.
Everything DAST-only stays out until the stage-2 sandbox exists.
