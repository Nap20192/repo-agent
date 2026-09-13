# Implementation Plan: Specialist roster + deterministic router

Status: GATE 1 (awaiting approval). Author: ecc:planner, 2026-09-12.

## Overview
Replace the single Investigator/Critic with a small roster of domain specialists (own instruction,
tool subset, auto-loaded skills, budget) picked by a pure router per hypothesis/finding. Language
flavour is an instruction *suffix* chosen by file extension (`_activation(..., suffix=)` exists),
so agents are built once per run, not per language. `verifier`/`critic` stay as generic fallbacks;
activation names are unchanged (`verify_r{rnd}_{i}`, `critic_{i}`).

## Roster
Investigate:
- `taint` — kinds {entry, sink}; CWE 89/78/77/88/22/79/80/918/94/95/1336/943/611/502/601. Tools: report_finding,
  lsp_*, read_file, grep, shell, list_anchors, load_skill. Skills: verifier-proof + class skill. 30 calls.
  Why: source→sink tracing is one discipline; ~70% of anchors.
- `authz` — kind authz; CWE 284/285/639/862/863/840/352/287/347/915. + consult_domain (mandatory), lsp_callers.
  Skills: authz-idor, broken-function-level-authorization, business-logic. 30. Why: hole vs rule needs domain.
- `dependency` — kind dependency. consult_knowledge (mandatory), lsp_references, lsp_path_to_entry, read_file,
  grep; no shell. Skills: dependency-advisory. 15. Why: reachability, not tracing.
- `secrets` — kind secret; CWE 798/327/328/338/614/703/312. read_file, grep, lsp_definition, lsp_references,
  report_finding; no shell. Skills: weak-password-detection, information-disclosure. 10. Why: cheap, redaction-sensitive.
Critique: `taint-critic` (check_dominance + lsp_path_to_entry), `authz-critic` (consult_domain),
`dependency-critic` (consult_knowledge, lsp_references, lsp_path_to_entry); all load `counterevidence` first.
Overlays (suffix by `static.LANG_EXT`): `go` (net/http, r.URL.Query, exec.Command, database/sql `$1`),
`node` (Express req.query/body, NoSQL `$where`, prototype pollution, eval/`new Function`),
`python` (Django ORM `.raw/.extra`, Flask `render_template_string`, Jinja `|safe`, FastAPI Depends).
Architect: one agent + `ARCHITECT_OVERLAYS[stack]` from `detect_langs`. One ThreatModeler.

## Task list (thin vertical slices, test-first)

1. **Router core** — `tests/test_specialists.py` → `scanner/app/specialists.py`
   ```python
   @dataclass(frozen=True)
   class Specialist: name: str; role: str; kinds: frozenset[str]; cwes: frozenset[str]; langs: frozenset[str]
       instruction: str; tools_fn: Callable[[Any, Path, Index], list]; skills: tuple[str, ...]; max_calls: int
   REGISTRY: tuple[Specialist, ...]; LANG_OVERLAYS: dict[str, str]
   def lang_of(files: list[str]) -> str                        # first suffix in static.LANG_EXT, "" else
   def route(item: Hypothesis | Finding, lang: str = "", role: str = "investigate") -> tuple[Specialist, str]
   def max_calls(spec: Specialist) -> int                      # env SPECIALIST_<NAME>_MAX_CALLS
   ```
   Tests: cwe beats kind (CWE-862 with kind sink → authz); kind when cwe empty; generic fallback; overlay by
   `.js` → node; unknown suffix → ""; env override. Add `Dossier.specialist: str = ""` in `core/types.py`. Risk: Low.
2. **Instructions** — extend `tests/test_contracts.py` to iterate `build()` (tools named ⊆ agent.tools, skills
   named ∈ SKILLS, Dossier JSON keys, OPERATING_PRINCIPLES prefix) → `scanner/app/instructions.py`:
   `SPECIALIST_SECTIONS[name]` (what to prove, sources/sinks per language, mandatory consult, counter-facts,
   evidence order) composed as `OPERATING_PRINCIPLES + VERIFIER_CORE + section`; `LANG_OVERLAYS`,
   `ARCHITECT_OVERLAYS`. Payload key `skills: [...]` in addition to the single `skill` hint. Risk: Medium.
3. **Tool subsets** — test first in `tests/test_tools.py`: secrets/dependency lack `shell`; authz has
   `consult_domain`; every critic has `disprove_finding`; taint-critic has `check_dominance`.
   `scanner/adapter/tools.py`: `def subset(tools, names: set[str]) -> list` (filter by `__name__`, raise on
   unknown name so typos fail at build). Registry `tools_fn`s: `lambda run, t, idx: subset(verifier_tools(run, t, index=idx), TAINT_TOOLS)` etc. Risk: Low.
4. **Build + graph routing** — tests in `tests/test_stages.py`: `specialists={"taint": Spy}` picked for
   CWE-89; names stay `verify_r{rnd}_{i}` / `critic_{i}`; payload carries `specialist`, `skills`;
   `dossier.specialist == "taint"`; empty dict → `self.verifier` fallback; critic pass notes
   `critic:<name> reviewed <finding_id>`.
   ```python
   # scanner/app/specialists.py
   def build(model, run, target: Path, index: Index) -> dict[str, LlmAgent]   # once per run
   # scanner/app/graph.py
   class _Graph: specialists: dict[str, BaseAgent] = Field(default_factory=dict)
   def _pick(self, item: Hypothesis | Finding, role: str) -> tuple[BaseAgent, str, str]  # (agent, name, overlay)
   ```
   `_verify`: `agent, name, suffix = self._pick(h, "investigate")`; payload `{**h.model_dump(), "skill": skill_for(...),
   "skills": spec.skills, "specialist": name}`; `_activation(agent, f"verify_r{rnd}_{i}", "Hypothesis", payload, suffix=suffix)`;
   `_retry_json` reuses the routed agent; `d.specialist = name`. `_critic_pass`: same with `"critique"`. Risk: Medium
   (retry path must reuse the routed agent, not `self.verifier`).
5. **Runner wiring** — test: `build_agent` on a tmp Go target returns `agent.specialists` keys == REGISTRY names and
   the architect instruction ends with `ARCHITECT_OVERLAYS["go"]`; `SPECIALIST_SECRETS_MAX_CALLS=3` honoured.
   `runner.build_agent`: `specialists=build(model, run, target, index)`, `new_architect(..., overlay=...)`;
   `VERIFIER_MAX_MODEL_CALLS`/`CRITIC_MAX_MODEL_CALLS` remain the fallback budgets. Risk: Low.
6. **Live eval** — `eval/agents.py` one trial per specialist (`--only taint,authz,...`): taint (02-vulnshop
   confirmed quoting `db.Query`, go overlay present); authz (08-idor-go, `domain:` ref, consult_domain called);
   dependency (osv anchor, `knowledge:` cited, lsp_references called, no shell); secrets (CWE-798 fixture,
   evidence redacted, shell never called); taint-critic (`/safe` `$1` disproved only after `check_dominance`
   true); authz-critic (owner check on another branch → survives); dependency-critic (uncalled vulnerable symbol
   → disproved via null `lsp_path_to_entry`); overlays (11-expressshop NoSQL, 10-flaskshop SSTI suffixes).

## Risks & mitigations
- Multi-CWE anchors: route on `h.cwe` only (`from_anchors` picks one); test CWE-862 kind=sink → authz.
- Clone cost: agents built once per run; overlays are suffixes, not per-language clones.
- Instruction drift: contract test iterates `build()` — tools named ⊆ tools, skills ∈ SKILLS, JSON keys.
- Web UI: activations stay branches named as today; specialist name only in payload/notes.
- Existing tests assume one verifier: `specialists` defaults to `{}` → fallback path keeps them green.

## Leave-outs
Per-file micro-specialists; LLM-based routing; per-specialist models (later, once eval shows where a stronger
model pays off); Critic specialists beyond the three families.

## Consultants: Domain and Knowledge (addendum, 2026-09-12)

Both are specialists whose value is a *source of truth* the other agents cite. Today `consult_domain` is
a grep heuristic and `consult_knowledge` a single osv.dev call. Target design:

### Domain specialist — where the business rules come from
1. **DomainModeler stage** (after Architect, before ThreatModeler; artifact `domain_map`, resumable).
   Deterministic skeleton first, LLM interprets second (same symbiosis as Architect):
   - schemas: Go structs with `json`/`db` tags, sqlc/migrations SQL, Django/SQLAlchemy models, Prisma/Mongoose
     schemas → entities {name, fields, owner_field candidates (`user_id`, `owner`, `tenant_id`), symbol};
   - access layer: middlewares/decorators (`@login_required`, `requireRole`, `s.auth(`, `ensureAuthenticated`),
     role enums, permission tables → roles and which entry points each role reaches (from `entry_points`
     + `lsp_callers`);
   - rules: docs/README/ADR/tests (business rules live in tests) → falsifiable statements
     "Order is visible only to Order.UserID", each grounded on a symbol (gate: no symbol → note);
   - invariants and trust boundaries per role.
   Rounds: round 1 from schemas + middlewares (cheap, mostly deterministic); round 2 the LLM fills gaps —
   entities without owner_field or without any rule — by reading handlers via `lsp_definition`/`lsp_callers`.
   Output schema: `DomainMap{entities[], roles[], rules[{id, statement, entity, symbol, evidence}], gaps[]}`.
2. **`consult_domain(question|entity)`** = deterministic lookup in the DomainMap (entity, its owner field,
   rules, which roles reach which entries) + optional LLM Domain agent as an ADK `AgentTool` for open questions
   ("is /admin/orders reachable without the admin role?") that answers by reading the map and the code,
   citing symbols; returns `domain:<entity>` refs the gate already requires for authz.
3. Consumers: ThreatModeler generates authz/IDOR/business-logic threats from rules × entry points
   (a rule with no enforcing symbol on a reachable path = threat); `authz` specialist and `authz-critic` consult
   it; Critic's "intended business rule" disproof route cites `domain:<rule id>`.
   Files: `scanner/core/types.py` (DomainMap), `scanner/adapter/domain.py` (skeleton extractors per language,
   pure), `scanner/app/instructions.py` (DOMAIN_MODELER), `scanner/app/pipeline_v2.py` (stage), tools.

### Knowledge specialist — every vulnerability database, in parallel rounds
1. **Deterministic enrichment in the pre-pass** (no LLM): for every osv anchor (package@version) run
   parallel queries with an asyncio/ThreadPool fan-out and a SQLite cache table `knowledge(key, json, fetched_at)`:
   - OSV batch `POST /v1/querybatch` (ids per package) then `GET /v1/vulns/{id}` (affected ranges, fixed versions,
     `database_specific`, references, aliases CVE/GHSA);
   - GitHub Advisory DB `GET /advisories?ghsa_id=` / `?affects=pkg@ver` (vulnerable functions when present,
     severity, patched versions; token `GITHUB_TOKEN` optional for rate limits) or the local clone `GHSA_DIR`
     as in git-agent3 (offline mode);
   - NVD 2.0 `GET /rest/json/cves/2.0?cveId=` (CVSS v3.1 vector, CWE ids; `NVD_API_KEY` raises the rate limit);
   - EPSS `GET api.first.org/data/v1/epss?cve=` (exploit probability) and CISA KEV feed (known exploited);
   - deps.dev `GET /v3/systems/{sys}/packages/{pkg}/versions/{ver}` (advisory keys, licenses) as a cross-check.
   Result: the osv anchor's message carries CVSS, EPSS, KEV, fixed version and the vulnerable symbols named in
   the advisory; calibrate uses EPSS/KEV as likelihood; `rule_ids` keeps all aliases. Rounds: R1 by package,
   R2 enrich each advisory id, R3 vulnerable-symbol names → `lsp_references`/`lsp_path_to_entry` for reachability
   (this is what turns "dependency has a CVE" into "the vulnerable function is called from an entry point").
2. **Knowledge agent** (LlmAgent, `AgentTool` for the `dependency` specialist, ThreatModeler and critics) with
   tools `osv_query`, `ghsa`, `nvd_cve`, `epss`, `kev`, `deps_dev`, plus optional web search (`WEB_SEARCH=tavily|exa`,
   ecc `exa-search` skill; the user's own key) for questions beyond databases ("known bypasses of this CSRF
   library", "is this framework version's default config unsafe"). It answers with `knowledge:<id>` refs and a
   short verdict; multi-round: it may issue follow-up queries per alias; budget 10 calls; cache-first.
3. Consumers: `dependency` specialist (mandatory consult), ThreatModeler ("known vuln classes for this stack and
   versions" → threats with `wstg_id`), `dependency-critic` (patched_in vs manifest version, unreachable symbol).
   Files: `scanner/adapter/knowledge.py` (clients + cache + enrichment, pure functions over JSON), `scanner/adapter/static.py`
   (call enrichment after osv), `scanner/app/agents.py` (knowledge agent), tools, `scanner/core/calibrate.py` (EPSS/KEV).
   Tests: fixtures of each API's JSON, cache hits, offline mode (GHSA_DIR), reachability round on 11-expressshop.

### Task list additions
7. `adapter/domain.py` skeleton extractors (Go structs/sqlc, Django models, Mongoose/Prisma) + DomainMap type + tests.
8. DomainModeler stage + `consult_domain` over the map + ThreatModeler rules×entries + authz specialist wiring.
9. `adapter/knowledge.py` clients (OSV batch, GHSA, NVD, EPSS, KEV, deps.dev) + cache + pre-pass enrichment + tests.
10. Knowledge agent (AgentTool) + reachability round (advisory symbols → lsp) + calibrate likelihood from EPSS/KEV.
