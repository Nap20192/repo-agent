# Shannon workflow vs ours — gap report (2026-09-12)

Exhibit: NodeGoat run 13 (gemini-flash-lite). 48 anchors (osv 40, semgrep 5, gitleaks 3) + 2 threatmodel + 2 entrypoint
synthetic. Round 0: 4 dependency + 3 sink + 1 secret; rounds 1–3: 8 dependency each. 3 confirmed, 11 rejected (all
dependency), 60 gate refusals, 490 model calls, ~3.9M tokens, `stop_reason="round limit"`. Missed: NoSQL `$where`,
IDOR on `allocations/:userId`, XSS in profile, missing `isAdmin`, CSRF, ReDoS, plaintext passwords.

Shannon paths are relative to `~/tmp/repos/shannon/apps/worker`; ours to the repo root.

## 1. Shannon, stage by stage

Shannon has two code-analysis streams that join in reconciliation and only exploited findings are reported
(`README.md` "Architecture"; `docs/coverage-roadmap.md`: "many dependency, policy, configuration, and broad
static-analysis findings are outside the core Shannon workflow").

### 1a. Capella — the agentic SAST child workflow (our true counterpart)

Ten sequential Temporal activities, one per stage, each with its own timeout/retry policy
(`src/ai/sast/capella/temporal/workflow.ts:330-455`; policies `temporal/activity-types.ts:278-290`). Tools everywhere
are read-only `read`/`find`/`grep`, no shell (`prompts/partials/capella-tools.hbs`). Every stage is checkpointed by
fingerprint and reused on resume (`stages/research.ts:329-345`, `stages/verdicts.ts:245`). A failed stage falls back to
the last good finding set and still exports (`workflow.ts:412-450`).

| # | Stage | In → Out | Prompt | Agents / parallelism | Budget |
|---|---|---|---|---|---|
| 1 | architecture | repo → Markdown KB: `architecture.md`, `entities/*.md`, `vulnerabilities/CWE-*.md`, `index.md`, `dependencies.json` | `prompts/sast/capella/architecture.prompt.hbs` | 1 agent, `role: large` | 400 turns, 90 min (`stages/architecture.ts:57`) |
| 2 | threat-model | KB → `THREAT_MODEL.md` + `Intent: PRODUCTION\|SAMPLE_OR_TEST_ONLY` (fail-closed 5-item checklist), trust boundaries, actors, assets with availability tier | `threat_model.prompt.hbs` | 1, no source access | 150 turns, 30 min |
| 3 | plan | KB + threat model → `plan.json{investigations[{title,target_files,kb_references,question}]}` | `plan.prompt.hbs` | 1 | 150 turns |
| 4 | research | plan → findings (one JSON per finding) | `triage.prompt.hbs` then `research.prompt.hbs` | **triage**: all target files split into ≤4 batches, 4 concurrent, 100 turns; **audit**: one agent per investigation that has ≥1 flagged file, 2 concurrent, 200 turns (`stages/research.ts:46-47,133,329,432`; `types.ts:32-33`) | 3 h |
| 5 | dedupe | findings → `record_duplicates` | `dedupe.prompt.hbs` | 1 | 200 turns |
| 6 | review | findings → VALID / FALSE_POSITIVE / PROVISIONALLY_VALID / NEEDS_RESEARCH + 13-rule `triage_checklist` | `review.prompt.hbs` | 1 primary + 1 repair pass over skipped ids (`verdicts.ts:246-300`) | 400 turns, 2 h |
| 7 | critic | findings + KB → `production_viability` VIABLE / CONDITIONAL_VIABLE / NON_VIABLE / SAMPLE_OR_TEST | `critic.prompt.hbs` | 1 + repair | 300 turns |
| 8 | confirm | → `repro_status` statically_confirmed / not_attempted; promotes PROVISIONALLY_VALID→VALID | `confirm.prompt.hbs` | 1 + repair | 300 turns |
| 9 | calibrate | → risk score 1–10, 27-rule cap catalogue, report-only | `calibrate.prompt.hbs`, `partials/capella-calibration-rules.hbs` | 1 | 200 turns |
| 10 | export | → `capella.sarif`; deterministic | — | none | 5 min |

Key prompt lines:
- plan: "**Guarantee complete coverage:** crawl all production directories and source code files … A file no
  investigation lists is never examined by anything downstream"; 25–50 % chance of an "Adversarial Sweep" over an area the
  threat model marks safe, or "Random Digging" with empty `kb_references` (`plan.prompt.hbs` step 2).
- research: "Run a repo-wide grep for the function name to build the exhaustive set of candidate call-sites — this is the
  mandatory floor"; `report_finding` once per finding with a **required bare CWE**, `code_paths[0]` = sink `<path>:<line>`.
- review: "Assume every finding is a false positive by default … Explicitly ignore the original finder's prose"; rule 13
  requires citing the ingress `file:line` where attacker data enters.
- operating principles (`partials/capella-operating-principles.hbs:44-56`): committed secrets are **out of scope** — "A
  dedicated secret-scanning pipeline runs over the same commit and already reports these"; CWE-798/259/321/256/260/547 are
  rejected by the tool (`collectors.ts:199-203`).

Finding record and dedup: `report_finding` validates at the boundary (`collectors.ts:527-596`); identity is
`cwe--file--l<line>--title` (`collectors.ts:149-153`); dedupe merges only same `code_paths` line-inclusive + similar title.
Export gate: `status === 'VALID' && viability ∈ {VIABLE, CONDITIONAL_VIABLE}` (`sarif-exporter.ts:59-60`).
Capella output is then just another SARIF for the pentest lanes (see 1b); it never reports on its own.

### 1b. Pentest stream + reconciliation (`src/temporal/workflows.ts:320`)

preflight → auth validation (`prompts/validate-authentication.txt`) → **pre-recon** (1 agent, `prompts/pre-recon-code.txt`,
"the ONLY agent with complete source code access", 7 `set_*` deliverable tools) → **recon** (1 agent,
`prompts/recon.txt`; `add_endpoints` deduped on `(method,path)`, per-role route patterns, IDOR/privilege-escalation
endpoint lists — `collectors/recon-collector.ts:165-196,369-496`) → **5 class lanes + miscellaneous, 5 concurrent**
(`workflows.ts:145,698-729,1377`): vuln agent (`prompts/vuln-{injection,xss,auth,authz,ssrf}.txt`) → join Capella SARIF →
reconcile → exploit agent (`prompts/exploit-*.txt`, only if the queue says `shouldExploit`, `workflows.ts:779`) → report
(`prompts/report-executive.txt` → Markdown/PDF/SARIF/JSON, `services/report-finalization.ts`).

Per-endpoint sweep: prompt-driven, not code. `vuln-injection.txt:38` "An incomplete analysis is a failed analysis …
**every potential data entry point** … documented using the `todo_write` tool. **Do not terminate early.**";
`:131` "Create a To Do for each Injection Source found in the Pre-Recon Deliverable"; `:256-266` coverage list (URL
params, form data, headers, cookies, JSON, upload names) + "Revisit coverage when new endpoints … are discovered".
Termination: "ALL tasks completed" + required deliverable tool call (`vuln-injection.txt:314-323`); Temporal caps at 2 h,
50 attempts (`workflows.ts:53-80`).

Reconciliation per class (`workflows.ts:638`): SARIF intake (digest-pinned, `reconciliation/sast/intake.ts`) →
deterministic parse + CWE→class (`sast/sarif-parser.ts`, `sast/cwe-mapper.ts`) → **one-shot LLM enrichment** adding
`witness_payload`, `slot_type`, `externally_exploitable`, `confidence` (`reconciliation/enrich.ts`, 32 k tokens,
`prompts/sast-enrichment-*.txt`) → code-owned policy: SAST observations get `primary_preference:'preferred'` and their own
id namespace `PREFIX-SAST-NN` (`sast/enrichment/policy.ts:21-52`) → **task formation** LLM groups observations by opaque
labels into "one attacker-controlled input reaching one dangerous operation" (`prompts/task-formation-injection.txt:6`;
`form.ts`, 64–128 turns; skipped when <2 observations, `form.ts:143-153`; singleton fallback on model failure) →
deterministic materialize/publish with a manifest whose lineage must be dense and unique (`manifest.ts:107-170`).
Scanner results are therefore **never auto-published** — Shannon has no deterministic-finding lane at all; they become
exploitation candidates and die if not exploited.

Report: ordered category → severity → ref (`services/finding-order.ts:31,85`); Markdown per finding with
Severity/Confidence/Status, `severity_rationale` mandatory for `exploited`
(`collectors/exploit-collector.ts:205-222`); SARIF only for `exploited`.

## 2. Ours, stage by stage (`scanner/app/pipeline_v2.py`)

| # | Stage | In → Out | Prompt | Agents / parallelism | Budget |
|---|---|---|---|---|---|
| 0 | static pre-pass | repo → `Anchor[]` from gosec/semgrep/osv/gitleaks, one thread each (`adapter/static.py:229-268`); osv capped at 40 packages, all `severity="high", line=1` (`static.py:183,202`); gitleaks forced CWE-798 (`:212`); dup-merge on `(file,line,cwe)` except osv (`core/rules.py:57-90`); EPSS/KEV enrichment (`static.py:243`) | — | none | — |
| 0' | entry points | regex detectors per language → `Candidate[]` (`adapter/entrypoints.py:84-87`) | — | none | — |
| 1 | Architect | `{target, entry_points, anchors}` → `ArchitectureModel` (`pipeline_v2.py:102`) | `instructions.py:147 ARCHITECT_INSTRUCTION` "every entity and boundary you assert MUST cite a symbol" | 1, sequential | 40 calls, 600 s (`settings.py:52`, `pipeline_v2.py:60`) |
| 2 | DomainModeler | model + skeleton → domain map (rules/gaps) (`pipeline_v2.py:110`) | `app/domain.py:84` | 1 | 12 calls |
| 3 | ThreatModeler | model + domain map → ≤12 threats, intent (`pipeline_v2.py:119`) | `instructions.py:171` "every threat MUST carry a `symbol`" | 1, **no code tools**, only `consult_owasp` (`runner.py:101`) | 6 calls |
| 3' | grounding | deterministic drop of ungrounded entities/threats (`reconcile.py:148`) | — | none | — |
| 4 | queue build | anchors → hypotheses `priority = SEVERITY_RANK×20` (`reconcile.py:37-45`); threats → hypotheses, synthetic `threatmodel` anchor if no scanner match (`:50-84`); entry points → `kind="entry"`, **priority 10** (`:207-224`); merged by `anchor_id or symbol\|cwe`, sorted desc (`:194-204`) | — | none | — |
| 5 | investigate loop | `queue[:8]` per round → gate → specialist activation → dossier → ≤3 `new_hypotheses` re-queued (`pipeline_v2.py:174-209`) | `OPERATING_PRINCIPLES + INVESTIGATOR_CORE + section` (`specialists.py:41`, `instructions.py:7,197,231`) | 1 agent per hypothesis, `ParallelAgent` in chunks of 3 (`graph.py:139-148,250`) | 4 rounds × 8 = **32 investigations**, 30 calls each (`settings.py:41-56`) |
| 6 | critic | one activation per confirmed finding (`graph.py:270-291`) | `CRITIC_CORE` "assume it is a false positive and try to DISPROVE it" (`instructions.py:219`) | chunks of 3 | 20 calls |
| 7 | report | `report.sarif` confirmed only + `summary.json` (`adapter/store.py:173-215`) | — | none | — |

Findings exist only through `report_finding` (`adapter/tools/gates.py:21-77`): anchor_id required, cwe/file/line must
equal the anchor's, quotes must appear within ±3 lines of the anchor line, dependency/authz need a consult ref.
Dedup key in the store: same `anchor_id` **or** same `(cwe,file,line)`; higher confidence replaces (`store.py:109-121`).
Calibration is report-only (`core/calibrate.py:48`). Router is deterministic CWE→kind→fallback (`specialists.py:106`).
Termination: queue empty, `rnd >= max_rounds`, budget flag, or a verify exception (`pipeline_v2.py:181-208`).

Run-13 gate-refusal breakdown (`.state/state.db gate_log`): 28 "evidence does not match the code at file:line",
~26 "line N does not match anchor's 1" (osv anchors pinned at `package-lock.json:1`), 4 "confidence must be in [0,1]"
(model sent 95.0/100.0), 2 file mismatch. `reconcile.adversarial_sweep` (`reconcile.py:232`) is tested but never called
from the pipeline.

## 3. Gap table

| Area | Shannon | Ours | Causes the NodeGoat miss? |
|---|---|---|---|
| Deterministic scanner output | Not a finding stream at all; secrets explicitly out of scope for the LLM; SARIF becomes exploitation candidates | Every osv/gitleaks/semgrep anchor is an LLM hypothesis at priority 60–80 | **Yes — primary.** 40 osv anchors × p60 outrank p10 entry hypotheses; 28 of 32 investigation slots went to `package-lock.json:1` |
| Coverage guarantee | plan: "A file no investigation lists is never examined"; every production file is in some investigation; triage sweeps all files, audit only flagged ones | Only anchors + ≤12 threats + p10 entry baselines; no file-level coverage; threat modeler cannot read code | **Yes.** `$where`, IDOR, `isAdmin`, CSRF, ReDoS, plaintext passwords have no scanner anchor, and the ≤12 threats came from a modeler with no code access |
| Hypothesis source | Route/endpoint catalog (recon `add_endpoints`, per-role patterns, IDOR endpoint list) + per-class prompts with a coverage checklist and `todo_write` loop; "Do not terminate early" | `new_hypotheses` only from the investigator that ran (≤3), so discovery is gated on the queue that starved | **Yes.** Zero route-driven hypotheses were ever generated |
| Per-class specialist prompts | 5 vuln classes each with own long prompt, hypothesis checklist, witness-payload rules (`vuln-*.txt` ~300 lines) | 5 specialist *sections* of 4–6 lines each (`instructions.py:231-258`); language overlays | Partial — sections tell how to verify an anchor, not how to hunt a class |
| Adversarial / random sweep | 25–50 % chance per plan | Implemented, dead (`reconcile.py:232`) | Minor |
| Verdict ladder | research → dedupe → review (13 rules + checklist) → critic (viability) → confirm (static, promotes) → calibrate | investigate → critic (13 rules in one prompt); calibrate | No; ours is cheaper and adequate once inputs are right |
| Anchor coordinate rigidity | `code_paths` are model-supplied and validated for existence; review may refine them | Gate rejects any line ≠ anchor line; osv anchors have no real line | **Yes — 26 refusals**, ~1/3 of the wasted calls |
| Confidence scale | 1–10 risk score computed by calibrate from enum fields | Model must emit [0,1]; 4 refusals for 95.0/100.0 | Minor, cheap fix (`gates.py`: normalise >1 by /100 or /10) |
| Dedup identity | `cwe--file--line--title`; manifest lineage dense+unique; SAST primary wins | `anchor_id` or `(cwe,file,line)`, ids `f_<n>` not stable across runs | No |
| Parallelism | triage 4, audit 2, review sequential; 5 class lanes concurrent | 3 investigations at a time, stages sequential | No |
| Termination | per-stage turn caps + timeouts; whole stage checkpointed | 4 rounds × 8; budget per branch | Aggravates: 32 slots is the whole run |
| Budget accounting | usage per stage accumulated, `usageComplete` flag | timings + gate refusals; no cost per stage | No |
| Reporting | Markdown + PDF + SARIF + JSON, severity_rationale mandatory | SARIF + summary.json, no human-readable report | No (product gap) |
| What we do that Shannon doesn't | — | Deterministic grounding of artifacts (`reconcile.py:148`), gate-enforced anchor coordinates, quote-in-window evidence, domain modeler + `consult_domain`, OSV/EPSS/KEV knowledge, WSTG/ASVS taxa in SARIF, per-branch budget stripping | Keep all |

## 4. Proposal

### 4a. Direct findings (no LLM) — anchor kinds that "definitely happened"

New deterministic step between static pre-pass and queue build, in `scanner/app/reconcile.py` (`split_direct(anchors)
-> (direct, investigate)`), stored through the existing `store.report` dedup key and written by the existing SARIF/summary
writers. Findings get `status="confirmed"`, `confidence` fixed per kind, `evidence=[snippet]`, and are **excluded** from
`from_anchors` so they never enter the queue.

| Kind | Rule (all data already on the anchor / knowledge cache) | Enrichment in `description` / SARIF `properties` |
|---|---|---|
| dependency (osv, `anchor_kind=="dependency"`) | always direct | advisory ids, CVSS/severity from OSV, EPSS score + percentile, KEV flag, fixed version (OSV `fixed` event) as `fixes[]`, manifest file, **reachability note**: "imported by N files" via a grep of the package name over source (grep helper already in `adapter/index/`); confidence 0.9 |
| secret (gitleaks, CWE-798) | always direct | rule id, entropy, redacted snippet (`core.redact_secrets`), file history hint if git available; confidence 0.85; remediation = rotate + move to env |
| semgrep high-confidence | `rule metadata.confidence in {HIGH}` and `severity in {ERROR}` and rule id in an allowlist (sqli/xss/eval/ssrf/path-traversal rules) — read from SARIF `properties` in `static.py:99` | rule id + rule description, CWE, OWASP taxa from `store.py:36-53`, snippet at line; confidence 0.7. Other semgrep rules stay LLM hypotheses (they carry a real file:line, so the gate works) |

Critic pass skips direct findings (they carry `anchor.tool` ∈ {osv, gitleaks}); `disprove_finding` still applies if a
later investigator wants to. This removes 40 of 48 anchors from the queue and, with `OSV_MAX`, makes it a report cap
rather than a queue cap. Expected on NodeGoat run 13: ~26 line-mismatch refusals → 0, 11 dependency rejections → 0
(they become direct dependency findings, deduped per package), ~300 of 490 model calls freed for code.

Also cheap: normalise confidence >1 in `gates.py` (`/100` if >10 else `/10`) instead of refusing.

### 4b. LLM stages become Shannon-style discovery

1. **Coverage plan (deterministic + 1 call).** Port `plan.prompt.hbs`'s "guarantee complete coverage" as a new
   `PLANNER_INSTRUCTION` in `instructions.py` next to `THREAT_MODELER_INSTRUCTION` (`:171`). Input: entry points
   (`adapter/entrypoints.py`), architecture model, threat model, list of production source files (skip tests/vendor per
   `capella-operating-principles.hbs` rules, already mirrored in our `OPERATING_PRINCIPLES` `instructions.py:7`). Output:
   `investigations[{route|file, class, question, kb_refs}]` → hypotheses with `kind="entry"|"sink"`, priority 50+ so they
   compete with real semgrep anchors. Every entry point gets at least one investigation per applicable class (Shannon's
   `todo_write`-per-source loop, done in code instead of prompt). Wire `adversarial_sweep` (`reconcile.py:232`) here with
   `fraction=0.25`.
2. **Give the ThreatModeler code access** (`runner.py:101`: add `read_file`/`grep` from `rosters.py`) and raise the
   threat cap from 12 to per-entry-point; or keep it and let the planner do the sweep. Shannon's threat modeler reads only
   the KB, but its planner and triage read everything.
3. **Triage before audit** (from `research.ts:329-432`): one cheap activation per batch of ~10 route files with
   `triage.prompt.hbs` semantics (`{file, potentially_flawed, reason}`), then only flagged files get a full specialist
   activation. Maps to a new `TRIAGE_INSTRUCTION` and a `_triage_round` in `pipeline_v2.py` before `_investigate_round`.
   This is how 32 slots cover a whole app.
4. **Per-class hunting prompts.** Grow `SPECIALIST_SECTIONS` (`instructions.py:231-258`) from verification hints into
   hunting checklists, porting the `<coverage_requirements>` and hypothesis lists:
   - `taint` ← `prompts/vuln-injection.txt` (sources list `:256-260`, sink classes incl. NoSQL `$where`/`$regex`, eval,
     template, ReDoS) + `prompts/vuln-xss.txt` + `prompts/vuln-ssrf.txt`
   - `authz` ← `prompts/vuln-authz.txt` + `prompts/vuln-auth.txt` (IDOR per `:id` route param, role checks per admin
     route, session fixation, missing CSRF token on state-changing routes, password storage)
   - `config` ← `pre-recon-code.txt` framework-config items (CSRF middleware, cookie flags, `trust proxy`)
   - `secrets`, `dependency` sections shrink to "consult only" since these are direct findings now
   Keep each section short and put the checklists as bullet lists; the investigator core already forces `report_finding`.
5. **Anchors for discovered code.** Investigators on `entry`/planner hypotheses have synthetic anchors without a class or
   line (`reconcile.py:224`). Let `gate_finding` accept model-supplied `file:line` when `anchor.tool in
   {"entrypoint","planner","threatmodel"}` and the quote is found at that line (`gates.py:28-30,39-48`), mirroring
   Capella's `code_paths[0]` validation (`collectors.ts:237-279`): existence + line in range, not equality with the anchor.
6. **Review ladder later, not now.** Shannon's review→critic→confirm split is three prompts we already have compressed into
   `CRITIC_CORE`; port the 13-rule `triage_checklist` as a JSON field only if false positives rise after 1–5.

### Order of work (each a BOARD card)
1. direct findings + confidence normalisation (deterministic, tests on `reconcile`/`gates`/`store`) — removes queue starvation.
2. planner + entry-point investigations + wire `adversarial_sweep` — restores coverage.
3. triage round — makes 32 slots enough.
4. specialist hunting checklists (prompt-only, eval with `eval/agents.py` pass@k).
5. anchor-relaxed gate for synthetic anchors.
