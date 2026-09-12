# Board — rewrite of git-agent3 workflow on ADK Python

Goal: `scan full --target <path>` = pre-pass (scanners → Anchors) → candidates → rounds
`lead → verify ×N → lead …` with grounding + evidence gates → SARIF/summary, exit 0/1/2.
Source workflow: `/home/vnkjd/Projects/git-agent3` (docs/ARCHITECTURE.md, internal/app/fullscan).
Not replicated: hexagonal layout, Docker sandbox, go/ssa, LSP index, Domain Map builder.

## Cards

_v1 (Lead ⇄ Verifier, `FullScan`) removed 2026-09-12; the only graph is `PipelineV2`._

| id | title | owner | state | files | merge gate |
|---|---|---|---|---|---|
| 00 | core types + pure rules | main | merged | scanner/core.py | `python scanner/core.py` prints `core ok` |
| 01 | static scanners → anchors, entry points, symbol check; sqlite store + SARIF/summary | adapters | merged | scanner/static.py, scanner/store.py, tests/test_store.py, tests/test_static.py | `uv run pytest tests/test_store.py tests/test_static.py`; `static.scan` on samples/02-vulnshop returns ≥2 anchors with CWE-89/CWE-78 |
| 02 | ADK function tools with gates | tools | merged | scanner/tools.py, tests/test_tools.py | `uv run pytest tests/test_tools.py`; report_finding refuses: unknown anchor, coord mismatch, missing consult ref, unmatched quote |
| 03 | Lead/Verifier agents, FullScan graph, CLI, eval | graph | merged (reviewed: python, security, code, silent-failure; dev-team) | scanner/agents.py, scanner/main.py, scanner/__main__.py, tests/test_graph.py, eval/dataset.json | `uv run pytest tests/test_graph.py` with fake agents: 2 rounds, dossiers stored, finish on `route=finish`, budget → finish |
| 04 | integration: real run on samples/02-vulnshop | user (needs LLM key) | blocked | .env | exit 2, SARIF has CWE-89 + CWE-78, `/safe` not confirmed |
| 05 | v2 step 1: Critic (adversarial pass, disprove → uncertain) | main | merged | scanner/agents.py, scanner/tools.py, scanner/store.py | `uv run pytest`; disprove gate refuses unknown/non-confirmed/unquoted; FullScan runs critic after the loop |
| 06 | v2 step 2: Reconciler (pure fn: anchors + threats → queue) + Investigator loop (queue-driven, no Lead), `PIPELINE=v2` | main | merged | scanner/reconcile.py, scanner/agents.py | `uv run pytest`; ollama smoke on 02-vulnshop drains the queue, exit 0 |
| 07 | v2 step 3: Architect + ThreatModeler stages, artifacts in State, synthetic anchors for grounded threats, consult_owasp (static tables) | main | merged (reviewed: code, python) | scanner/owasp.py, scanner/artifacts.py, scanner/agents.py, scanner/tools.py, scanner/store.py | `uv run pytest`; eval with a real model: 08-idor-go confirmed via threat path, 0 FP on 03 (blocked on card 04) |
| 08 | eval on samples with a real model (v1 removed; v2 is the only graph) | user (needs LLM key) | blocked | — | `PIPELINE=v2 uv run python -m scanner eval` vs v1: recall ≥, FP == 0 |
| 09 | package layout core/adapter/app + observe (tracing, compaction) + persistent sessions | main | merged | scanner/core/{types,rules}.py, scanner/adapter/{static,store,owasp,tools}.py, scanner/app/{instructions,callbacks,agents,graph,fullscan,pipeline_v2,reconcile,observe,runner}.py, scanner/main.py, web/fullscan/agent.py | `uv run pytest` all green; `adk web web --port 8080 --session_service_uri=sqlite:///.state/sessions.db` lists run-<n>-<target> under app `fullscan` |
| 11 | Shannon prompts: operating principles, research/review/critic rules, calibrate (report-only fn), plan coverage | shannon-prompts | merged | scanner/app/instructions.py, scanner/app/calibrate.py, scanner/app/reconcile.py | pytest green; attribution kept |
| 12 | Strix skills corpus + load_skill/list_skills tools | strix-skills | merged | scanner/skills/, scanner/adapter/skills.py, scanner/adapter/tools.py | pytest green; skill_for(cwe) map |
| 13 | wiring: calibrate (core) → summary/SARIF properties, coverage → queue, skill hint → verify payload | main | merged | scanner/core/calibrate.py, scanner/adapter/store.py, scanner/app/pipeline_v2.py, scanner/app/graph.py | pytest green |
| 14 | LSP index: core port `Index` + adapters per language (Go/Python/TS/JS) + grep fallback + multiplexer; JSON-RPC stdio client; gopls integration test | lsp-core | merged | scanner/core/ports.py, scanner/adapter/index/*.py, tests/test_lsp*.py | fake-server round-trip, fallback without binaries, gopls on samples/02-vulnshop |
| 15 | lsp_* tools, read_file 60-line window, grep cap, tool_window_callback(keep=3) | tools-window | merged | scanner/adapter/tools.py, scanner/app/callbacks.py, scanner/app/agents.py, tests/test_tools.py, tests/test_callbacks.py | tools with FakeIndex; window test on synthetic LlmRequest |
| 16 | wiring: build_agent/prepare use the Index; close on scan_full; reviewers (code + security: 2 critical, 3 high fixed); GATE 2 | main | merged, awaiting GATE 2 | scanner/app/runner.py, tests/test_graph.py | pytest green; code+security review clean |
| 17 | static pre-pass verified on mixed-language trees (synthetic mono-repo, bakery, NodeGoat, DVWA, govulnlab): osv aggregation per package + OSV_MAX, JS routes with `;`, php grep prefix, per-language grep scope, LSP-first routing, missing-target check | main | merged | scanner/adapter/static.py, scanner/adapter/index/{grep,__init__}.py, scanner/app/runner.py, tests/test_static.py, tests/test_lsp_multilang.py | pytest green; NodeGoat osv 300 → ≤40, entry points 0 → 20 |
| 18 | per-node unit tests + agent contract tests (tools named in instructions exist, skills exist, payload keys match) | node-tests | running | tests/test_stages.py, tests/test_contracts.py | pytest green; every stage of PipelineV2 covered in isolation |
| 19 | live per-agent eval harness (pass@k on a local/cheap model, scorecard JSON), marker `live` | live-eval | running | eval/agents.py, tests/live/, pyproject markers | `uv run python -m eval.agents` produces a scorecard; default pytest unaffected |
| 20 | workflow improvements: parallel scanners in pre-pass, JSON-retry nudge for stages/verifier, stage timings in summary | workflow-improve | running | scanner/adapter/static.py, scanner/app/{graph,pipeline_v2}.py, scanner/adapter/store.py, tests/test_workflow_improvements.py | pytest green; pre-pass wall time ≤ slowest scanner |
| 21 | R&D team: project skill `ecc-rnd` + catalog-diff script that finds new ECC skills/agents/commands and proposes how to apply them; first report | rnd-team | running | .claude/skills/ecc-rnd/SKILL.md, scripts/ecc_rnd.py, docs/rnd/ | script runs; first report lists concrete proposals |
| 22 | R&D proposal #1: CLAUDE.md contract for agents; preamble names each agent's own verdict tool | main | merged | CLAUDE.md, scanner/app/instructions.py | contracts test green |
| 23 | OWASP R&D team: WSTG → Investigator/Critic checklists + corpus-backed consult_owasp | owasp-wstg | merged | docs/rnd/owasp/wstg.md | report with ranked proposals + integration design |
| 24 | OWASP R&D team: Cheat Sheets + Proactive Controls → Critic counter-fact catalog, remediation | owasp-cheatsheets | merged | docs/rnd/owasp/cheatsheets.md | report |
| 25 | OWASP R&D team: ASVS + Top10 → coverage model for Architect/ThreatModeler, calibration alignment | owasp-asvs | merged | docs/rnd/owasp/asvs-top10.md | report |
| 26 | OWASP R&D tooling: scripts/owasp_rnd.py corpus inventory + gap analysis vs our CWE tables/skills; project skill owasp-rnd; index report | owasp-tooling | merged | scripts/owasp_rnd.py, .claude/skills/owasp-rnd/SKILL.md, docs/rnd/owasp-2026-09-12.md | script runs; gap table |
| 27 | eval corpus: Python sample, Express sample (inline handlers), NodeGoat ground truth (clone on demand), safe neighbours per class; dataset validation test | eval-corpus | merged | samples/10-*, samples/11-*, eval/dataset.json, scanner/main.py (clone-on-demand), tests/test_eval_dataset.py | dataset lines exist; `scan eval --dry` validates |
| 28 | semgrep packs per language + excludes; entry points: Express inline handlers, Django urls.py, FastAPI routers, PHP/Laravel; coverage mints anchors for symbol-less entries | static-detect | merged | scanner/adapter/static.py, scanner/app/reconcile.py, scanner/app/pipeline_v2.py, tests/test_static.py, tests/test_reconcile.py | NodeGoat semgrep noise ↓, mixed fixture entries for all 4 langs |
| 29 | LSP call hierarchy (callers/callees) on the Index port + tools + grep approximation; closure container fix | lsp-callgraph | merged | scanner/core/ports.py, scanner/adapter/index/*, scanner/adapter/tools.py, tests/test_lsp_* | gopls callHierarchy on samples; fake-client tests |
| 30 | Critic dominance check: pure analysis (same function, before sink, not in a skippable branch) + Critic instruction; tool wiring by lead | critic-dominance | merged | scanner/adapter/dominance.py, scanner/app/instructions.py, tests/test_dominance.py | unit tests on Go/Py/JS snippets |
| 31 | ParallelAgent → ADK Workflow migration (or documented no-go) | workflow-migration | merged | scanner/app/graph.py, tests/test_graph.py | suite green, deprecation warning gone or decision recorded |
| 32 | specialists core: registry, router (cwe → kind → generic, language overlay), tool subsets, per-specialist instruction sections, contract test per specialist | specialists-core | merged | scanner/app/specialists.py, scanner/app/instructions.py, scanner/adapter/tools.py (subset), tests/test_specialists.py, tests/test_contracts.py, tests/test_tools.py | route tests; contracts for every specialist |
| 33 | specialists graph: `_Graph.specialists` + `router` field, routing in _verify/_critic_pass/retry, Architect overlay param | specialists-graph | merged | scanner/app/graph.py, scanner/app/agents.py, tests/test_stages.py, tests/test_graph.py | activation names unchanged; fallback path keeps old tests green |
| 34 | Domain consultant: DomainMap types, skeleton extractors (Go structs/sqlc, Django, Prisma/Mongoose, middlewares), DomainModeler stage, consult_domain over the map + AgentTool | domain | merged | scanner/core/domain.py, scanner/adapter/domain.py, scanner/app/domain.py, scanner/app/pipeline_v2.py, tests/test_domain.py | extractors on fixtures; stage stores artifact domain_map |
| 35 | Knowledge consultant: OSV batch/GHSA/NVD/EPSS/KEV/deps.dev clients with cache, pre-pass enrichment of osv anchors, Knowledge AgentTool, EPSS/KEV in calibrate | knowledge | merged | scanner/adapter/knowledge.py, scanner/app/knowledge_agent.py, scanner/adapter/static.py, scanner/core/calibrate.py, tests/test_knowledge.py | fixture-driven tests, no network; offline GHSA_DIR |
| 36 | OWASP integration steps 1/2/4: full CWE map (WSTG/Top10 2021+2025/CheatSheet/ASVS), wstg_id/asvs_id end-to-end + SARIF taxonomies, remediation + attribution | owasp-integration | merged | scanner/adapter/owasp.py, scanner/core/types.py, scanner/app/reconcile.py, scanner/adapter/store.py, THIRD_PARTY_NOTICES.md, tests | owasp_rnd gap table shrinks; SARIF taxonomies test |
| 37 | wiring: runner builds the registry + Domain/Knowledge tools into specialists; live eval per specialist; reviewers; GATE 2 | main + live-eval-specialists | merged (reviewed; GATE 2 done) | scanner/app/runner.py, scanner/adapter/tools.py, scanner/adapter/store.py, tests/test_runner_wiring.py, eval/agents.py | pytest green; reviews clean |
| 38 | `llm` specialist for AI projects: OWASP Top 10 for LLM Apps (LLM01 prompt injection, LLM05 improper output handling, LLM02 sensitive info, LLM07 system-prompt leakage, LLM06 excessive agency) + agentic threats; detectors for LLM call sites as sources+sinks; CWE-1427 map; skills; eval sample | — | backlog | scanner/adapter/static.py, scanner/app/specialists.py, scanner/skills/llm-*.md, scanner/adapter/owasp.py, samples/12-llm-app | eval case: prompt→exec confirmed, validated neighbour rejected |
| 39 | ground stage artifacts in code, not in prompts: symbols of entities/threats/rules verified via the Index (else notes/gaps), wstg_id verified against owasp.py, criticality/trust boundaries → calibrate exposure and queue priority, live-eval graders for fabricated ids | artifact-grounding | merged | scanner/app/pipeline_v2.py, scanner/app/reconcile.py, scanner/core/calibrate.py, scanner/adapter/store.py, eval/agents.py, tests | fabricated WSTG ids dropped; ungrounded rules land in gaps |
| 40 | OWASP step 3: ~25 WSTG verdict skills + 12 control skills (Cheat Sheets) in our own words; skill_for returns [wstg, class, control]; Specialist.skills per roster; skills payload key | owasp-skills | merged | scanner/skills/*, scanner/adapter/skills.py, scanner/app/specialists.py (skills lists only), tests/test_skills.py | owasp_rnd gap 'WSTG tests with no skill' 92 → ≤ 60; contract tests green |
| 41 | quality phase (orch-refine-code): audits → ports split + RunStore/Router, fakes library, docs/architecture.md + ADR 0002–0006, CLI/eval/web cleanup, fs/entrypoints split, Literal vocabularies + CWE taxonomy, Settings as the only env reader, tools package + one agent factory, layer guard tests | main + 9 agents | merged (reviews: python 4 high + 8 medium fixed, code-review approve + 1 medium fixed) | scanner/**, tests/**, docs/** | 210+ tests green after every step; reviews clean |
| 42 | direct findings lane: osv/gitleaks/semgrep-ERROR anchors → store.report without LLM (dedup, OSV/EPSS/KEV/fixed-version enrichment, reachability note, secrets redacted); excluded from the queue and the Critic; confidence normalisation in the gate | fork agent | merged (f528749..2beed1b + M2) | scanner/app/reconcile.py (split_direct), scanner/app/pipeline_v2.py, scanner/adapter/knowledge.py, scanner/adapter/tools/gates.py, scanner/adapter/store.py, tests | tests first; NodeGoat re-run shows the queue is code-only; code-reviewer + security-reviewer (secrets path) |
| 43 | migrate PipelineV2 to the ADK 2.9 Workflow graph (FunctionNode pre-pass, single_turn stages with output_schema, JoinNode reconciler, dynamic investigator node with parallel workers, terminal reporter); ADR-0001 revisited | architect agent → dev | in progress (steps 1–7 done: c0170a9 0070db3 7388619 d7d6d36 e08697c 31aa995; PIPELINE=v3 opt-in) | scanner/app/pipeline_v2.py, graph.py, runner.py, web/fullscan/agent.py, docs/adr/0007 | blueprint reviewed at GATE 1; all pipeline tests green on the Workflow root; adk web renders the graph |
| 44 | Shannon-style discovery: Planner (coverage guarantee, adversarial share), Triage sweep → specialist audit, ported hunting checklists, existence-check gate for synthetic anchors | dev-team | planned | scanner/app/instructions.py, reconcile.py, pipeline_v2.py, tools/gates.py, skills | NodeGoat re-run recalls ≥5 of the known code vulns |
| 10 | workflow e2e test + tracing check | workflow-test | merged (Jaeger: 10 spans on a fake run) | tests/test_workflow.py, tests/test_observe.py | `uv run pytest tests/test_workflow.py tests/test_observe.py` green (unit-level, done); pending: real run with `OTEL_EXPORTER_OTLP_ENDPOINT` set shows spans in Jaeger and the session in `adk web` |

Blocked (04, 08): нужен LLM-ключ с запасом квоты — прогон на `.targets/bakery` упёрся в `429 RESOURCE_EXHAUSTED`.

## Contract (module APIs — owners must match these exactly)

### scanner/core.py (done)
Types (pydantic, `extra=ignore`): `Anchor, Candidate, Hypothesis, Dossier, Finding`.
Rules: `new_anchor_id, norm_severity, select_candidates, merge_duplicates, ground_hypothesis(h, has_anchor, has_symbol)->str|None,
validate_finding(f)->str|None, required_consults(a)->(bool,bool,str), check_consulted(a, evidence)->str|None, is_consult_ref`.
Constants: `CONFIRMED/REJECTED/UNCERTAIN, KINDS, STATE_ROUND, STATE_BUDGET_EXHAUSTED, STATE_STOP_REASON`.

### scanner/adapter/static.py (card 01)
```python
class ScanResult(BaseModel): anchors: list[Anchor]; ran: list[str]; failed: dict[str, str]
def detect_langs(target: Path) -> set[str]            # {"go","python","javascript","typescript","php"}
def scan(target: Path, skip_deps: bool = False) -> ScanResult
    # gosec -fmt sarif -quiet -no-fail ./...  (if go)         → tool "gosec"
    # semgrep --sarif --quiet --metrics=off --config <SEMGREP_CONFIG or auto> .  (if non-go langs or env) → "semgrep"
    # osv-scanner --format json -r .  (unless skip_deps)      → "osv", rule_id = advisory id (GHSA-/CVE-), file = manifest, line 1
    # gitleaks detect --no-banner --report-format json --report-path /dev/stdout --exit-code 0 → "gitleaks", cwe "CWE-798"
    # missing binary / failure → failed[tool] = reason, never raises. Anchors go through merge_duplicates.
    # SARIF: cwe from result.properties.cwe|cwe_ids|tags, then rule.properties, then rule.relationships[target.toolComponent.name=="CWE"]
def entry_points(target: Path) -> list[Candidate]      # kind="entry", symbol=<func name>, file, line; text detectors:
    # go: http.HandleFunc/Handle("/x", h), r.HandleFunc, r.GET/POST(...); python: @app.route/get/post..., FastAPI; js: app.get/post/router.x
def has_symbol(target: Path, fqn: str) -> bool         # last "." segment is defined: func|def|function|class|const|var <name>
def read_lines(target: Path, file: str, line: int, window: int = 3) -> str   # raises FileNotFoundError
```
### scanner/adapter/store.py (card 01)
```python
class Store:
    def __init__(self, path: str)                      # sqlite, schema created; tables runs, anchors, hypotheses, dossiers, findings, gate_log, notes
    def start_run(self, target: str) -> "Run"          # marks orphan running runs as stopped
class Run:
    id: int; target: str
    def save_anchors(self, anchors: list[Anchor]) -> None
    def anchors(self) -> list[Anchor]
    def anchor(self, id: str) -> Anchor | None
    def put_hypotheses(self, round: int, hs: list[Hypothesis]) -> None
    def put_dossiers(self, round: int, ds: list[Dossier]) -> None
    def report(self, f: Finding) -> Finding            # assigns id "f_<n>"; dup (same anchor_id, or same cwe+file+line) → returns existing (higher confidence replaces status/evidence/confidence)
    def findings(self) -> list[Finding]
    def log_gate(self, anchor_id: str, reason: str) -> None
    def add_note(self, text: str, ref: str = "") -> None
    def notes(self) -> list[dict]                      # [{"time","text","ref"}]
    def finish(self, status: str, reason: str = "") -> None   # done|stopped|failed
    def write_report(self, out_dir: Path) -> Path      # SARIF 2.1.0 of confirmed findings → out_dir/report.sarif
    def write_summary(self, out_dir: Path) -> Path     # {"run_id","target","confirmed","rejected","uncertain","findings":[...],"gate_refusals":n} → out_dir/summary.json
```
### scanner/adapter/tools.py (card 02)
```python
def lead_tools(run: Run, candidates: Callable[[], list[Candidate]], has_symbol: Callable[[str], bool]) -> list[Callable]
    # list_candidates(kind="", cwe="", severity="", limit=0), dispatch(hypothesis: dict) -> {"hypothesis_id","accepted","reason"},
    # list_anchors(cwe="", severity="", file="", limit=0), list_findings(), note_add(text, ref=""), note_list(), consult_knowledge(query)
def verifier_tools(run: Run, target: Path, has_symbol) -> list[Callable]
    # list_anchors, report_finding(anchor_id, title, status, evidence: list[str], hypothesis_id="", severity="", confidence=0.0, cwe="", file="", line=0)
    #   gate order: anchor exists → cwe/file/line empty-or-equal → check_consulted (unless uncertain) → confirmed: at least one non-consult
    #   evidence line found (strip-compare) in read_lines(file, line) → validate_finding → run.report; refusal → run.log_gate + {"status":"error","reason":...}
    # list_findings, read_file(path, start=1, end=200) (inside target only), grep(pattern, path=".") (rg/grep -n, inside target),
    # shell(command) (cwd=target, timeout 60s, output capped 20k; ponytail: host exec, no sandbox),
    # note_add, note_list, consult_knowledge(query) (osv.dev: /v1/vulns/<id> or /v1/query {package,version}; returns advisory + "knowledge:<id>"),
    # consult_domain(entity) (heuristic: grep entity decl + owner/user-id comparisons nearby; returns "domain:<entity>" ref)
# Every tool returns a dict; errors as {"status":"error","reason":...} — never raise into the model.
```
### scanner/app/{agents,graph,fullscan,pipeline_v2}.py (card 03)
```python
LEAD_INSTRUCTION / VERIFIER_INSTRUCTION: port the Go prompts + lead-planning / verifier-proof skill text (inline, no skill loader).
def budget_callback(limit: int, per_branch: bool) -> before_model_callback  # counts calls; over limit → state[STATE_BUDGET_EXHAUSTED]=True and return LlmResponse(error) that ends the turn
def log_tools_callback(tool, args, ctx) -> None
def new_lead(model, tools, max_calls) -> LlmAgent     # include_contents="none"; instruction gets RoundInput via state key "round_input" ({round_input})
def new_verifier(model, tools, max_calls) -> LlmAgent # include_contents="none"; hypothesis JSON via instruction (clone per hypothesis)
class FullScan(BaseAgent):  # ctor(name, lead, verifier, run, candidates_fn, has_anchor, has_symbol, max_rounds=4, max_hyps=8, max_parallel=3)
    # loop: RoundInput{round,target,candidates,last_round} → state → run lead (sub-branch) → parse RoundOutput JSON best-effort from final text
    #   (no valid JSON → finish) → gate hypotheses (ground_hypothesis, cap max_hyps, assign ids h<round>-<n>) → run.put_hypotheses
    #   → route: dispatch&&accepted&&round+1<max_rounds ? verify : finish
    # verify: ParallelAgent per chunk of max_parallel with verifier.clone(name=f"verify_r{r}_{i}", instruction=base+hypothesis JSON)
    #   → dossier per hypothesis from STORE facts (findings with hypothesis_id, else anchor_id w/o foreign id; best of confirmed>rejected>uncertain),
    #   model JSON only adds notes/new_hypotheses → run.put_dossiers → loop
    # budget exhausted (state flag) → finish; stop reason → state[STATE_STOP_REASON]; state via yielded Event(actions=EventActions(state_delta=...))
```
### scanner/main.py + scanner/app/runner.py (card 03)
`python -m scanner full --target <path> [--deps]` → Store(STATE_PATH or .state/state.db) → static.scan → run.save_anchors → candidates = entry_points + sink anchors
→ model from env (GOOGLE_API_KEY → `LLM_MODEL` or "gemini-flash-latest"; else LiteLlm(model=f"openai/{LLM_MODEL or gpt-4.1}", api_base=LLM_BASE_URL, api_key=LLM_API_KEY))
→ Runner(app_name="scanner", agent=FullScan, session_service=InMemorySessionService()) → report to `.runs/<unixtime>/` → print summary → exit 2 if confirmed, 1 on error, 0 clean.
`python -m scanner eval [dataset.json]` → per case run full, precision/recall/F1 by (cwe, file, |line-expected|<=tolerance); exit 0 iff all expected confirmed and no false positives.
Env: LEAD_MAX_MODEL_CALLS=40, VERIFIER_MAX_MODEL_CALLS=30, BUGFINDER_MAX_ROUNDS=4, BUGFINDER_MAX_HYPS=8, STATE_PATH, SEMGREP_CONFIG. `.env` loaded if present (python-dotenv is not installed: parse KEY=VALUE lines manually).

## Rules for owners
- Only touch your card's files. Tests: pytest, minimal, no fixtures beyond tmp_path.
- ADK 2.9.0 is installed in `.venv` (`uv run ...`); read the source under `.venv/lib/python3.13/site-packages/google/adk/` when unsure.
- Ponytail: stdlib first, no abstractions with one implementation, mark deliberate corners with `# ponytail:`.
- Finish with a handoff: what works, what's skipped, how to run the merge gate.
