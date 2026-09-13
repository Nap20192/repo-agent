# Architecture audit — repo-agent2 (ecc:architect, 2026-09-12)

Scope: `scanner/{core,adapter,adapter/index,app}`, `web/`, `eval/`, `tests/`, CLAUDE.md, README, BOARD, ADR-0001,
`docs/plans/specialists.md`. Method: import graph by grep, line counts, source reading.

Sources: [CA] R. C. Martin, *Clean Architecture* (2017), ch. 7–11 (SOLID), ch. 22 (dependency rule).
[HEX] A. Cockburn, *Hexagonal Architecture*, https://alistair.cockburn.us/hexagonal-architecture/.
[DDD] E. Evans, *Domain-Driven Design* (2003), ch. 4 "Isolating the Domain". [PEP8] https://peps.python.org/pep-0008/ ·
[PEP20] /pep-0020/ · [PEP257] /pep-0257/ · [PEP484] /pep-0484/. [GPSG] Google Python Style Guide,
https://google.github.io/styleguide/pyguide.html. [REF] M. Fowler, *Refactoring* 2nd ed. (2018), ch. 3 smells.
[ADK] Google ADK docs, https://google.github.io/adk-docs/.

## 1. Layer map as built vs the dependency rule

| Rule (CLAUDE.md) | Result | Evidence |
|---|---|---|
| `core` imports nothing of ours | ✅ | stdlib + pydantic only (pydantic in the domain leaf is a tolerated framework dependency: [CA ch.22] would prefer none, [DDD ch.4] accepts a supporting library). |
| `adapter` never imports `app` | ✅ | no `scanner.app` under `scanner/adapter/`. |
| `app → adapter` inward | ✅ direction, ❌ on concretes, not ports | `graph.py` (`static`, `skills.skill_for`), `reconcile.py` (`owasp`), `specialists.py` (`static`, `tools`), `pipeline_v2.py` (`adapter.domain.extract`, inline), `runner.py` (legit composition root — [HEX] "configurator"). |
| `main.py` CLI only | ❌ | `score`, `_ensure_target` (git clone), `validate_case` — eval use-case logic in the CLI layer. |
| hidden (indented) imports | ⚠ | `pipeline_v2.py`, `tools.py` (try/except ImportError around a package that always exists → dead fallback `_GrepIndex`), `static.py` (`knowledge`), `runner.py`, `observe.py`. Inline imports hide edges [GPSG 2.2]. |
| adapter hub | ⚠ | `adapter/static.py` is imported by 8 modules for `LANG_EXT`, `files`, `FILE_CAP`, `read_lines` — a filesystem "God module" [REF Large Class / Divergent Change]. No cycles. |

Only one port exists (`core/ports.py:Index`). Everything else the app needs from outside (store, skills catalog,
OWASP catalog, language table, entry-point detector) is reached through concrete adapter modules — the hexagon
has one side [HEX; CA ch.11 DIP].

## 2. SOLID per module

| Module | SRP | OCP | LSP | ISP | DIP |
|---|---|---|---|---|---|
| `adapter/tools.py` (446 l) | ❌ five tool sets + report gate + disprove gate + an osv HTTP client duplicating `knowledge.osv_vuln` + grep `consult_domain` duplicating `app/domain.make_consult_domain` + roster name sets | ⚠ adding a tool = edit 2–3 lists | — | ❌ consumers get all 9 `Index` methods | ⚠ `_default_index` imports the adapter package itself |
| `app/graph.py` (287 l) | ❌ JSON parsing, activation cloning, deadline helper, dossier assembly, router dispatch, fan-out, retry, critic pass, dead v1 types `RoundInput/RoundOutput` | ⚠ new role = edit `_pick` | — | — | ❌ `store: Any`, `router: Any` |
| `adapter/static.py` (381 l) | ❌ fs walk + 4 scanner drivers + SARIF/OSV parsing + 4-language entry detectors + symbol grep + reader + redaction | ❌ new language = if/elif chain + `LANG_EXT` + `_DEF_KW` [REF Replace Conditional with Polymorphism]; new scanner = if-chain | — | — | hub imported by 8 modules |
| `app/runner.py` | ❌ .env parsing, model choice, session service, tracing, wiring, pre-pass, report; 10 `os.environ` reads | — | — | — | ✅ as composition root [HEX configurator]; but appends to `LlmAgent.tools` after construction (temporal coupling) |
| `adapter/index/*` | ✅ | ✅ `LANGUAGES` table | ⚠ `FallbackIndex` requires `primary.failed`, not in `Index`; `GrepIndex.failed` exists only to fit → implicit port `Index+failed` [CA ch.9]; `tools._GrepIndex` implements 6/9 methods → `AttributeError` on `callers` | — | — |
| `core/ports.py:Index` | — | — | — | ❌ 9 methods; runner already narrows by passing bound methods; dominance needs `symbols` only; `_lsp_tools` needs 6 | — |
| `adapter/store.py` | ⚠ `Run` = repository + SARIF writer + summary writer + calibration; imports `owasp` and `knowledge` | — | — | — | persistence reaching into two catalogs |
| `app/specialists.py` | ✅ registry + router | ⚠ one specialist = 3 files (`REGISTRY`, `tools.<NAME>_TOOLS`, `instructions.SPECIALIST_SECTIONS`) | — | — | ❌ imports `tools`, `static` concretes. **CWE truth duplicated**: `core/types.py` AUTHZ/TAINT sets vs `specialists.py` cwes: CWE-352 routes to `authz` but the gate needs no `domain:` consult [REF Shotgun Surgery] |
| `adapter/knowledge.py` | ⚠ 6 HTTP clients + SQLite cache + enrichment + reachability; reads `PYTEST_CURRENT_TEST` (production code aware of the test runner) | — | — | — | — |
| `app/reconcile.py` | `ground_artifacts` on raw dicts though the pydantic models exist [REF Primitive Obsession]; a "pure fn" module imports `adapter.owasp` | — | — | — | — |

## 3. Smells with metrics
| Smell [REF] | Instances |
|---|---|
| Long module | `tools.py` 446, `static.py` 381, `knowledge.py` 313, `instructions.py` 300, `graph.py` 287, `lsp.py` 274, `owasp.py` 261, `eval/agents.py` 545 |
| Function > 40 lines | `tools._code_tools` 78, `_lsp_tools` 66, `_common_tools` 66, `verifier_tools` 64; `pipeline_v2._run_async_impl` 70; `reconcile.ground_artifacts` 65; `graph._verify` 49; `knowledge._enrich_one` 43; `eval.trial_taint_critic` 55 |
| Params > 5 | `report_finding`/`_gate` 10 (LLM signature; `_gate` could take a `Finding`); `graph._retry_json` 7; `pipeline_v2._stage` 6; `eval._pick` 9 |
| Output parameters | `_verify(..., out)`, `_stage(..., out)`, `_model_threats(..., out)` |
| Duplicated helpers | path confinement ×5 (`tools._inside` ×2, `static.read_lines`, `grep._lines`, `dominance`); 2 MiB literal in grep.py vs `static.FILE_CAP`; `grep.definition_range` ≡ `_body_end`; `LlmAgent(...)` boilerplate ×7; intent lookup ×2 in store; `SEMGREP_CONFIG` ×2; osv client ×2 (`tools.consult_knowledge`, `knowledge.osv_vuln`); `consult_domain` ×2 (`tools.py`, `app/domain.py`) |
| `Any` fields [PEP484] | `graph.py store/router`, `pipeline_v2.py index` (bag field for the runner to close) |
| Flags read deep | `JSON_RETRY`, `STAGE_TIMEOUT`, `PYTEST_CURRENT_TEST`; import-time env `OSV_MAX`, `INDEX_MAX_*` (untestable after import) [GPSG 2.5] |
| Dead code | `RoundInput/RoundOutput`, `tools._GrepIndex/_default_index`, `reconcile.adversarial_sweep` (tests only), `app/domain.make_consult_domain` (eval only — runner wires the grep heuristic path instead) |

## 4. Naming / readability
- `specialists.ROUTER` — a function in CAPS [PEP 8]; `route`'s "docstring" sits after a statement → not a docstring [PEP 257].
- Private names imported across modules: `pipeline_v2` (`_activation`, `_Graph`, `_with_deadline`), `eval/agents.py` (`_activation`, `_text_of`), `grep.py` (`static._DEF_KW`), tests (`tools._lsp_tools`, `static._run_jobs`) [PEP 8; GPSG 2.2].
- Three modules named `domain` (`core/`, `adapter/`, `app/`) while "domain" also means the DDD leaf [DDD ch. 2].
- Misleading names: `graph.py` (fan-out/retry/dossier), `static.py` (fs + detectors), `store.Run` (unit-of-work + exporters); `main.py` holds eval logic contra CLAUDE.md "CLI only".
- `web/fullscan/agent.py`: `sys.path` hack, full pre-pass at import [GPSG 3.17].
- Docstrings ≈ 55 % of public callables; missing on `static.detect_langs/entry_points/has_symbol/read_lines`, `store.Store/Run` + 14 methods, 3 of 4 `agents.new_*`, `callbacks.log_tools_callback`.

## 5. Tests
No `conftest.py`. Test modules act as libraries: `tests.test_graph` ← 6 files; `tests.test_tools` ← `test_specialists` (a second `FakeRun`); `tests.test_lsp_index` ← 3 files; `tests.test_stages.Node` ← `test_domain`. `FakeRun` is the de-facto `RunStore` port → make it the Protocol. Positive: per-node tests, roster contract tests, fake LSP client ([HEX] "test per boundary").

## 6. Refactor task list (what — fixes — files — effort — risk)
1. `RunStore`/`Router`/`Closeable` Protocols in `core/ports.py`; type `_Graph.store/router`, `PipelineV2.index`; assert `FakeRun` conforms — DIP, `Any` — S — low.
2. Split `Index` → `SymbolLocator`/`Definitions`/`CallGraph`/`Closeable` + `Degradable(failed)`; delete `tools._GrepIndex/_default_index` — ISP, LSP — M — low.
3. `tests/conftest.py` + `tests/fakes.py` (single FakeRun/FakeVerifier/FakeClient/Node) — test-as-library — M — low.
4. One CWE taxonomy in `core/types.py`; router and gate derive from it — shotgun surgery — S — med (CWE-352 gate semantics).
5. `adapter/tools/{gates,code,lsp,common,rosters}.py`; one `_inside`; roster tool sets next to `Specialist` — SRP, duplication — M — low.
6. `adapter/fs.py` (`files`, `LANG_EXT`, `FILE_CAP`, `read_lines`, `inside`) + `adapter/entrypoints.py` per-language detector table — God module, OCP — M — low.
7. One `new_agent(...)` factory; Knowledge AgentTool injected at build, not appended — duplication, temporal coupling — S — low.
8. Runner wires map-backed `consult_domain` with grep fallback in one impl; `tools.consult_knowledge` → `knowledge.osv_vuln` — duplicate impls — S — med (model-visible).
9. `Settings` built once in runner; no `os.environ` in graph/pipeline/knowledge/static/lsp; drop `PYTEST_CURRENT_TEST` — deep flags — M — low.
10. `ground_artifacts` over typed models returning a dataclass; `_verify/_stage` return values, not out-dicts — primitive obsession, out-params — M — low.
11. Eval logic → `eval/dataset.py`; `ROUTER → route_name`; fix `route` docstring; publicize `Graph/activation/with_deadline`; delete `RoundInput/Output` — naming, PEP 8/257 — S — low.
12. `web/` lazy `prepare()`, drop the `sys.path` hack via pyproject — import side effects — S — low (verify the `adk web` loader).

## ADR candidates
1. Ports live in `core/ports.py`; app imports adapter concretes only in `runner.py`.
2. One CWE taxonomy and the consult-requirement rule per CWE.
3. Index port split (ISP) and the degradable-adapter contract. 4. Settings object as the only env reader. 5. Test fakes as a shared library conforming to the ports.
