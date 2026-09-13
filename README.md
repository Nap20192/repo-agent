# scanner — git-agent3 workflow on ADK Python

Гибридный сканер: статика (gosec, semgrep, gitleaks, osv-scanner) даёт Anchors,
текстовые детекторы — entry points; граф `Architect → ThreatModeler → Reconciler → Investigator ⇄ очередь → Critic`
(Google ADK) проверяет гипотезы под гейтами `dispatch` (заземление) и `report_finding`
(якорь, координаты, цитата в коде, consult-ссылка); Critic после петли пытается опровергнуть
каждую confirmed-находку (`disprove_finding` с контрцитатой из кода → uncertain). Вердикт досье берётся из стора,
не из прозы модели. Состояние прогона — SQLite `.state/state.db`; выгрузка — `.runs/<ts>/`.

Не перенесено из Go-версии: Docker-песочница (команды идут на хосте), go/ssa и LSP-индекс
(символы — LSP или grep-fallback), Domain Map (`consult_domain` — эвристика).

## Слои (`scanner/core` / `adapter` / `app`)

Архитектура, порты, инварианты гейтов и источники (SOLID, Clean/Hexagonal Architecture, PEP, ADK) —
`docs/architecture.md`; решения — `docs/adr/`; аудиты — `docs/audits/`; план фазы качества — `docs/plans/quality.md`.

- `scanner/core` — типы (`types.py`), чистые правила (`rules.py`), calibrate (`calibrate.py`),
  settings (`settings.py`), порты (`ports.py`), domain-карта (`domain.py`): доменный лист без ADK и I/O.
- `scanner/adapter` — SQLite State (`store.py`), OWASP (`owasp.py`), domain-модель (`domain.py`), dominance
  (`dominance.py`), knowledge-кэш (`knowledge.py`), entry points (`entrypoints.py`), файловая система (`fs.py`),
  скиллы (`skills.py`); пакет `scanners/` (один сканер — один файл: `gosec.py`, `semgrep.py`, `osv.py`, `gitleaks.py`,
  `sarif.py`, `process.py` — единственная точка запуска подпроцессов, `scan.py`); пакет `tools/` (один инструмент —
  один файл с `make(ctx: ToolContext)`: `code/`, `lsp/`, `gates/`, `store/`, `consult/`, `knowledge/`; `registry.py` —
  имя → фабрика в порядке, который видит модель; `context.py` — ToolContext); пакет `index/` (LSP-адаптеры и grep
  fallback: `lsp.py`, `grep.py`, `rpc.py`, `languages.py`, `callgraph.py`).
- `scanner/app` — пакет `agents/` (одна папка на агента: `agent.py` с `SPEC = AgentSpec(...)`, `instruction.py`,
  `tools.py` с ростером имён; `base.py` — единственная фабрика `new_agent` + `build(spec, ...)`; `shared.py` — общие
  секции промптов; `registry.py` — `AGENTS`, специалисты `REGISTRY` и роутер CWE → kind → fallback); пакет `graph/`
  (`nodes/` — один узел на файл с фабрикой `<node>_node(...)`, `stage.py` и `workers.py` — две обёртки, через которые
  агент становится узлом, `workflow.py` — `NODES` и список рёбер, `helpers.py`, `planning.py`, `reconcile.py`);
  колбэки (`callbacks.py`), трассировка и сжатие (`observe.py`), сборка и прогон (`runner.py`: `build_agents()` —
  один цикл по `AGENTS`), settings (`settings.py`). Шаблон «добавить агента» — `docs/adr/0009-feature-folders.md`.
- `scanner/main.py` — только CLI, вся логика в `scanner/app/runner.py`.
- `web/fullscan/agent.py` — точка входа `adk web` (тот же граф); `web/<agent>/agent.py` — каждый агент отдельно
  (`runner.standalone`), с seed-кейсами `*.evalset.json` и code-грейдерами `eval/adk_metrics.py` для `adk eval`.

## Пайплайн

Staged-конвейер по мотивам Shannon capella: `Architect → ThreatModeler → Reconciler → Investigator ⇄
очередь → Critic → Reporter`. Architect интерпретирует скелет (entry points, якоря) в
ArchitectureModel; ThreatModeler выдаёт заземлённые threats и deployment intent; Reconciler
сливает якоря сканеров и threats в одну очередь без дублей, чеканя синтетический якорь
(`tool=threatmodel`, file:line определения символа) для угроз без якоря сканера, чтобы гейт
`report_finding` остался единственным и якорным. Артефакты стадий — в таблице `artifacts` State
(resume пропускает готовые стадии). Граф — статический ADK 2.9 `Workflow` из 24 узлов по стадиям Capella (Shannon): `scan → build_skeleton →
direct_findings → (architect ∥ recon) → join_model → domain_modeler → threat_modeler → ground → plan → route_plan →
triage_sweep → fold_triage → audit → route_research → dedupe → review → route_survivors → route_intent →
critic → confirm → calibrate → export` (ADR-0008; fan-out/JoinNode, route-карты, parallel-worker для triage/review/
critic/confirm, динамический цикл только в `audit`; `docs/workflow-nodes.md` описывает каждый узел). `THREAT_MODEL=0` — без Architect/ThreatModeler.
Инструкции стадий адаптированы из Mantis/Shannon (Apache-2.0), см. THIRD_PARTY_NOTICES.md.

**Прямые находки (direct lane).** Якоря, которые точно случились — osv-зависимости, gitleaks-секреты,
semgrep уровня ERROR — не идут в очередь и к Critic: `split_direct` отделяет их до стадий, `direct_finding`
делает из каждого confirmed-находку (`source=direct`) через дедуп стора, с advisory/CVSS/EPSS/KEV/fixed
из knowledge-кэша и подсчётом «пакет импортируется в N файлах» (`knowledge.imported_by`); секреты
редактируются. Модель занимается только кодом.

**Planner и Triage (Shannon-стиль поиска, карта 44).** Планировщик детерминирован (`reconcile.coverage`):
каждая непокрытая точка входа получает baseline-гипотезу с классами для охоты по словам маршрута, файла и
обработчика (`hunt_classes`: login → CWE-287/307/522, profile → 79/639, `:id` → 639/862, admin → 862/285,
search → 89/943, file → 22, redirect → 601, eval/template → 95/1336, regex → 1333), поэтому роутер отдаёт её
нужному специалисту с нужным скиллом; 25 % baseline'ов (детерминированно) несут adversarial-формулировку;
каждый production-файл, который никто не читает (`fs.source_files`, без тестов/фикстур), получает
file-baseline (приоритет 8, не больше 60). У каждого baseline свой якорь `entrypoint`, а гейт разрешает с
такого якоря подтвердить sink в другом месте (чеканится якорь `investigator`). Перед аудитом специалистом
батч baseline'ов проходит дешёвый **Triage** (`read_file`/`grep`/`lsp_symbols`, 4 вызова): непомеченные
становятся rejected-досье с причиной (покрытие доказуемо), помеченные несут класс и причину триажа в аудит;
сбой триажа помечает элемент (fail open). `TRIAGE=0` выключает.

## Сессии и трассировка

Каждый прогон сохраняет ADK-сессию в SQLite `SESSIONS_PATH` (app `fullscan`, user `user`,
session id `run-<n>-<target>`) — `scanner/app/runner.py:run_session`. `adk web web --port 8080
--session_service_uri=sqlite:///.state/sessions.db` показывает эти сессии в dev-UI.

`OTEL_EXPORTER_OTLP_ENDPOINT` (например, `http://localhost:4318` для Jaeger; UI Jaeger в этой
конфигурации — порт 16687) включает экспорт спанов через
`google.adk.telemetry.setup.maybe_set_otel_providers`; сервис по умолчанию — `OTEL_SERVICE_NAME=scanner`.
Сжатие истории сессии — `COMPACTION_INTERVAL`/`COMPACTION_OVERLAP` (`scanner/app/observe.py`): раз в
N вызовов старые события агента суммируются моделью, последние `OVERLAP` остаются дословно; агенты
работают с `include_contents="none"`, так что сжатие уменьшает сохранённую сессию, а не промпты.

## Бюджет вызовов модели

Бюджеты локальные: у Verifier/Critic/Architect/
ThreatModeler бюджет per-branch, исчерпание не глушит весь граф. Последний
разрешённый вызов лишает агента тулов и заставляет ответить финальным JSON немедленно
(`scanner/app/callbacks.py:budget_callback`).

## Индекс кода (LSP)

Порт `scanner/core/ports.py:Index` расщепляется по потребителю (ISP): `SymbolLocator` (gate, synthetic anchors),
`Definitions` (bodies: `symbols`, `definition_range`), `CallGraph` (reachability: `references`, `callers`, `callees`,
`path_to_entry`), плюс `Closeable` и `Degradable`. Адаптеры в `scanner/adapter/index/`: `LspIndex` на язык поверх
stdlib JSON-RPC (`rpc.py`) — gopls (Go), pyright (Python), typescript-language-server (TS/JS, две сессии);
`GrepIndex` как fallback; `MultiIndex` маршрутизирует по языку файла; `build_index(target)` собирает лениво,
сервер стартует при первом запросе. Агенты получают `lsp_symbols`, `lsp_definition` (≤120 строк) и `lsp_references`
(≤50 мест); `has_symbol`/`locate` для гейта идут через индекс. `read_file` по умолчанию 60 строк, grep ≤4k.
`tool_window_callback(keep=3)` заменяет старые результаты однострочным дайджестом.

## Специалисты и консультанты

Один Investigator и один Critic заменены реестром специалистов (`scanner/app/specialists.py`): investigators
`taint` (A03/A08/A10), `authz` (A01/A07), `dependency` (A06/A08), `secrets` (A02), `config` (A02/A05/A09) и критики
`taint_critic`, `authz_critic`, `dependency_critic`; `TOP10_COVERAGE` закрывает OWASP Top 10 2021 целиком (A04 —
через Domain-карту и ThreatModeler). Роутер детерминированный: CWE → kind → generic fallback; языковой оверлей
(Go / Node / Python) — суффикс инструкции по расширению файла. У каждого свой набор тулов (`subset()`),
скиллы и бюджет `SPECIALIST_<NAME>_MAX_CALLS`; `SPECIALISTS=0` возвращает одиночных Verifier/Critic.
Консультанты: **Domain** — стадия DomainModeler (после Architect) строит `domain_map` из схем, guard'ов и
правил (`scanner/adapter/domain.py`), `consult_domain` отвечает по карте (grep-эвристика как fallback;
`DOMAIN_MODEL=0` выключает стадию); **Knowledge** — пре-пасс обогащает osv-якоря через OSV/GHSA/NVD/EPSS/KEV с
SQLite-кэшем (`KNOWLEDGE_ENRICH=0` выключает, `GHSA_DIR` для офлайна, `GITHUB_TOKEN`/`NVD_API_KEY` снимают лимиты),
плюс AgentTool `knowledge` (веб-поиск: `WEB_SEARCH=tavily` + `TAVILY_API_KEY`) инъектируется в `dependency` и
`dependency_critic` через `specialists.build(knowledge_factory=)`.
OWASP-карта (`scanner/adapter/owasp.py`) покрывает 58 CWE: WSTG, Top 10 2021 и 2025, ASVS 5.0 с уровнем, cheat
sheet и remediation; SARIF несёт таксономии и `fixes[]`.

## Скиллы, калибровка, покрытие

- `scanner/skills/*.md` — 34 скилла (Strix через адаптацию git-agent3): per-CWE (sql-injection, xss, ssrf, idor…),
  analysis (counterevidence, severity-calibration, source-aware-discovery, verifier-proof). Тулы `list_skills` /
  `load_skill` у Investigator, Critic, Architect; `skill_for(cwe, kind)` кладёт подсказку в payload гипотезы.
- `scanner/core/calibrate.py` — report-only score по Shannon calibrate: `Hazard = (Impact + Likelihood) × Multiplier`,
  cap 10, exposure и intent-масштабирование; пишется в `summary.json` (`findings[].calibration`) и в SARIF
  `properties.calibration`, статус находки не меняет.
- Reconciler добавляет baseline-гипотезу (kind `entry`, низкий приоритет) на каждый entry point, который не
  покрыт ни якорем, ни угрозой (plan-правило Shannon: «файл, не попавший в investigation, не смотрит никто»).
- Инструкции всех агентов начинаются с operating principles Shannon; Critic идёт по 13 правилам review.

## Запуск

```
uv sync
# модель: GOOGLE_API_KEY (Gemini, по умолчанию самая дешёвая — gemini-flash-lite-latest)
# ИЛИ LLM_API_KEY + LLM_BASE_URL (+ LLM_MODEL) — OpenAI-совместимый
uv run python -m scanner full --target samples/02-vulnshop     # exit 0 чисто, 2 есть confirmed, 1 ошибка
uv run python -m scanner eval eval/dataset.json                # precision / recall / F1 по ground truth
uv run pytest -q
```

| Переменная | Назначение | По умолчанию |
|---|---|---|
| `GOOGLE_API_KEY` | ключ Google Gemini API | — |
| `LLM_API_KEY` | ключ OpenAI-совместимого API (вместо GOOGLE_API_KEY) | — |
| `LLM_BASE_URL` | базовый URL OpenAI-совместимого API | — |
| `LLM_MODEL` | модель (gemini-flash-lite-latest для GOOGLE_API_KEY) | — |
| `BUGFINDER_MAX_ROUNDS` | раунды investigation | 4 |
| `BUGFINDER_MAX_HYPS` | гипотез за раунд | 8 |
| `BUGFINDER_MAX_PARALLEL` | параллельных Investigator'ов | 3 |
| `STAGE_TIMEOUT` | таймаут стадии в секундах | 600 |
| `SPECIALISTS` | использовать специалистов (0 = одиночные Verifier/Critic) | on |
| `THREAT_MODEL` | включить Architect/ThreatModeler | on |
| `DOMAIN_MODEL` | включить DomainModeler и `consult_domain` | on |
| `CRITIC` | включить адверсариальный проход Critic | on |
| `TRIAGE` | дешёвый triage-проход по baseline'ам перед аудитом | on |
| `TRIAGE_MAX_CALLS` | бюджет вызовов Triage на элемент | 4 |
| `VERIFIER_MAX_MODEL_CALLS` | бюджет вызовов Investigator'а | 30 |
| `CRITIC_MAX_MODEL_CALLS` | бюджет вызовов Critic'а | 20 |
| `ARCHITECT_MAX_MODEL_CALLS` | бюджет вызовов Architect | 40 |
| `DOMAIN_MODELER_MAX_MODEL_CALLS` | бюджет вызовов DomainModeler | 12 |
| `THREAT_MODELER_MAX_MODEL_CALLS` | бюджет вызовов ThreatModeler | 6 |
| `KNOWLEDGE_MAX_MODEL_CALLS` | бюджет вызовов Knowledge AgentTool | 10 |
| `SPECIALIST_<NAME>_MAX_CALLS` | переопределить бюджет специалиста по имени | — |
| `STATE_PATH` | SQLite State (якоря, гипотезы, досье, находки, artifacts) | `.state/state.db` |
| `SESSIONS_PATH` | SQLite ADK-сессий (видны через `adk web`) | `.state/sessions.db` |
| `SKIP_DEPS` | пропустить osv-scanner (SKIP_DEPS=1) | off |
| `KNOWLEDGE_CACHE` | SQLite кэш OSV/GHSA/NVD/EPSS | `.state/knowledge.db` |
| `KNOWLEDGE_ENRICH` | обогащать osv-якоря из кэша и APIs | on |
| `GHSA_DIR` | директория офлайн GHSA (вместо GitHub API) | — |
| `GITHUB_TOKEN` | токен GitHub (снять лимит GHSA) | — |
| `NVD_API_KEY` | ключ NVD API | — |
| `WEB_SEARCH` | веб-поиск для Knowledge (`tavily`) | — |
| `TAVILY_API_KEY` | ключ Tavily API | — |
| `INDEX_MAX_FILES` | лимит файлов индекса | 3000 |
| `INDEX_MAX_BYTES` | лимит памяти индекса в байтах | 30M |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP-экспорт трассировки (например, http://localhost:4318) | — |
| `OTEL_SERVICE_NAME` | имя сервиса в OTLP | `scanner` |
| `COMPACTION_INTERVAL` | сжатие ADK-сессии каждые N вызовов (0 = off) | 0 |
| `COMPACTION_OVERLAP` | последние N событий — дословно | 2 |

osv-scanner сканирует явные манифесты (`-L <manifest>` на каждый go.mod/package-lock.json/…) —
git-aware обход osv-scanner ничего не находит в мелком клоне без `.git`.

**Тесты:** `tests/fakes.py` — общие test doubles (FakeRun, fake agents); `tests/test_layers.py` — архитектурные гарды
(core ← ничего, adapter ← core only, test модули не импортируют друг друга); маркер `tests/live` для live-eval.

Модули: `scanner/core/{types,rules,calibrate,settings,ports,domain}.py` (доменный лист), `scanner/adapter/static.py`
(сканеры → якоря), `scanner/adapter/{store,owasp,domain,dominance,knowledge,entrypoints,fs,skills}.py` (адаптеры),
`scanner/adapter/tools/{common,code,lsp,gates,rosters}.py` (агент-тулы), `scanner/adapter/index/{lsp,grep,rpc,languages,callgraph}.py`
(код индекс), `scanner/app/{agents,specialists,knowledge_agent,pipeline,graph_nodes,graph,reconcile,domain}.py` (специалисты и граф),
`scanner/app/{callbacks,observe,runner,settings}.py` (исполнение), `scanner/main.py` (CLI, eval), `web/fullscan/agent.py` (`adk web`).
