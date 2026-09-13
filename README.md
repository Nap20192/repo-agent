# scanner — git-agent3 workflow on ADK Python

Гибридный сканер: статика (gosec, semgrep, gitleaks, osv-scanner) даёт Anchors,
текстовые детекторы — entry points; граф `Architect → ThreatModeler → Reconciler → Investigator ⇄ очередь → Critic`
(Google ADK) проверяет гипотезы под гейтами `dispatch` (заземление) и `report_finding`
(якорь, координаты, цитата в коде, consult-ссылка); Critic после петли пытается опровергнуть
каждую confirmed-находку (`disprove_finding` с контрцитатой из кода → uncertain). Вердикт досье берётся из стора,
не из прозы модели. Состояние прогона — SQLite `.state/state.db`; выгрузка — `.runs/<ts>/`.

Не перенесено из Go-версии: Docker-песочница (команды идут на хосте), go/ssa и LSP-индекс
(символы — LSP или grep-fallback), Domain Map (консультант `domain` — саб-агент).

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

Один статический ADK Workflow из семи узлов (`scanner/app/graph/workflow.py`, ADR-0010):

```
START → scan → build_skeleton → direct_findings → model → plan ─(пусто)→ export
                                                          └(иначе)→ audit → critique → export
```

- `scan` — сканеры (gosec/semgrep/osv/gitleaks) → якоря в SQLite State; `direct_findings` — osv/gitleaks/semgrep-ERROR
  становятся находками без модели и без гейта (card 42).
- `model` — один LLM-этап: архитектура + угрозы одним ответом, заземлённые по индексу (символ должен существовать).
- `plan` — якоря + угрозы + baseline по точкам входа → очередь гипотез; пустая → сразу export.
- `audit` — раунды: гейт заземления → fan-out агента `verify`; к каждой активации подмешивается секция класса
  (taint / authz / dependency / secrets / config по CWE → kind) и языковой overlay; вердикт — только через `report_finding`.
- `critique` — dedupe, затем `critic` по каждой подтверждённой находке: опровергнуть можно только `disprove_finding`
  с контр-цитатой; JSON критика — аннотация `review`.
- `export` — детерминированная калибровка, тайминги, стоп-причина → SARIF + summary в `.runs/<ts>/`.

Консультанты `knowledge` (OSV/GHSA/NVD/EPSS/KEV) и `domain` (владение/правила по коду) — саб-агенты `verify`/`critic`.

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
правил (`scanner/adapter/domain.py`); консультант `domain` — саб-агент (AgentTool) инвестигаторов/критиков: тул `domain_map` по карте, затем grep/read_file/lsp по коду (карта 49;
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
| `THREAT_MODEL` | включить Architect/ThreatModeler | on |
| `DOMAIN_MAX_MODEL_CALLS` | бюджет консультанта `domain` на один вопрос | 8 |
| `CRITIC` | включить адверсариальный проход Critic | on |
| `VERIFIER_MAX_MODEL_CALLS` | бюджет вызовов Investigator'а | 30 |
| `CRITIC_MAX_MODEL_CALLS` | бюджет вызовов Critic'а | 20 |
| `MODEL_MAX_MODEL_CALLS` | бюджет вызовов Architect | 40 |
| `KNOWLEDGE_MAX_MODEL_CALLS` | бюджет вызовов Knowledge AgentTool | 10 |
| `STATE_PATH` | SQLite State (якоря, гипотезы, досье, находки, artifacts) | `.state/state.db` |
| `SESSIONS_PATH` | SQLite ADK-сессий (видны через `adk web`) | `.state/sessions.db` |
| `SKIP_DEPS` | пропустить osv-scanner (SKIP_DEPS=1) | off |
| `KNOWLEDGE_CACHE` | SQLite кэш OSV/GHSA/NVD/EPSS | `.state/knowledge.db` |
| `KNOWLEDGE_ENRICH` | обогащать osv-якоря из кэша и APIs | on |
| `GHSA_DIR` | директория офлайн GHSA (вместо GitHub API) | — |
| `GITHUB_TOKEN` | токен GitHub (снять лимит GHSA) | — |
| `NVD_API_KEY` | ключ NVD API | — |
| `INDEX_MAX_FILES` | лимит файлов индекса | 3000 |
| `INDEX_MAX_BYTES` | лимит памяти индекса в байтах | 30M |
| `WORKSPACE_ROOT` | adk web `fullscan`: цель из сообщения только под этим каталогом; клоны GitHub — в `.targets/` под ним | cwd |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP-экспорт трассировки (например, http://localhost:4318) | — |
| `OTEL_SERVICE_NAME` | имя сервиса в OTLP | `scanner` |

osv-scanner сканирует явные манифесты (`-L <manifest>` на каждый go.mod/package-lock.json/…) —
git-aware обход osv-scanner ничего не находит в мелком клоне без `.git`.

**Тесты:** `tests/fakes.py` — общие test doubles (FakeRun, fake agents); `tests/test_layers.py` — архитектурные гарды
(core ← ничего, adapter ← core only, test модули не импортируют друг друга); маркер `tests/live` для live-eval.

Модули: `scanner/core/{types,rules,calibrate,settings,ports,domain}.py` (доменный лист), `scanner/adapter/static.py`
(сканеры → якоря), `scanner/adapter/{store,owasp,domain,dominance,knowledge,entrypoints,fs,skills}.py` (адаптеры),
`scanner/adapter/tools/{common,code,lsp,gates,rosters}.py` (агент-тулы), `scanner/adapter/index/{lsp,grep,rpc,languages,callgraph}.py`
(код индекс), `scanner/app/{agents,specialists,knowledge_agent,pipeline,graph_nodes,graph,reconcile,domain}.py` (специалисты и граф),
`scanner/app/{callbacks,observe,runner,settings}.py` (исполнение), `scanner/main.py` (CLI, eval), `web/fullscan/agent.py` (`adk web`).
