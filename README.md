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

- `scanner/core` — типы (`types.py`) и чистые правила (`rules.py`): доменный лист без ADK и I/O.
- `scanner/adapter` — сканеры → якоря (`static.py`), SQLite State включая таблицу `artifacts`
  для стадий v2 (`store.py`), OWASP-справочник (`owasp.py`), тулы агентов (`tools.py`).
- `scanner/app` — инструкции агентов (`instructions.py`), колбэки бюджета/логов (`callbacks.py`),
  фабрики агентов (`agents.py`), общий граф `_Graph` (`graph.py`),
  граф v2 (`pipeline_v2.py`), Reconciler (`reconcile.py`), трассировка и сжатие сессии (`observe.py`),
  сборка графа / прогон / CLI-обвязка (`runner.py`).
- `scanner/main.py` — только CLI, вся логика прогона в `scanner/app/runner.py`.
- `web/fullscan/agent.py` — точка входа для `adk web` (тот же граф, что и `scan full`).

## Пайплайн

Staged-конвейер по мотивам Shannon capella: `Architect → ThreatModeler → Reconciler → Investigator ⇄
очередь → Critic → Reporter`. Architect интерпретирует скелет (entry points, якоря) в
ArchitectureModel; ThreatModeler выдаёт заземлённые threats и deployment intent; Reconciler
сливает якоря сканеров и threats в одну очередь без дублей, чеканя синтетический якорь
(`tool=threatmodel`, file:line определения символа) для угроз без якоря сканера, чтобы гейт
`report_finding` остался единственным и якорным. Артефакты стадий — в таблице `artifacts` State
(resume пропускает готовые стадии). Lead (петля v1) вырезан: единственный граф — `PipelineV2`. `THREAT_MODEL=0` — без Architect/ThreatModeler.
Инструкции стадий адаптированы из Mantis/Shannon (Apache-2.0), см. THIRD_PARTY_NOTICES.md.

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

Порт `scanner/core/ports.py:Index` (`find_symbol`, `definition_range`, `references`, `symbols`), адаптеры в
`scanner/adapter/index/`: `LspIndex` на язык поверх stdlib JSON-RPC клиента (`rpc.py`) — gopls для Go,
pyright для Python, typescript-language-server для TS и JS (две сессии), `GrepIndex` как fallback, `MultiIndex`
маршрутизирует по языку файла; `build_index(target)` собирает всё лениво, сервер стартует при первом запросе.
Агенты получают `lsp_symbols`, `lsp_definition` (только тело символа, ≤120 строк) и `lsp_references`
(≤50 мест) вместо чтения файлов целиком; `has_symbol`/`locate` для гейта и синтетических якорей идут через
индекс. `read_file` по умолчанию 60 строк, grep ≤4k. `tool_window_callback(keep=3)` заменяет старые результаты
тулов в контексте активации однострочным дайджестом.

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
а `knowledge` — AgentTool у `dependency` и `dependency_critic` (веб-поиск: `WEB_SEARCH=tavily` + `TAVILY_API_KEY`).
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
| `VERIFIER_MAX_MODEL_CALLS` | бюджет вызовов модели одного Investigator'а на гипотезу | 30 |
| `BUGFINDER_MAX_ROUNDS` / `BUGFINDER_MAX_HYPS` / `BUGFINDER_MAX_PARALLEL` | раунды, гипотез за раунд, Verifier'ов одновременно | 4 / 8 / 3 |
| `STATE_PATH` | SQLite State (якоря, гипотезы, досье, находки, artifacts) | `.state/state.db` |
| `SESSIONS_PATH` | SQLite ADK-сессий (видны через `adk web`) | `.state/sessions.db` |
| `CRITIC_MAX_MODEL_CALLS`, `CRITIC=0` | бюджет Critic на находку; `0` — отключить адверсариальный проход | 20 / on |
| `LLM_MODEL` | модель Gemini (с `GOOGLE_API_KEY`) или модель за OpenAI-совместимым API (с `LLM_API_KEY`) | `gemini-flash-lite-latest` / `gpt-4.1` |
| `SEMGREP_CONFIG`, `SKIP_DEPS=1` | конфиг semgrep (`auto` без `--metrics=off` — semgrep не даёт их сочетать); не запускать osv-scanner | `auto` / off |
| `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME` | OTLP-экспорт трассировки; имя сервиса | — / `scanner` |
| `COMPACTION_INTERVAL`, `COMPACTION_OVERLAP` | сжатие событий ADK-сессии каждые N вызовов, последние `OVERLAP` — дословно | off / 2 |

osv-scanner сканирует явные манифесты (`-L <manifest>` на каждый go.mod/package-lock.json/…) —
git-aware обход osv-scanner ничего не находит в мелком клоне без `.git`.

Модули: `scanner/core/{types,rules}.py` (типы и чистые правила), `scanner/adapter/static.py`
(сканеры → якоря), `scanner/adapter/store.py` (SQLite, SARIF/summary, artifacts стадий v2),
`scanner/adapter/tools.py` (тулы агентов с гейтами), `scanner/adapter/owasp.py` (consult_owasp),
`scanner/app/reconcile.py` (Reconciler: якоря + threats → очередь), `scanner/app/agents.py`
(фабрики Verifier, Critic, Architect, ThreatModeler), `scanner/app/graph.py` (общий `_Graph`),
`scanner/app/pipeline_v2.py` (граф `PipelineV2`),
`scanner/app/observe.py` (трассировка, сжатие сессии), `scanner/app/runner.py` (сборка графа,
прогон в сессии, CLI-обвязка), `scanner/main.py` (CLI, eval), `web/fullscan/agent.py` (`adk web`).
