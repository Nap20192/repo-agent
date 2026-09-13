# Shannon-граф: полный Capella + pentest-поток (без эксплуатации) на ADK 2.9 `Workflow`

Продолжение `docs/rnd/shannon-workflow-gap-2026-09-12.md` (там — разбор стадий и причины промахов; здесь не повторяется)
и `docs/plans/workflow-migration.md` / ADR-0007 (4-узловой граф). Карта 44 уже дала планировщик (`reconcile.coverage`,
`hunt_classes`, `adversarial_sweep`), triage-свип (`graph_nodes.triage_node`, `TRIAGE_INSTRUCTION`) и hunting-чеклисты
специалистов; всё это переиспользуется. Пути Shannon — относительно `~/tmp/repos/shannon/apps/worker`.
Неизменные ограничения: находки только через `report_finding`/`disprove_finding` (+ direct lane), RunStore — продукт,
слои hexagonal, бюджеты/колбэки на `LlmAgent`, `Workflow` не вкладывается в агента, каждая стадия деградирует,
тесты без LLM через node-дублёры (`tests/fakes.py`).

## 1. Стадии Shannon → что есть у нас

Capella (`src/ai/sast/capella/temporal/workflow.ts`, политики `activity-types.ts:278-290`, схемы `schemas.ts`,
запись находки `finding-types.ts:183-227`, гейт экспорта `sarif-exporter.ts:57-62`). Правило Capella: стадии-документы
(architecture, threat-model, plan, triage) отдают `outputSchema`; всё, через что проходит *находка*, идёт через
collector-тул (`schemas.ts:7-16`) — ровно наша пара «`output_schema` для моделирования / гейты для вердиктов».

| # | Стадия | Назначение | Вход → выход (схема) | Prompt | Модель / параллелизм / лимит | У нас: reuse / не хватает |
|---|---|---|---|---|---|---|
| C1 | architecture | KB репозитория | repo → `KbResult{architecture, entities[], vulnerabilities[], index, dependencies{}}` | `prompts/sast/capella/architecture.prompt.hbs` | 1 × `large`, 400 turns, 90 мин, retry 3 | Architect (`ArchitectureModel`, заземлён по индексу) + DomainModeler. Нет `dependencies` (граф импортов) |
| C2 | threat-model | границы доверия, intent | KB → `ThreatModelResult{threatModel, intent: PRODUCTION\|SAMPLE_OR_TEST_ONLY}` | `threat_model.prompt.hbs` | 1 × `medium`, без исходников | ThreatModeler (threats + fail-closed intent). Есть |
| C3 | plan | покрытие: каждый production-файл в каком-то investigation | KB+TM → `PlanResult{investigations[{title,target_files,kb_references,question}]}`; 25–50 % adversarial/random | `plan.prompt.hbs` | 1 × `medium` | Детерминированно: `reconcile.coverage` + `hunt_classes` + `adversarial_sweep` (карта 44). Нет батчей файлов для triage |
| C4a | research/triage | быстрый свип всех `target_files` | файлы → `TriageResult{classifications[{file,potentially_flawed,reason}]}`; батчи ≤4, `usableClassifications`, repair-проход по пропущенным, `computeTriageCoverage` | `triage.prompt.hbs` | ≤4 батча × `small`, 4 параллельно, 100 turns | `triage_node` — по одному baseline внутри раунда. Нет батчей по файлам, repair, coverage-артефакта |
| C4b | research/audit | глубокий аудит только flagged | investigation с ≥1 flagged → находки через `report_finding` (`code_paths[0]` = sink, bare CWE обязателен) | `research.prompt.hbs` | 1 на investigation × `medium`, 2 параллельно, 200 turns | `route_and_verify` + специалисты + гейт. Есть |
| C5 | dedupe | слияние дублей | находки → `record_duplicates` (тот же `code_paths` line-inclusive + похожий title) | `dedupe.prompt.hbs` | 1 × `small`, 200 | `store.report` дедуп по anchor / (cwe,file,±NEAR_LINES) при записи. Нет отдельной стадии (и не нужна модель) |
| C6 | review | независимая валидация | → `status` VALID/FALSE_POSITIVE/PROVISIONALLY_VALID/NEEDS_RESEARCH + `triage_checklist` (13 правил, `FAIL` ⇒ FP) + `repro_hints`; `record_review_verdict`; repair по пропущенным id | `review.prompt.hbs` | 1 + repair × `medium`, 400 turns, 2 ч | 13 правил уже в `CRITIC_INSTRUCTION`, вердикт через `disprove_finding`. Нет чек-листа как данных, статуса «provisional», repair |
| C7 | critic | production viability | → `production_viability` VIABLE/CONDITIONAL_VIABLE/NON_VIABLE/SAMPLE_OR_TEST; `Intent: SAMPLE_OR_TEST_ONLY` ⇒ все SAMPLE_OR_TEST без вызовов; missing file ⇒ CONDITIONAL (fail-safe) | `critic.prompt.hbs` | 1 + repair × `medium`, 300 | Маршруты viability зашиты в `CRITIC_CORE`. Нет отдельного вердикта, intent-короткого замыкания |
| C8 | confirm | статическое подтверждение | VALID/PROVISIONAL → `repro_status` statically_confirmed/not_attempted; promotion PROVISIONAL→VALID, если чек-лист без UNKNOWN | `confirm.prompt.hbs` | 1 + repair × `medium`, 300 | Нет |
| C9 | calibrate | report-only score | → impact/likelihood/multiplier, risk 1–10, 27-правильный `calibration_checklist`; не меняет экспорт | `calibrate.prompt.hbs` + `partials/capella-calibration-rules.hbs` | 1 + repair × `small`, 200 | `core/calibrate.py` детерминированно (Hazard×Multiplier, intent, exposure, EPSS/KEV). Нет 27-чек-листа |
| C10 | export | SARIF | гейт `status==='VALID' && viability∈{VIABLE,CONDITIONAL_VIABLE}`; при падении стадии — export последнего хорошего набора с `reduction` | — | 0 | `store.write_report/write_summary` (confirmed only). Нет `coverage: complete\|reduced`, fallback-семантики |
| P1 | preflight / auth validation | доступность цели, логин | — | `prompts/validate-authentication.txt` | 1 | Нет runtime: аналог — `runner.prepare` (сканеры, индекс, знания). Есть |
| P2 | pre-recon (code) | единственный агент с полным кодом; deliverables `set_auth_deep_dive`, `set_xss_sinks`, `set_ssrf_sinks`, `set_injection_sources`, `set_critical_file_paths`, `set_codebase_indexing` | repo → deliverables | `prompts/pre-recon-code.txt` | 1, todo-loop | Architect + `adapter/entrypoints`. Нет инвентаря sinks по классам |
| P3 | recon (dynamic) | `add_endpoints` (dedup по method+path), `set_authz_candidates`, `set_role_architecture`, `set_injection_sources` | live target → endpoints | `prompts/recon.txt` | 1 | Статический эквивалент: `entrypoints` + `hunt_classes` (`:id` ⇒ 639/862, admin ⇒ 862/285). Есть |
| P4 | vuln-lanes ×5 (+misc) | по классу: todo на каждый source, «do not terminate early», deliverable-тулы | pre-recon+recon → findings summary per class | `prompts/vuln-{injection,xss,auth,authz,ssrf}.txt` | 5 агентов, 5 параллельно, 2 ч, 50 attempts | Специалисты + роутер CWE→kind; per-(entry,class) baseline — это todo-loop, сделанный кодом (карта 44). Есть |
| P5 | reconcile per class | SARIF intake → CWE→class → LLM enrichment (`witness_payload`, `slot_type`, `externally_exploitable`) → task formation → materialize | Capella SARIF + lane → exploit tasks | `sast-enrichment-*.txt`, `task-formation-*.txt` | 1 + 1 на класс | Аналог — `from_anchors` + direct lane. Enrichment/task formation служат эксплуатации — **не портируем** |
| P6 | report | `set-report-meta`, `add_finding`; Markdown/PDF/SARIF/JSON, `severity_rationale` | deliverables → отчёт | `prompts/report-executive.txt` | 1 | `summary.json` + SARIF с таксономиями. Нет Markdown/executive summary (опция, см. §4) |
| P7 | exploit | — | — | `exploit-*.txt` | — | Исключено по условию |

## 2. Граф

Форма известна до входа (Shannon: линейная цепочка с четырьмя закрытыми решениями), поэтому верхний уровень —
статический `Workflow` с route-картами и одним `JoinNode`; внутри каждого модельного узла — dynamic-обёртка с
`try/except` (ADR-0007: падение узла = падение `Workflow`, а скан обязан деградировать). Цикл очереди (new_hypotheses)
остаётся Python-циклом в `audit`, как сейчас в `investigate`. Все fan-out'ы — `@node(parallel_worker=True)`.

```
START → build_skeleton → direct_findings ─┬→ architect ─┐
                                          └→ recon ─────┴→ join_model → domain_modeler → threat_modeler → ground → plan
plan → route_plan ──── empty ───────────────────────────────────────────────────────────────────────┐
         │ default                                                                                  │
         ▼                                                                                          │
      triage_sweep → fold_triage → audit → route_research ──── none | budget ───────────────────────┤
                                                 │ default                                          │
                                                 ▼                                                  │
                                              dedupe → review → route_survivors ──── none ──────────┤
                                                                      │ default                     │
                                                                      ▼                             │
                                                                route_intent ── sample → mark_sample ─┐
                                                                      │ default                     │ │
                                                                      ▼                             │ │
                                                                critic → confirm → calibrate ◄──────┘ │
                                                                                      └→ export ◄─────┘  (единственный терминал)
```

```python
# scanner/app/pipeline.py — build_workflow(...) возвращает ScanWorkflow(Workflow); все узлы — фабрики из graph_nodes.py
return ScanWorkflow(name="scan_v4", max_concurrency=2, index=index, edges=[
    (START, build_skeleton, direct_findings, (architect, recon), join_model,   # fan-out + JoinNode → {"architect":…, "recon":…}
     domain_modeler, threat_modeler, ground, plan, route_plan),
    (route_plan, {"empty": export, DEFAULT_ROUTE: triage_sweep}),             # Shannon: investigationCount == 0 → export
    (triage_sweep, fold_triage, audit, route_research),
    (route_research, {"none": export, "budget": export, DEFAULT_ROUTE: dedupe}),  # findingCount == 0 / fallback → export
    (dedupe, review, route_survivors),
    (route_survivors, {"none": export, DEFAULT_ROUTE: route_intent}),         # reviewedSurvivors == 0 → export
    (route_intent, {"sample": mark_sample, DEFAULT_ROUTE: critic}),           # Intent: SAMPLE_OR_TEST_ONLY → 0 вызовов
    (mark_sample, calibrate),
    (critic, confirm, calibrate, export),
])
```

Конструкции ADK — намеренно:
- `FunctionNode` — детерминированная работа (skeleton, direct lane, recon, ground, plan, fold, dedupe, mark_sample, calibrate, export) и
  все route-узлы: `yield Event(route="empty", output=payload)`; без `route` срабатывает `DEFAULT_ROUTE` (`events/event.py:168-223`, `_workflow.py:796`).
- Модельные стадии — `LlmAgent(mode="single_turn", output_schema=<pydantic из scanner/core>, output_key=<stage>)`, обёрнутые фабрикой
  `stage_node(agent, name)` = `@node(rerun_on_resume=True)` с `asyncio.wait_for(ctx.run_node(...), stage_timeout)` в `try/except` (нынешний `stage()`
  из `pipeline.py:92-110`, вынесенный в узел). `output_schema` и тулы совместимы (`llm_agent.py:449-452`, `set_model_response`).
- `JoinNode` — только там, где fan-in реален: `join_model` ждёт Architect и recon и отдаёт `{name: output}` (`_join_node.py:52-64`).
- Route-карты — закрытые решения по данным (пустая очередь, 0 находок, бюджет, intent, 0 survivors) — «детерминированный роутер, когда
  множество закрыто» (adk-multi-agent §1).
- `@node(parallel_worker=True, max_parallel_workers=N)` — triage (N=`triage_parallel`), audit (N=`max_parallel`), review/critic/confirm (N=`max_parallel`);
  ошибка элемента ловится в теле воркера (как `route_and_verify`), иначе ADK отменяет батч.
- `RetryConfig(max_attempts=2)` + `timeout` на модельных узлах = политика активности Shannon (retry и repair-проход в одном механизме);
  `report_finding`/`disprove_finding` идемпотентны через дедуп стора — требование at-least-once выполняется.
- `App(resumability_config=ResumabilityConfig(is_resumable=True))`: завершённые статические узлы реплеятся из событий сессии, dynamic-узлы
  с `rerun_on_resume=True` переигрывают тело с кэшем детей; артефактный resume (`store.artifact`) остаётся для CLI-перезапуска (новая сессия).

## 3. Узлы

Схемы (`scanner/core/workflow.py`, дополнение): `DirectResult{remaining, reported}`, `ReconMap{sources[Candidate], sinks{class→[file:line]}, auth[], config_files[]}`,
`PlanState(QueueState){batches[[file]]}`, `TriageClassification{file, flagged, classes[], why}`, `TriageBatch{classifications[]}`,
`TriageCoverage{considered, classified, missing[], flagged[]}`, `ResearchResult(InvestigateResult){findings}`,
`RuleEval{outcome: PASS|FAIL|UNKNOWN|NOT_APPLICABLE, reason}`, `ReviewVerdict{finding_id, status: VALID|FALSE_POSITIVE|PROVISIONALLY_VALID|NEEDS_RESEARCH, reasoning, repro_hints, checklist{13 ключей→RuleEval}}`,
`Viability{finding_id, viability: VIABLE|CONDITIONAL_VIABLE|NON_VIABLE|SAMPLE_OR_TEST, reasoning}`, `Confirmation{finding_id, repro_status: statically_confirmed|not_attempted, repro_hints}`,
`ExportResult(Report){coverage: complete|reduced, reductions[]}`. `Finding` получает аннотации `review`, `viability`, `repro_status`, `calibration`
через новый метод порта `RunStore.annotate(finding_id, **fields)`, который **отказывает** для `status/evidence/confidence` — статус меняют только гейты.
Соответствие статусов Shannon: VALID = confirmed; FALSE_POSITIVE = агент обязан вызвать `disprove_finding` с цитатой (иначе — заметка «FP без
контрфакта», статус не меняется); PROVISIONALLY_VALID/NEEDS_RESEARCH = аннотация; promotion в `confirm` = повторный `report_finding` с большей
`confidence` (store.report заменяет вердикт, `store.py:110-121`). NON_VIABLE тоже только через `disprove_finding` (debug-only route, mock provider —
это контрфакты с цитатой), поэтому гейт SARIF остаётся `status == confirmed`, а аннотации едут в `properties`.

| Узел | ADK | Вход → выход | Prompt: Shannon → наш | Тулы | Бюджет (Settings) | Отказ / завершение | Дублёр |
|---|---|---|---|---|---|---|---|
| `build_skeleton` | FunctionNode (есть) | user turn → `ScanSkeleton` | — | — | — | детерминирован | есть |
| `direct_findings` | FunctionNode (есть, из внутреннего в графовый) | `store.anchors()` → `DirectResult` | — | — | `DIRECT_MAX` | как сейчас | есть |
| `architect` | `stage_node(LlmAgent single_turn, output_schema=ArchitectureModel)` | `DirectResult` → артефакт `architecture_model` | `architecture.prompt.hbs` → `ARCHITECT_INSTRUCTION` (есть) | `architect_tools` | `architect_max_calls`, `stage_timeout`, Retry 2 | таймаут/невалидный JSON → `None` + note | `fake_stage_node` |
| `recon` | FunctionNode | `ScanSkeleton` → `ReconMap` | `pre-recon-code.txt` (`set_*_sinks`, `set_injection_sources`, `set_auth_deep_dive`) → детерминированный grep по sink-паттернам `LANG_OVERLAYS` + entrypoints + middleware из `adapter/domain` | — | `RECON=0` выключает | ошибка индекса → пустая карта + note | unit на фикстуре |
| `join_model` | JoinNode | `{architect, recon}` → dict | — | — | — | ждёт оба (оба деградируют сами) | test dict-формы |
| `domain_modeler` | stage_node, `output_schema=DomainMap` | join dict → `domain_map` | наш | `architect_tools` | 12 | как architect | `fake_stage_node` |
| `threat_modeler` | stage_node, `output_schema=ThreatModel` | am + dm + `recon.auth` → `threat_model` | `threat_model.prompt.hbs` → `THREAT_MODELER_INSTRUCTION` (есть) | consult_owasp, read_file, grep | 6 | intent по умолчанию production | `fake_stage_node` |
| `ground` | FunctionNode (есть: `ground_artifacts`) | артефакты → `{dropped}` | — | — | — | чистая | есть |
| `plan` | FunctionNode (есть: `build_queue`, `coverage`) + `batch_files` | → `PlanState`; артефакт `plan` | `plan.prompt.hbs` → `coverage`/`hunt_classes`/`adversarial_sweep` | — | `TRIAGE_BATCH=10`, `FILE_BASELINE_MAX` | чистая | есть + батчи |
| `route_plan` | FunctionNode (route) | `PlanState` → `empty`/default, output = batches | `workflow.ts:382` | — | — | — | route test |
| `triage_sweep` | `@node(parallel_worker, max_parallel_workers=triage_parallel)` над triage `LlmAgent(output_schema=TriageBatch)` | `[batch]` → `[TriageBatch+failed]` | `triage.prompt.hbs` → `TRIAGE_INSTRUCTION` (есть; батч файлов вместо одного item) | `triage_tools` (read_file окно 200 для triage) | `triage_max_calls`×файлы, `LLM_MODEL_SMALL`, Retry 2 = repair | пропущенный файл → 1 repair, потом flagged=True (fail open) | `fake_triage_batch_node` |
| `fold_triage` | FunctionNode | батчи + `PlanState` → `QueueState`; артефакт `triage_coverage` | `research.ts:206-250` (`usableClassifications`, `computeTriageCoverage`) | — | — | missing>0 ⇒ coverage=reduced; unflagged → rejected-досье (есть) | unit |
| `audit` | `@node(rerun_on_resume)` цикл (есть: `investigate` без `triage_batch`) + `route_and_verify` parallel_worker | `QueueState` → `ResearchResult` | `research.prompt.hbs` + `vuln-*.txt` → `INVESTIGATOR_CORE` + `SPECIALIST_SECTIONS` (есть) | ростеры специалистов | `max_rounds×max_hyps`, `max_parallel`, `SPECIALIST_*_MAX_CALLS` | error-dossier на элемент; раунд 0 весь упал → RuntimeError; budget → stop | `fake_verifier_node` |
| `route_research` | FunctionNode (route) | → `none`/`budget`/default | `workflow.ts:401`, fallback `:503` | — | — | — | route test |
| `dedupe` | FunctionNode | → `{merged}` | `dedupe.prompt.hbs` → `store.report` дедуп (есть) + слияние по title-similarity в (file,cwe,±NEAR_LINES) | — | — | чистая | unit |
| `review` | parallel_worker над `LlmAgent(output_schema=ReviewVerdict)` | `[Finding]` → `[ReviewVerdict]`; `annotate(review=…)` | `review.prompt.hbs` → `REVIEW_INSTRUCTION` (13 правил из `CRITIC_INSTRUCTION` + checklist JSON + repro_hints) | `critic_tools`: disprove_finding, read_file, grep, lsp_* , check_dominance | `review_max_calls=8`, Retry 2 | исключение/нет JSON → аннотации нет, note, статус не тронут | `fake_review_node` |
| `route_survivors` | FunctionNode (route) | → `none`/default, output = ids confirmed | `workflow.ts:428` | — | — | — | route test |
| `route_intent` | FunctionNode (route) | `threat_model.intent` → `sample`/default | `critic.prompt.hbs` шаг 2 | — | — | нет TM ⇒ production | route test |
| `mark_sample` | FunctionNode | → `annotate(viability=SAMPLE_OR_TEST)` всем llm-находкам | там же | — | — | 0 вызовов | unit |
| `critic` | parallel_worker над `LlmAgent(output_schema=Viability)` | survivors → `[Viability]`; annotate | `critic.prompt.hbs` → `VIABILITY_INSTRUCTION` (маршруты из `CRITIC_CORE`) | disprove_finding, check_dominance, lsp_path_to_entry, read | `critic_max_calls=6`, Retry 2 | missing file/line → CONDITIONAL_VIABLE (fail-safe Shannon) | `fake_viability_node` |
| `confirm` | parallel_worker над `LlmAgent(output_schema=Confirmation)` | элементы с `review.status==PROVISIONALLY_VALID` (остальные — skip, 0 вызовов) → `[Confirmation]` | `confirm.prompt.hbs` → `CONFIRM_INSTRUCTION` | report_finding + read/lsp | `confirm_max_calls=8`, Retry 2 | сбой → `not_attempted` | `fake_confirm_node` |
| `calibrate` | FunctionNode (есть: `core.calibrate`, переносится из `write_report` в узел) [+ опция `CALIBRATE_LLM=1`: parallel_worker с 27-чек-листом, `small`] | → annotate(calibration) | `calibrate.prompt.hbs` + `capella-calibration-rules.hbs` → `core/calibrate.py` | — | 0 | чистая | есть |
| `export` | FunctionNode, единственный терминал | → `ExportResult`; `write_report/write_summary`, артефакт `timings` | `sarif-exporter.ts` гейт → `status==confirmed` (без изменений) + `properties{review,viability,repro_status,calibration,coverage}` | — | 0 | выполняется всегда (Shannon: export даже при fallback) | есть (`finish` минус critic) |

## 4. Дельта к `scanner/app/pipeline.py`

| Действие | Узлы | Переиспользуется | Размер |
|---|---|---|---|
| остаются | `build_skeleton`, `direct_findings` (становится ребром графа) | `graph_nodes.py:39-68` | 0 |
| `plan` разрезается на 8 | `architect`, `domain_modeler`, `threat_modeler` (через `stage_node`), `recon`, `join_model`, `ground`, `plan`, `route_plan` | `stage()` → `stage_node` (`pipeline.py:92-110`), `ground_artifacts`, `build_queue`, `coverage` | `stage_node` 25, `recon` 60 (+ тест 40), route-узлы 10 каждый, `plan` +15 (батчи) |
| `investigate` → `audit` | `triage_batch` уходит из раунда; тело цикла без изменений | `pipeline.py:151-193`, `route_and_verify_node` | −25 / +5 |
| новые | `triage_sweep` (rework `triage_node` на батч + `TriageBatch`), `fold_triage`, `route_research`, `dedupe`, `route_survivors`, `route_intent`, `mark_sample` | `triage_node` (`graph_nodes.py:115-135`), `store.report` | 45, 40, 10, 30, 10, 10, 15 |
| `finish` → `review` + `critic` + `confirm` + `calibrate` + `export` | `route_and_critique_node` → `review` (та же форма, + `ReviewVerdict`); `critic` и `confirm` — копии формы с другими агентом/схемой | `graph_nodes.py:138-160`, `core.calibrate`, `store.write_*` | review 40, critic 40, confirm 45, calibrate 20, export 25 |
| core | схемы §3 в `core/workflow.py`; `Finding.review/viability/repro_status/calibration`; `RunStore.annotate` (порт + `Store`) | `core/types.py`, `core/ports.py`, `adapter/store.py` | 60 + 30 |
| app | `REVIEW_INSTRUCTION`, `VIABILITY_INSTRUCTION`, `CONFIRM_INSTRUCTION` в `instructions.py`; `new_review/new_viability/new_confirm` в `agents.py`; `Settings`: `triage_batch, triage_parallel, review_max_calls, confirm_max_calls, calibrate_llm, recon, llm_model_small`; `runner.wiring` | `CRITIC_INSTRUCTION`, `CRITIC_CORE`, `new_agent` | 120 промптов, 30 agents, 20 settings, 30 runner |
| tests | `fake_triage_batch_node`, `fake_review_node`, `fake_viability_node`, `fake_confirm_node`, `fake_recon` в `fakes.py`; `_workflow(run, **kw)` принимает их | `_run_node`, `fake_stage_node` | 80 + ~25 тестов |
| удаляется | `triage_batch` из `pipeline.py`, критик внутри `finish`, calibrate внутри `write_report` | — | −60 |

Итого ≈ 900 строк кода + 350 тестов; ни один гейт не меняется. Порядок — поведенчески нейтральные шаги, после каждого `uv run pytest -q` зелёный
и NodeGoat-артефакты (`.runs/`) совпадают по находкам:
1. `stage_node` + статическая цепочка `architect → domain_modeler → threat_modeler → ground → plan` вместо тела `plan`; `recon` — заглушка `{}`
   за `JoinNode`. Тест: те же артефакты/заметки, что `test_pipeline` даёт сейчас. `Event(route=…, output=…)` и вход `export` от нескольких
   предшественников проверяются здесь спайком (не JoinNode — срабатывает от любого триггера).
2. `route_plan` (`empty` → `export`), `export` = `finish` без критика; критик временно остаётся динамическим вызовом внутри `export`.
3. `triage_sweep` на батчах + `fold_triage` + артефакт `triage_coverage`; `triage_batch` удаляется из раунда. Тест: пропущенный файл → 1 repair
   → coverage=reduced; unflagged → rejected-досье (как сейчас).
4. `route_research` (`none`/`budget`) + `dedupe`; `review` = переименованный `route_and_critique` с `REVIEW_INSTRUCTION` и `ReviewVerdict`,
   `RunStore.annotate`. Тест: FALSE_POSITIVE без `disprove_finding` не меняет статус.
5. `route_survivors`, `route_intent`, `mark_sample`, `critic` (viability). Тест: intent=sample ⇒ 0 вызовов viability, все SAMPLE_OR_TEST.
6. `confirm`: promotion через повторный `report_finding` с большей confidence. Тест: PROVISIONAL + цитата у якоря → confidence выросла; без цитаты — `not_attempted`.
7. `calibrate` как узел (+ `CALIBRATE_LLM`), `ExportResult.coverage`, `ResumabilityConfig` в `runner.build_app`; тест resume на `InMemorySessionService`.
8. `recon` настоящий; `LLM_MODEL_SMALL` для triage/calibrate-LLM; README-таблица узлов, BOARD-карта 45, ADR-0008 «verdict ladder на статическом графе».
Каждый шаг — `ecc:orch-add-feature` → `tdd-workflow` → `code-reviewer` (+ `security-reviewer` на шагах 4 и 6: новый метод стора и путь promotion).

Открытые вопросы:
- ADK: узел `export` с пятью входящими рёбрами из route-карт — валидатор `_graph_validation` допускает (не цикл), но срабатывание «от первого
  триггера» надо подтвердить спайком (шаг 1); иначе — `JoinNode` не подходит (ждёт всех), остаётся dynamic-обёртка «finish» с маршрутами внутри.
- Parallel-worker-узел прямо в статическом графе и `Workflow.max_concurrency` — независимые лимиты? (`_workflow.py:503`, `_parallel_worker.py:104`).
- Бюджетный колбэк пишет `budget_exhausted:<branch>`; при `RetryConfig` вторая попытка получает новый `run_id`/branch — бюджет обнуляется,
  что и нужно для repair, но глобальный флаг `STATE_BUDGET_EXHAUSTED` должен читаться route-узлами, а не только `audit`.
- PROVISIONALLY_VALID: явная аннотация (предлагается) или порог `confidence < 0.7`? Порог дешевле, но переносит смысл Shannon на число модели.
- Markdown-отчёт (P6): отдельный `single_turn` агент с `output_schema=ExecutiveSummary` перед `export` — 1 вызов, вне этой карты.
- Роли моделей Shannon (`small/medium/large`): одна ручка `LLM_MODEL_SMALL` или полная тройка?

## 5. Модель стоимости (вызовы модели)

Приложение на 150 production-файлов, ~25 entry points, ~10 semgrep-warning якорей, ~8 угроз; «вызов» = один запрос к модели
(как считает `budget_callback`). Ориентир — NodeGoat run 18: 386 вызовов, 26 гипотез (≈ 14,8 вызова/гипотезу), 3 класса найдены,
file-baseline'ы (до 60) не были просмотрены вовсе; 6 известных промахов лежат в файлах, которых очередь не достигла.

| Стадия | Формула | 150 файлов, cap 4×8 | 150 файлов, parity (все flagged) | Роль |
|---|---|---|---|---|
| architect / domain / threat | ≤ 40 / 12 / 6 | ~20 / 8 / 4 | ~20 / 8 / 4 | large / medium / medium |
| recon, ground, plan, dedupe, fold, routes, calibrate, export | 0 | 0 | 0 | — |
| triage_sweep | батчи(150/10=15) × (≈1 read на файл + 1 ответ) + repair ≤ 1/батч | ~165 (+15) | ~165 (+15) | **small** |
| audit | min(flagged, rounds×hyps) × ≈12 | 32 × 12 ≈ 385 | (45 файлов + 15 entry + 10 + 8 ≈ 65) × 12 ≈ 780 | medium |
| review | confirmed × ≈6 (+25 % repair) | ~8 × 6 ≈ 60 | ~12 × 6 ≈ 90 | medium |
| critic (viability) | survivors × ≈5; intent=sample ⇒ 0 | ~35 | ~55 | medium |
| confirm | provisional × ≈6 | ~18 | ~30 | medium |
| calibrate-LLM (опция) | survivors × 2 | 0 (14) | 0 (22) | small |
| **Итого** | | **≈ 700** (180 на small) | **≈ 1 170** (180 на small) | |

Против run 18: аудит стоит столько же на гипотезу; прирост — triage (дёшев, small-модель) и лестница вердиктов (~110 вместо ~30 у нынешнего
критика), зато аудит идёт только по flagged-файлам, и весь production-набор просмотрен хотя бы triage'ем (`coverage: complete|reduced` в
отчёте). Для NodeGoat (~35 production-файлов): triage ≈ 40, аудит 26–32 гипотезы ≈ 380, лестница ≈ 100 → ≈ 520 вызовов против 386, при этом
`$where`, IDOR `allocations/:userId`, XSS профиля, `isAdmin`, CSRF и ReDoS попадают в аудируемое множество (ожидание, не измерение — проверяется
NodeGoat-прогоном после шага 3 и после шага 6). Ручки для снижения: `TRIAGE_BATCH=15` (−30 % triage), `LLM_MODEL_SMALL` на ollama (0 $),
`max_rounds×max_hyps` как жёсткий потолок аудита, `CALIBRATE_LLM=0` по умолчанию.

## 6. Spike results (ADK 2.9, `tests/test_adk_spike.py`)

Все открытые вопросы §4 про ADK закрыты тестами против установленного `google-adk` 2.9.0; каждый ответ пришпилен
тестом, номера — `test_qN_*`.

| # | Вопрос | Ответ | Тест | Где в ADK |
|---|---|---|---|---|
| 1 | Route-карты | `Event(route="x", output=...)` из FunctionNode; `route` попадает в `actions.route`; в `edges` карта `{route: node, DEFAULT_ROUTE: node}`; нероутированная ветка не выполняется вовсе | `test_q1_route_map_runs_only_the_routed_branch` | `events/event.py:170-224`, `_graph.py:133-170` |
| 2 | `export` с несколькими входящими рёбрами | Обычный `FunctionNode` получает по триггеру на каждое **сработавшее** ребро (`_workflow.py:866-890`); при взаимоисключающих маршрутах он выполняется ровно один раз — это и есть форма для `export`. `JoinNode` ждёт **все** предшественники (`_join_node.py:38`, барьер `_workflow.py:831-861`): предшественник, пропущенный маршрутом, никогда не завершится, join не сработает — JoinNode терминалом быть не может. Ограничение валидатора: одно ребро `(r2, export)` не может встречаться дважды (`Duplicate edge`), т.е. из одного route-узла в `export` ведёт максимум один маршрут + DEFAULT | `test_q2_plain_terminal_with_many_predecessors_fires_on_the_first_route_taken`, `test_q2_join_terminal_waits_for_every_predecessor_so_a_route_skip_never_reaches_it` | `_workflow.py:463-500,831-890` |
| 3 | JoinNode fan-in | `(a, (b, c)), ((b, c), join)` → выход join = `{"b": out_b, "c": out_c}` (ключи — имена предшественников) | `test_q3_join_output_is_a_dict_keyed_by_predecessor_name` | `_join_node.py:52-64`, `_workflow.py:852` |
| 4 | `output_schema` + `tools` | Допустимо в одном `LlmAgent`: инструменты на цикле рассуждения, схема на финальном ответе (док-строка ADK). `tools` хранятся как сырые callables, оборачиваются в `canonical_tools()` | `test_q4_llm_agent_accepts_output_schema_and_tools_together` | `agents/llm_agent.py:449-452` |
| 5 | `RetryConfig` | `max_attempts=2` = оригинал + один повтор; узел перезапускается, граф идёт дальше с успешным выходом. Исчерпанные попытки роняют Workflow — примитива «продолжить с None» на статическом ребре нет: деградация остаётся внутри динамических узлов (try/except вокруг `ctx.run_node`), как и требует ADR-0007. Дефолты без конфига: 5 попыток, задержка 1 с ×2, jitter 1.0 — для тестов ставить `initial_delay=0, jitter=0` | `test_q5_retry_config_reruns_a_failing_node_once_then_succeeds`, `test_q5_a_node_failing_past_max_attempts_fails_the_workflow` | `_node_runner.py:125-200`, `utils/_retry_utils.py:34-40` |
| 6 | parallel_worker на статическом ребре | `@node(parallel_worker=True, max_parallel_workers=N)` получает список предшественника и возвращает список выходов **в порядке входа**; `Workflow.max_concurrency` ограничивает узлы, `max_parallel_workers` — элементы; лимиты независимы (max_concurrency=1 не мешает fan-out) | `test_q6_parallel_worker_fans_out_a_list_input_on_a_static_edge_in_input_order` | `_parallel_worker.py:95-135`, `_workflow.py:_at_concurrency_limit` |
| 7 | `ResumabilityConfig` | Возобновление = повторный `run_async` с **тем же `invocation_id` и без `new_message`**: replay ищет чекпоинты `node@run_id` в событиях этой invocation (`_replay_manager.py:289`); завершённые узлы фаст-форвардятся (функция не вызывается), упавший выполняется заново. Новое сообщение = новая invocation = полный перезапуск. Для CLI это значит: resume работает только внутри одной сессии-invocation; при перезапуске процесса нужен сохранённый `invocation_id`, иначе остаётся наш артефактный resume через `store.artifact` | `test_q7_resumable_app_replays_completed_nodes_and_reruns_the_failed_one` | `_workflow.py:229-235,600-650`, `utils/_replay_manager.py:274-296` |

**Рекомендуемая форма `export`:** обычный `FunctionNode` со всеми входящими рёбрами из route-карт и из `calibrate`;
каждый route-узел ведёт в `export` не более чем одним маршрутом. `calibrate` имеет двух предшественников
(`mark_sample`, `confirm`) — тоже обычный узел (сработает от того, кто пришёл), не JoinNode.

**Дублёры для волны 2** (`tests/fakes.py`): `fake_route_node(name, route)`, `fake_schema_stage_node(store, name,
schema, payload)` (валидирует payload по pydantic-схеме при конструировании), `fake_parallel_node(name, fn,
max_parallel_workers=None)`.
