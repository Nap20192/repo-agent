# ADR-0006: Одна таксономия CWE в `core`; роутер и гейт выводятся из неё

**Date**: 2026-09-12
**Status**: proposed (реализуется в wave 2, карточка C/E; см. `docs/plans/quality.md`)
**Deciders**: lead, ecc:architect audit

## Context

Наборы CWE живут в трёх местах: `core/types.py` (`AUTHZ_CWES`, `TAINT_CWES` — 5+5, правят гейт консультаций),
`app/specialists.py` (`cwes` реестра — 14+15, правят роутер), `adapter/owasp.py` (карты WSTG/Top10/ASVS).
Уже разошлись: CWE-352 маршрутизируется в `authz`, но гейт не требует `domain:`; новый класс правится в трёх
файлах [REF, Shotgun Surgery].

## Decision

`core/taxonomy.py` объявляет один справочник `CWE_CLASSES: {cwe: CweClass(kind, family, consult, wstg_id, asvs_id, top10)}`.
`ground_hypothesis`/`check_consulted` берут обязательную консультацию из него, `specialists.route` — семейство,
`owasp.consult` — идентификаторы. `AUTHZ_CWES`/`TAINT_CWES` остаются как производные множества.

## Alternatives Considered

### Alternative 1: оставить три таблицы, добавить тест согласованности
- **Pros**: минимальный диф
- **Cons**: тест ловит расхождение, но не убирает тройное редактирование
- **Why not**: причина запаха — дублирование, а не отсутствие проверки

### Alternative 2: держать таксономию в `adapter/owasp.py`
- **Pros**: данные уже там
- **Cons**: `core` не может импортировать `adapter` — гейт остался бы без источника
- **Why not**: правило зависимостей [CA гл. 22]

## Consequences

### Positive
- новый класс = одна запись; роутер и гейт не расходятся по определению
### Negative
- `owasp.py` теряет часть таблиц в пользу `core` (данные без поведения — допустимо для доменного леса)
### Risks
- семантика гейта для CWE-352 меняется (потребует `domain:`) → отдельный тест и запись в CHANGELOG
