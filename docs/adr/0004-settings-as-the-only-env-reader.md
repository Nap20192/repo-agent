# ADR-0004: Переменные окружения читает только `settings`/`runner`

**Date**: 2026-09-12
**Status**: proposed (реализуется в wave 2 плана `docs/plans/quality.md`, карточка D)
**Deciders**: lead, ecc:architect audit

## Context

`os.environ` читается в десяти местах пяти модулей (`runner`, `graph` — `JSON_RETRY`, `pipeline_v2` — `STAGE_TIMEOUT`,
`knowledge` — `KNOWLEDGE_*`, `PYTEST_CURRENT_TEST`, `static` — `OSV_MAX`, `lsp` — `INDEX_MAX_*` на уровне импорта).
Флаги, прочитанные в глубине, нельзя протестировать без monkeypatch, значения на уровне импорта не меняются после
загрузки модуля, а продакшен-код, знающий о pytest, — запах [GPSG §2.5 Global State; CA гл. 11 DIP].

## Decision

Все переменные окружения парсятся один раз в `scanner/app/settings.py` (`Settings` — pydantic-модель или dataclass)
из `runner.prepare`/`build_agent`; граф, стадии и адаптеры получают нужные значения параметрами конструкторов.
Тесты передают значения явно; `PYTEST_CURRENT_TEST` из кода удаляется (сетевое обогащение отключается параметром).

## Alternatives Considered

### Alternative 1: оставить `os.environ.get` по месту
- **Pros**: ноль изменений
- **Cons**: скрытые зависимости, невоспроизводимые тесты, документация env расходится с кодом
- **Why not**: аудит насчитал 10 точек чтения и 2 импорт-тайм константы

### Alternative 2: глобальный синглтон `config` с ленивым чтением
- **Pros**: одна точка
- **Cons**: та же скрытая зависимость под другим именем; порядок импорта влияет на значения
- **Why not**: DIP требует явной передачи, а не глобального доступа

## Consequences

### Positive
- один источник правды для README-таблицы env; тесты без monkeypatch окружения
### Negative
- сигнатуры конструкторов растут на 3–5 параметров
### Risks
- забытая переменная молча получает дефолт → тест `Settings` перечисляет все ключи из README
