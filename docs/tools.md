# scanner/adapter/tools — Система инструментов для агентов

## Что такое Tool?

**Tool** — это функция-замыкание (closure), которую вызывает ADK LLM-агент. Каждый tool:

- ✅ Получает параметры из LLM-ответа  
- ✅ Работает в контексте одного скана (`ToolContext`)  
- ✅ Всегда возвращает dict: `{"status": "ok/error", "result": ...}` или ошибку  
- ❌ **Никогда не выбрасывает исключения** — все ошибки идут в dict  

## Что такое ToolContext?

```python
@dataclass
class ToolContext:
    target: Path              # директория для скана
    run: RunStore             # хранилище findings для этого скана
    index: Index              # LSP symbols или grep индекс
    reader: Callable          # fn(file, line) → код вокруг линии
    in_target: Callable       # fn(quotes) → True если цитаты в target
    entries_fn: Callable      # fn() → list entry-points
    settings: Settings        # LLM URLs, API ключи, конфиг
```

**ToolContext** — это DI контейнер. Все инструменты получают один контекст, который содержит всё, что им нужно:
- Путь к сканируемому коду
- Базу найденных findings
- Индекс символов кода (для lsp_*)
- Настройки LLM

## Структура tools/

```
tools/
├── __init__.py              # экспорты (ToolContext, make, registry)
├── context.py               # ToolContext dataclass
├── registry.py              # TOOLS dict: имя → factory fn
├── common.py                # shared helpers (caps, confinement, quoting)
│
├── code/                    # Доступ к коду
│   ├── read_file.py         # read_file(path, start, end)
│   ├── grep.py              # grep(pattern, files, max_files)
│   └── shell.py             # shell(cmd, timeout)
│
├── lsp/                     # Навигация по коду (LSP)
│   ├── symbols.py           # lsp_symbols(path) → [symbol]
│   ├── definition.py        # lsp_definition(path, symbol) → body
│   ├── references.py        # lsp_references(symbol)
│   ├── callers.py           # lsp_callers(function)
│   ├── callees.py           # lsp_callees(function)
│   └── path_to_entry.py     # lsp_path_to_entry(file) → entry point
│
├── gates/                   # Вердикты findings
│   ├── report_finding.py    # ⭐ KEY: report_finding(anchor_id, title, status, evidence, ...)
│   ├── disprove_finding.py  # disprove_finding(anchor_id, reason)
│   └── finding.py           # gate_finding() валидация
│
├── store/                   # Хранилище state
│   ├── list_anchors.py      # list_anchors() → anchors для проверки
│   ├── list_findings.py     # list_findings(status) → findings
│   ├── note_add.py          # note_add(text) → note
│   └── note_list.py         # note_list() → notes
│
├── consult/                 # Консультации знаний
│   ├── domain.py            # consult_domain(entity, kind) → info
│   ├── dominance.py         # check_dominance(path, symbols)
│   ├── entry_points.py      # list_entry_points() → entry list
│   ├── owasp.py             # consult_owasp(cwe, category)
│   ├── knowledge.py         # consult_knowledge(query)
│   ├── list_skills.py       # list_skills(kind)
│   └── load_skill.py        # load_skill(name, version)
│
└── knowledge/               # Внешние БД (для Knowledge агента)
    ├── osv_query.py         # osv_query(package, version)
    ├── nvd_cve.py           # nvd_cve(cve_id)
    ├── ghsa.py              # ghsa(ghsa_id)
    ├── kev.py               # kev(cve_id)
    ├── epss.py              # epss(cve_id)
    ├── deps_dev.py          # deps_dev(package)
    └── web_search.py        # web_search(query)
```

## Как это работает: Пример

### 1. Агент объявляет свой инструментарий

`scanner/app/agents/architect/tools.py`:
```python
ROSTER = (
    'list_entry_points',
    'read_file',
    'grep',
    'lsp_symbols',
    'lsp_definition',
    'consult_owasp',
    'list_skills',
)
```

### 2. При создании агента вызывается `build()`

`scanner/app/agents/base.py`:
```python
def build(spec: AgentSpec, model, ctx: ToolContext, ...):
    names = spec.tools  # ['list_entry_points', 'read_file', ...]
    tools = make(names, ctx)  # Создаём tool functions
    return new_agent(
        name=spec.name,
        tools=tools,  # Передаём готовые functions в ADK
        ...
    )
```

### 3. `make()` создаёт tool функции из ToolContext

`scanner/adapter/tools/registry.py`:
```python
def make(names: Iterable[str], ctx: ToolContext) -> list[Callable]:
    """Для каждого имени берём factory из TOOLS, вызываем с ctx,
    получаем замыкание с привязанным контекстом."""
    
    TOOLS = {
        'read_file': read_file.make,        # factory function
        'grep': grep.make,
        'lsp_symbols': symbols.make,
        ...
    }
    
    return [TOOLS[n](ctx) for n in names]
```

### 4. Каждая factory создаёт замыкание

`scanner/adapter/tools/code/read_file.py`:
```python
def make(ctx: ToolContext):
    """Factory получает ctx, возвращает tool function."""
    
    def read_file(path: str, start: int = 1, end: int = 0) -> dict:
        """Внутренняя функция может использовать ctx!"""
        p = inside(ctx.target, path)  # ← Использует ctx.target
        if p is None:
            return err(f"not inside target")
        lines = p.read_text().splitlines()
        text = "\n".join(f"{i}: {lines[i-1]}" for i in range(start, end+1))
        return {"path": path, "text": text[:OUT_CAP]}  # ← Dict, не exception
    
    return read_file  # ← Замыкание захватило ctx
```

### 5. ADK вызывает tool, агент видит результат

LLM-агент может вызвать:
```json
{
  "type": "use_tool",
  "name": "read_file",
  "input": {
    "path": "src/auth.py",
    "start": 42,
    "end": 60
  }
}
```

LLM получит обратно:
```json
{
  "path": "src/auth.py",
  "start": 42,
  "end": 60,
  "text": "42: def verify_token(token):\n43:     ..."
}
```

## Зачем это всё устроено так?

### 1. **Конфайнмент** (безопасность)
```python
def inside(target: Path, rows: list[tuple]) -> list[tuple]:
    """Гарантирует: tool может читать только файлы в target"""
    return [r for r in rows if inside(target, r[0]) is not None][:50]
```
- Tools не могут выйти за пределы target
- Файлы конфайнены по размеру (FILE_CAP)
- Результаты кэпированы (OUT_CAP, GREP_CAP)

### 2. **Dependency Injection через ToolContext**
```python
# Тест может передать mock reader
ctx = ToolContext(
    target=test_target,
    run=FakeRun(),  # Не пишет на диск
    index=FakeIndex(),  # Не запускает LSP
    reader=lambda f, l: "mock code"
)
tool = read_file.make(ctx)
```

### 3. **Единый контракт tools**
- Никогда не выбрасывают исключения
- Всегда возвращают dict с `status` и результатом
- Одна сигнатура для всех: `(ctx) → fn(**args) → dict`

### 4. **Registry + Roster паттерн**
```python
# Глобальный registry (все tools)
TOOLS = {
    'read_file': read_file.make,
    'grep': grep.make,
    ...
}

# Каждый агент выбирает свой инструментарий
architect.ROSTER = ('list_entry_points', 'read_file', 'grep', ...)
investigator.ROSTER = ('report_finding', 'list_anchors', 'read_file', ...)

# make() собирает только нужные tools
tools = make(architect.ROSTER, ctx)  # 7 tools для architect
tools = make(investigator.ROSTER, ctx)  # Другой набор для investigator
```

## Ключевые инструменты (core tools)

| Tool | Цель | Кто использует |
|------|------|---|
| **report_finding** | ⭐ Вердикт: confirmed/rejected/uncertain + evidence | Investigator, specialists |
| **list_anchors** | Получить anchors для проверки | Все agents |
| **list_entry_points** | Найти entry points кода | Architect |
| **read_file** | Прочитать код (numbered) | Все agents |
| **grep** | Поиск по регулярке | Все agents |
| **lsp_*** | Навигация: symbols, definition, callers | Architect, Investigator |
| **consult_domain** | БД знаний: APIs, configs, security patterns | Domain specialist |
| **consult_owasp** | OWASP Top 10, CWE справочник | Investigator |

## Процесс с точки зрения agent

```
┌─ Агент запускается
│
├─ runner.py вызывает build(spec, ctx)
│  └─ make(spec.ROSTER, ctx) → список ready-to-call functions
│
├─ ADK LlmAgent передаёт tools в LLM
│  └─ LLM видит имена и схемы: report_finding, read_file, grep, ...
│
├─ LLM думает → "я вызову read_file(path='src/auth.py')"
│
├─ ADK вызывает tool: read_file(path='src/auth.py')
│  └─ read_file — это функция-замыкание, знает про ctx.target
│  └─ Возвращает {"status": "ok", "text": "42: def verify..."}
│
├─ LLM видит результат → "я вижу уязвимость на line 48!"
│
└─ LLM вызывает report_finding(anchor_id, status='confirmed', evidence=[...])
   └─ report_finding вызывает gate_finding() → проверка всех ограничений
   └─ Если ОК → сохраняет Finding в ctx.run
   └─ Если НЕ ОК → возвращает {"status": "error", "reason": "..."}
```

## Расширение: Добавить новый tool

1. Создать файл `scanner/adapter/tools/category/mytool.py`:
```python
def make(ctx: ToolContext):
    def mytool(param: str) -> dict:
        """Описание для LLM."""
        result = do_something(ctx.target, param)
        return {"status": "ok", "result": result}
    return mytool
```

2. Зарегистрировать в `registry.py`:
```python
from scanner.adapter.tools.category import mytool

TOOLS: dict[str, Callable[[ToolContext], Callable]] = {
    ...
    "mytool": mytool.make,
}
```

3. Добавить в агента `agents/<name>/tools.py`:
```python
ROSTER = (
    'read_file',
    'mytool',  # ← добавить
    'grep',
)
```

4. Написать тесты в `tests/test_tools_mytool.py`

---

## Итого: Почему это устроено так?

| Аспект | Зачем |
|--------|-------|
| **ToolContext** | DI для tools — не передавать 10 параметров в каждый tool |
| **Factory pattern** | Замыкание захватывает ctx → tool может использовать target, run, index |
| **Всегда dict** | LLM никогда не видит исключений — graceful error handling |
| **Registry** | Динамическая сборка инструментария → разные агенты, разные tools |
| **Roster** | Явная схема: какие tools нужны этому агенту |
| **Конфайнмент** | Безопасность: tools не могут выйти за пределы target |
