# OWASP R&D — Cheat Sheet Series + Proactive Controls → Critic / Investigator / Architect

Источники (читались на месте, в проект не копировались):
`~/tmp/repos/owasp-CheatSheetSeries/cheatsheets/*.md` (121 листа, CC BY-SA 4.0 — `LICENSE` в репо) и
`~/tmp/repos/owasp-proactive-controls/docs/the-top-10/c1..c10` (в клоне файла LICENSE нет; проект OWASP
публикуется под CC BY-SA 4.0 — проверить перед публикацией). Наше: `CRITIC_INSTRUCTION`
(`scanner/app/instructions.py`), гейт `disprove_finding` (`scanner/adapter/tools.py:353`),
`scanner/skills/counterevidence.md`, `severity-calibration.md`, `scanner/core/calibrate.py`.

Ключевой вывод. Critic сегодня умеет только «опровергни, процитировав контроль», но список того, что
считается контролем, живёт в его голове (модель) и в двух общих скиллах. Cheat Sheets — готовый
канонический каталог «как выглядит правильный контроль» и «что контролем не является» по каждому
классу. Их надо превратить в **control-скиллы** (по классу CWE, с grep-паттернами на Go / Python /
Node) и подсунуть Critic'у через уже существующий `skill_for(cwe, kind)`. Это единственный
дешёвый способ поднять precision Critic'а без новой модели.

## 1. Каталог контрфактов (counter-fact catalog)

Правило «доминирует sink»: контроль засчитывается только если он стоит **на том же пути** между
ingress и sink, **раньше** опасного эффекта, **не может быть обойдён** флагом/веткой/исключением и
**относится к тому же контексту** (SQL-значение, а не идентификатор; HTML body, а не JS). Это
дословно `counterevidence.md` «What Does NOT Rule Out» + Injection Prevention Rule #2/#3 + XSS
«Dangerous Contexts». Ниже для каждого класса: контроль по cheat sheet → grep-паттерн → что именно
проверить на доминирование.

### CWE-89 SQL injection (SQL_Injection_Prevention, Query_Parameterization)
Контроли по листу: (1) prepared statements / bind variables — единственная полноценная защита;
(2) allow-list для частей запроса, которые нельзя биндить (имя таблицы, ASC/DESC) — только switch/map
на фиксированные значения; (3) stored procedures без динамического SQL; (4) escaping —
«STRONGLY DISCOURAGED», не контроль.

| Язык | Контроль | grep | Доминирует, если |
|---|---|---|---|
| Go | `db.Query(q, args...)` / `QueryRow` / `Exec` с `?`/`$1`; sqlc/sqlx `Get/Select(&x, q, args)`; GORM `Where("id = ?", id)` | `\.(Query|QueryRow|Exec)(Context)?\([^)]*\$\d|\?` ; `Where\("[^"]*\?` | тот же вызов, что и sink; ни одной конкатенации `+ name` / `fmt.Sprintf` в **тексте запроса** (Sprintf с `%d` в LIMIT — не контроль) |
| Python | psycopg/sqlite3 `cursor.execute(sql, (params,))`; Django ORM `filter(**)`, `raw(sql, [params])`, `extra` — нет; SQLAlchemy `text(q).bindparams()` / `session.execute(stmt, {..})` | `execute\(\s*["'][^"']*%s[^"']*["']\s*,` ; `execute\([^,]+,\s*[\(\[\{]` ; `\.raw\([^,]+,\s*\[` | второй аргумент `execute` — кортеж/словарь; f-string или `%` **до** `execute` = нет контроля |
| Node | `pg` `client.query('... $1', [v])`; `mysql2` `execute('... ?', [v])`; knex `where('id', v)` / `raw('?', [v])`; Prisma/TypeORM параметры | `\.query\(\s*[`'"][^`'"]*\$\d[^`'"]*[`'"]\s*,\s*\[` ; `\.execute\([^,]+,\s*\[` ; `knex\.raw\([^,]+,\s*\[` | плейсхолдеры **и** массив параметров в одном вызове; template literal с `${}` в SQL = нет контроля |

Allow-list для идентификаторов: `switch tableName {case "a","b"}` / `if col not in ALLOWED` / `if (!ALLOWED.has(col))` — засчитывать только если множество литеральное и `default` бросает.

### CWE-78 / CWE-77 / CWE-88 OS command & argument injection (OS_Command_Injection_Defense)
Контроли: (1) вообще не звать shell — библиотечная функция (`os.MkdirAll` вместо `mkdir`); (2) параметризация без shell (`exec.Command(name, arg1, arg2)`, `subprocess.run([..])` без `shell=True`, `execFile`/`spawn` без `shell:true`); (3) allow-list команды **и** аргументов, метасимволы `& | ; $ > < \` \ ! ' " ( )`, `--` перед пользовательскими аргументами; escaping (`escapeshellarg`) — не контроль против argument injection.

| Язык | grep контроля | Нет контроля |
|---|---|---|
| Go | `exec\.Command\(\s*"[a-z]` (литеральная команда, argv раздельно) | `exec.Command("sh", "-c", ...)`, `"bash", "-c"` |
| Python | `subprocess\.(run\|call\|Popen)\(\s*\[` без `shell=True` ; `shlex\.quote` только вместе с allow-list | `shell=True`, `os.system(`, `os.popen(` |
| Node | `execFile\(`, `spawn\(\s*['"][a-z]` без `shell: true` | `exec(`, `execSync(`, `spawn(..., {shell: true})`, `child_process.exec` с template literal |

Доминирует: пользовательская строка попадает **только** в отдельный элемент argv, а сама команда — литерал; дополнительно значение прошло allow-list-regex до вызова (`^[A-Za-z0-9._-]{1,64}$`) или `--` стоит перед ним.

### CWE-79 XSS (Cross_Site_Scripting_Prevention, DOM_based_XSS_Prevention, Django/Nodejs)
Контроли: контекстное output encoding через шаблонизатор с auto-escape; safe sinks (`textContent`, `setAttribute(safeName)`, `createTextNode`); sanitizer (DOMPurify) только для HTML-контента; CSP — defense in depth, **не** контроль (лист: «Sole Reliance on CSP» — анти-паттерн).

| Язык | Контроль | Нет контроля (escape hatch) |
|---|---|---|
| Go | `html/template` (`template.ParseFiles/New`) + `.Execute(w, data)`; `template.HTMLEscapeString` для body | `text/template` для HTML, `template.HTML(...)`, `template.JS(...)`, `fmt.Fprintf(w, "<div>"+x)`, `w.Write([]byte(x))` |
| Python | Django templates по умолчанию; Jinja2 `Environment(autoescape=True)` / `select_autoescape`; `markupsafe.escape`; `json_script` для данных в JS | `\|safe`, `mark_safe(`, `Markup(`, `autoescape=False`, `render_template_string` с f-string, `HttpResponse("<h1>"+x)` |
| Node | движки с auto-escape (`{{ }}` в Handlebars/EJS `<%= %>`/Pug `#{}`), `res.json()`, `escape-html`, `DOMPurify.sanitize` | `{{{ }}}`, `<%- %>`, `!{}`, `res.send('<div>'+x)`, `innerHTML =`, `dangerouslySetInnerHTML`, `bypassSecurityTrust*` |

Доминирует: тот **же** контекст (HTML body / attribute / JS / URL / CSS — таблица «XSS Prevention Rules Summary»); HTML-escape внутри `<script>` или в `href="javascript:"` не защищает. Для `href/src` контроль = allow-list схем `http(s)`.

### CWE-352 CSRF (Cross-Site_Request_Forgery_Prevention, Django, Nodejs)
Контроли по листу в порядке силы: встроенная защита фреймворка (Go ≥1.25 `http.CrossOriginProtection`, Django `CsrfViewMiddleware` + `{% csrf_token %}`, `csurf`/`csrf-csrf` в Express, `gorilla/csrf`, `justinas/nosurf`); synchronizer token (генерация на сервере, сравнение на каждом небезопасном методе); signed double-submit cookie; Fetch Metadata (`Sec-Fetch-Site`); `SameSite` — **только defense in depth**, сам по себе достаточен лишь при четырёх условиях листа (нет чужих поддоменов, нет state-changing GET, `Strict` или `Lax`+`__Host-`, есть Origin-проверка).

grep: Go `nosurf\.New|csrf\.Protect|CrossOriginProtection`; Python `CsrfViewMiddleware|csrf_token|@csrf_protect` (и **отсутствие** `@csrf_exempt` на роуте sink); Node `csurf\(|csrfProtection|doubleCsrf\(|Sec-Fetch-Site`. Доминирует: middleware применён к **тому** роутеру/группе, где sink, а не к соседнему; `csrf_exempt`/`ignoreMethods` не покрывает метод sink.

### CWE-22 path traversal (Input_Validation «File Upload», File_Upload, WSTG-ATHZ-01)
Контроли: канонизация + проверка префикса базовой директории; allow-list имени файла; отображение id → путь на сервере (пользователь передаёт ключ, не путь).

| Язык | Контроль | Ловушка |
|---|---|---|
| Go | `filepath.Clean` + `strings.HasPrefix(abs, base+string(os.PathSeparator))` или `filepath.Rel` без `..`; Go ≥1.24 `os.Root`/`os.OpenInRoot`; `http.Dir` (уже canonicalize) | `filepath.Join(base, userPath)` **без** проверки префикса — не контроль (`..` нормализуется наружу); `strings.Contains(p, "..")` — обходится |
| Python | `os.path.realpath` + `startswith(base + os.sep)`; `pathlib.resolve().is_relative_to(base)`; `werkzeug.utils.secure_filename`; `send_from_directory` | `os.path.join(base, user)` без проверки, `replace("..","")` |
| Node | `path.resolve(base, user)` + `startsWith(base + path.sep)`; `express.static`; allow-list regex имени | `path.join` без `startsWith`, `includes('..')` |

Доминирует: проверка стоит **после** canonicalize и **до** `open/read/send`; символические ссылки: только `realpath/EvalSymlinks/resolve()` считаются.

### CWE-918 SSRF (Server_Side_Request_Forgery_Prevention, C10)
Case 1 (известные адресаты): allow-list IP/доменов **после** валидации формата библиотекой, сравнение по результату парсинга; **redirect отключён** в HTTP-клиенте; протокол только из allow-list. Case 2 (любой адрес): резолв домена → все IP → блок приватных/link-local/metadata (169.254.169.254), IMDSv2, и снова без redirect. Deny-list — «last resort».

grep: Go `CheckRedirect:\s*func` (возвращает `http.ErrUseLastResponse`), `net.ParseIP`, `ip.IsPrivate\(\)|IsLoopback|IsLinkLocalUnicast`, литеральный `map[string]bool{"api.example.com"`; Python `allow_redirects=False`, `ipaddress.ip_address(...).is_private`, `urlparse(url).hostname in ALLOWED`; Node `redirect: 'manual'` / `maxRedirects: 0`, `ip-address`/`ipaddr.js` `.range()`, `new URL(u).hostname` против Set. Доминирует: проверка идёт по **тому же** URL, который уходит в клиент (не по исходной строке до нормализации), и redirect выключен; проверка только `startswith("https://")` — не контроль.

### CWE-502 deserialization (Deserialization)
Контроли: не использовать native-формат — JSON/XML DTO; подпись данных перед десериализацией; allow-list классов (`yaml.safe_load`, `SafeLoader`, `RestrictedUnpickler` с `find_class` allow-list, `ObjectInputFilter`); Go `encoding/gob` только на доверенном канале.
grep: Python `yaml\.safe_load|SafeLoader|json\.loads` (контроль) vs `pickle\.loads?\(|yaml\.load\([^)]*\)$|jsonpickle\.decode|marshal\.loads` (sink); Node `JSON\.parse` (безопасно) vs `node-serialize|unserialize\(|eval\(`. Доминирует: данные приходят из недоверенного источника **и** проходят allow-list/подпись до `load`; «мы используем YAML, а не pickle» без `safe_load` — не контроль.

### CWE-434 file upload (File_Upload)
Контроли (все нужны): allow-list расширений + защита от двойного расширения/`%00`; content-type **и** magic bytes; переименование в сгенерированное имя; лимит размера; хранение вне web-root или на отдельном домене; отсутствие exec-прав.
grep: Go `filepath.Ext(...)` + `switch ext {case ".png"`, `http.DetectContentType`, `io.LimitReader|MaxBytesReader`, `uuid.New()` в имени; Python `secure_filename`, `imghdr|magic.from_buffer`, `MAX_CONTENT_LENGTH`, `FileExtensionValidator`; Node `multer({limits:{fileSize}, fileFilter})`, `file-type`. Доминирует: проверка расширения по allow-list **и** контент; только `Content-Type` из запроса — не контроль.

### CWE-639 / 284 / 285 / 862 / 863 authz & IDOR (Authorization, IDOR_Prevention, C1)
Контроли: проверка владения/права **на каждый запрос** и **на конкретный объект**; выборка по датасету текущего пользователя (`current_user.projects.find(id)`, `WHERE id=? AND user_id=?`); deny-by-default; централизованный middleware/decorator, применённый к роуту sink; идентификатор из сессии, не из запроса.
grep: Go `WHERE .* user_id\s*=\s*\$|owner_id`, `if .*\.UserID != .*UserID`, `Authorize|RequireRole|PolicyEnforce`; Python `@login_required|@permission_required|get_object_or_404\([^,]+,\s*[^)]*user=|owner=request\.user|has_object_permission`; Node `req.user.id ===|ensureOwner|can\(|checkPermission`. Доминирует: сравнение владельца происходит **до** возврата/изменения объекта и на **этом** роуте; «только авторизованные» (auth ≠ authz) не контроль; GUID вместо int — defense in depth, не контроль (лист IDOR: «even with complex identifiers, access control checks are essential»).

### CWE-601 open redirect (Unvalidated_Redirects_and_Forwards)
Контроли: id/токен вместо URL; allow-list хостов; относительный путь только (`/…` и не `//…`); валидация по правилам SSRF-листа. grep: Go `url.Parse` + `u.IsAbs\(\)|u.Host != ""|strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//")`; Python `url_has_allowed_host_and_scheme`, `is_safe_url`; Node `new URL(next, base).origin === base.origin`. Доминирует: проверка над **тем же** значением, что уходит в `Redirect/redirect(`; `startswith("/")` без `//` и `\`-проверки — не контроль.

### CWE-287 / 521 / 916 auth & password storage (Password_Storage, Session_Management, C7)
Контроли: Argon2id (`m=19456,t=2,p=1` или сильнее), scrypt (`N=2^17,r=8,p=1` …), bcrypt cost ≥ 10, PBKDF2 только как legacy; constant-time compare (`subtle.ConstantTimeCompare`, `hmac.compare_digest`, `crypto.timingSafeEqual`); cookie `__Host-` + `Secure; HttpOnly; SameSite`. grep: `argon2id|golang.org/x/crypto/bcrypt|bcrypt.GenerateFromPassword|argon2.PasswordHasher|PBKDF2PasswordHasher|bcrypt.hash\(`. Нет контроля: `md5|sha1|sha256\(` пароля без KDF, `==` на секретах.

### CWE-798 / 312 secrets (Secrets_Management, Logging «Data to exclude»)
Контроли: секрет из env/секрет-менеджера, не литерал; ротация; не логировать (список исключений листа: session id, tokens, passwords, connection strings, keys). Для Critic: литерал секрета — интринсик-дефект (наше правило 08), контрфакт только «это placeholder/пример/тестовая фикстура, не используется» — процитировать, где он используется/не используется.

### CWE-611 XXE (XML_External_Entity_Prevention)
Контроли: `defusedxml`, `XMLParser(resolve_entities=False, no_network=True)`; Go `encoding/xml` не резолвит внешние сущности (контроль по умолчанию, но `Strict=false` не влияет); Node `libxmljs` `noent:false`, `fast-xml-parser` без DTD. Нет контроля: `lxml.etree.XMLParser()` по умолчанию, `xml.etree` для недоверенного ввода.

### Формат control-скилла и три примера (готовы к `scanner/skills/`)

Frontmatter как у остальных (`name`, `description`), плюс поле `cwes` для `list_skills`. Секции
фиксированные, чтобы Critic знал, где искать: **Control**, **Grep**, **Dominates when**, **Not a control**,
**Cite as**, **Remediation** (одна строка + URL листа). Подключение: расширить `_MAP` в
`scanner/adapter/skills.py` вторым скиллом на класс (`control-*`), а `CRITIC_INSTRUCTION` — «call
load_skill for the control skill of the CWE» (сейчас он грузит только `counterevidence` + класс-скилл).

````markdown
---
name: control-sql-parameterization
description: What a real SQL-injection control looks like (prepared statements, bind variables, identifier allow-lists) and how to prove it dominates the sink — for the Critic
cwes: CWE-89, CWE-943
---
# Control: SQL parameterization

## Control (OWASP SQL Injection Prevention CS, Defense Option 1 & 3)
Prepared statement with bind variables in the SAME call that executes the query; identifiers
(table/column/sort) only via a literal switch/map with a rejecting default.

## Grep
- Go: `\.(Query|QueryRow|Exec)(Context)?\(.*(\$[0-9]|\?)` , `Where\("[^"]*\?"`, sqlc-generated `db.<Method>(ctx, arg)`
- Python: `execute\(\s*["'][^"']*%s[^"']*["']\s*,\s*[\(\[\{]` , `\.raw\([^,]+,\s*\[` , `text\(.*\)\.bindparams`
- Node: `\.query\(\s*[`'"][^`'"]*\$[0-9][^`'"]*[`'"]\s*,\s*\[` , `\.execute\([^,]+,\s*\[` , `knex\.raw\([^,]+,\s*\[`

## Dominates when
1. The placeholder query string and the parameter list are in the very call at the anchor line.
2. No `+`, `fmt.Sprintf`, f-string, `%`, or template literal touches the query text before that call.
3. Identifier parts come from a literal allow-list whose default branch rejects.

## Not a control
Escaping (`mysql_real_escape_string`, `sanitize`), `strings.ReplaceAll(x, "'", "''")`, a WAF, an ORM
mention without the actual bound call, a safe sibling query in the same file, `%s` inside an
f-string that is then passed to `execute` without params.

## Cite as
counter_evidence = [the execute/Query line with placeholders, the params line]; reason =
"parameterized query dominates the sink (OWASP SQLi Prevention CS, Defense Option 1)".

## Remediation (for Investigator findings)
Use prepared statements with bind variables; allow-list identifiers.
https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
````

````markdown
---
name: control-path-traversal
description: What a real path-traversal control looks like (canonicalize then base-dir check, id→path mapping) and when it dominates the file sink — for the Critic
cwes: CWE-22, CWE-98, CWE-434
---
# Control: path containment

## Control (OWASP Input Validation CS «File Upload Validation», File Upload CS «Filename Safety»)
Canonicalize the FULL path (symlinks resolved) then require it to start with the base directory,
BEFORE open/read/send; or never take a path from the user at all (id → path map).

## Grep
- Go: `filepath\.(Clean|Abs|EvalSymlinks)` followed by `strings\.HasPrefix\(.*base` or `filepath\.Rel`; `os\.OpenInRoot|os\.Root`; `http\.Dir\(`
- Python: `os\.path\.realpath\(.*\)` + `startswith\(` ; `\.resolve\(\)\.is_relative_to\(` ; `secure_filename\(` ; `send_from_directory\(`
- Node: `path\.resolve\(` + `startsWith\(.*path\.sep` ; `express\.static\(`

## Dominates when
1. The containment check runs on the resolved path, after Clean/realpath/resolve.
2. It runs before the sink (`os.Open`, `open(`, `fs.readFile`, `sendFile`) on the same variable.
3. The base is a constant or config, not user input.

## Not a control
`filepath.Join(base, user)` alone, `strings.Contains(p, "..")`, `replace("..", "")`, checks before
URL-decoding, extension allow-list without containment, `secure_filename` on a full path.

## Cite as
counter_evidence = [the Clean/realpath line, the HasPrefix/is_relative_to line]; reason =
"canonicalized path is confined to the base dir before the open (OWASP Input Validation CS)".

## Remediation
Resolve the path and reject anything outside the base directory; prefer id→path mapping.
https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#file-upload-validation
````

````markdown
---
name: control-csrf
description: What a real CSRF control looks like (framework middleware, synchronizer/signed double-submit token, Fetch Metadata) and why SameSite alone rarely suffices — for the Critic
cwes: CWE-352
---
# Control: CSRF token / origin check

## Control (OWASP CSRF Prevention CS)
Built-in framework protection or a synchronizer token verified on every unsafe method of the route
that owns the sink; signed double-submit cookie; Fetch Metadata resource-isolation policy.
SameSite is defense in depth: sufficient alone ONLY if no shared registrable domain, no
state-changing GET, `Strict` (or `Lax` + `__Host-`), and Origin/Referer verification exist.

## Grep
- Go: `nosurf\.New\(|csrf\.Protect\(|http\.NewCrossOriginProtection|CrossOriginProtection`
- Python: `CsrfViewMiddleware|csrf_token|@csrf_protect` and NO `@csrf_exempt` on the sink view; Flask `CSRFProtect\(`
- Node: `csurf\(|doubleCsrf\(|csrfSynchronisedProtection|Sec-Fetch-Site`
- Cookies (defense in depth only): `SameSite=Strict|sameSite:\s*['"]?(strict|lax)`

## Dominates when
1. The middleware/decorator is registered on the router/group/blueprint that serves the sink route.
2. The sink's HTTP method is not excluded (`ignoreMethods`, `csrf_exempt`, a GET that mutates).
3. Token comparison happens server-side on every request (not only at login).

## Not a control
`SameSite` alone (unless the four conditions hold — quote them), CORS headers, a token that is
only rendered but never verified, checks on a sibling route, `Referer` present-but-not-compared.

## Cite as
counter_evidence = [middleware registration line, route registration line]; reason =
"CSRF middleware covers this route's unsafe methods (OWASP CSRF Prevention CS)".

## Remediation
Enable the framework's CSRF protection for all state-changing routes; add SameSite as defense in depth.
https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
````

## 2. Remediation в находке (Investigator → Reporter)

Сейчас `Finding` не несёт remediation, а `report_finding` его не принимает. Предложение:
- `core.types.Finding.remediation: str = ""` и `remediation_url: str = ""`; `report_finding` получает
  необязательные `remediation`, `remediation_url`; `store.write_report` кладёт их в SARIF
  `fixes[].description.text` (стандартное поле SARIF 2.1.0) и в `summary.findings[]`.
- Источник по умолчанию — таблица `CWE → (one-liner, URL)` в `scanner/adapter/owasp.py` (`_CHEAT` уже
  есть, не хватает one-liner'ов): для confirmed-находки без переданного remediation Reporter подставляет
  табличное. Тогда Investigator'у **не нужно** тратить вызов на `consult_owasp` ради ссылки.
- В `VERIFIER_INSTRUCTION` одна строка: «remediation: one sentence from the class skill's Remediation
  section, plus its URL». Без обязательности — гейт не меняется.
- Атрибуция (обязательна, CC BY-SA 4.0): в `THIRD_PARTY_NOTICES.md` и в футере SARIF
  `runs[0].tool.driver.properties.attribution`:
  «Remediation guidance adapted from the OWASP Cheat Sheet Series (https://cheatsheetseries.owasp.org),
  © OWASP Foundation, licensed under CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/).
  Control skills in scanner/skills/control-*.md are derived works under the same license.»
  ShareAlike означает: производные control-скиллы должны публиковаться под CC BY-SA 4.0, а не под
  лицензией кода проекта — держать их отдельным каталогом с собственным LICENSE.

## 3. Proactive Controls C1–C10 как чек-лист Architect'а

`ARCHITECT_INSTRUCTION` просит `entities / trust_boundaries / vuln_classes / deployment_signals`, но не
говорит, **какие вопросы задать коду**. Proactive Controls — ровно этот список. Предлагаемое поле
`ArchitectureModel.controls: list[{id: "C1".."C10", status: present|absent|unknown, symbol, note}]` и
вопросы:

| PC | Поле модели | Вопрос Architect'а (ответ = символ или `unknown`) | Чей потребитель |
|---|---|---|---|
| C1 Access Control | trust_boundaries, controls | Где единая точка проверки прав (middleware/decorator)? Deny-by-default? Роли захардкожены (`hasRole("ADMIN")`)? | ThreatModeler → authz-угрозы на роуты **без** middleware; Critic → C1-контроль как контрфакт для CWE-862/863 |
| C2 Crypto | controls, vuln_classes | Какой KDF для паролей? Где ключи/секреты (env vs литерал)? TLS-термин? | vuln_classes CWE-916/327/798 |
| C3 Validate input | trust_boundaries | Есть ли центральный слой валидации (pydantic/validator/DTO)? Allow-list или deny-list? Mass assignment (auto-binding)? | ThreatModeler CWE-20/915 |
| C4 Secure architecture | entities, deployment_signals | Сторонние компоненты с внешними входами; минимальная поверхность (лишние роуты) | Reconciler coverage |
| C5 Secure by default | deployment_signals | Debug/dev-флаги в конфиге (`DEBUG=True`, `app.debug`), дефолтные креды, `0.0.0.0` | intent + calibrate exposure |
| C6 Secure dependencies | deployment_signals | Lockfile есть? Пиннинг? (osv-якоря уже дают факты) | Reconciler: dependency-гипотезы |
| C7 Digital identities | controls | Сессии server-side или JWT? Cookie-флаги? Password reset flow? | vuln_classes CWE-287/384/613 |
| C8 Browser features | controls | CSP/HSTS/XFO middleware, cookie `HttpOnly/SameSite` | Critic: framework protection route для CWE-79/352 |
| C9 Logging | controls | Где логируются auth-события; логируются ли секреты (Logging «Data to exclude») | vuln_classes CWE-532 |
| C10 SSRF | trust_boundaries | Исходящие HTTP-клиенты с URL из входа; allow-list; redirect выключен? | ThreatModeler CWE-918 |

Architect отвечает на C1, C3, C8, C10 обязательно (они прямо задают угрозы), остальные — по наличию
сигналов. Это заменяет «call consult_owasp per class» на детерминированный чек-лист и даёт
ThreatModeler'у структурный вход вместо прозы.

## 4. Ловушки ложных контролей (из листов, по классам)

Общие (Input Validation, Injection Prevention, counterevidence.md): deny-list/blacklist символов;
client-side валидация; WAF/interceptor; «фреймворк защищает» без конкретного вызова; контроль на
соседнем роуте или после sink; контроль, который может fail-open (`try/except: pass`).

| Класс | Выглядит как контроль, но нет |
|---|---|
| SQLi | escaping (Defense Option 4 — discouraged), `ReplaceAll("'", "''")`, ORM-упоминание без bound-вызова, `%s` в f-string перед `execute` |
| OS cmd | `escapeshellarg`/`shlex.quote` без allow-list (argument injection остаётся), удаление `;` и `|` |
| XSS | HTML-escape в JS/URL/CSS-контексте, CSP как единственная защита, `X-XSS-Protection`, sanitizer для не-HTML контекста, escape **после** `innerHTML` |
| CSRF | `SameSite=Lax` при наличии state-changing GET или чужих поддоменов, CORS, `Referer` присутствует, но не сравнивается, токен рендерится, но не проверяется |
| Path | `Join` без префикс-проверки, `Contains("..")`, проверка до URL-decode, extension allow-list без containment |
| SSRF | `startswith("https://")`, deny-list `127.0.0.1` (обход `0x7f000001`, `[::ffff:127.0.0.1]`, DNS rebinding), проверка до resolve, клиент с включёнными redirect |
| Deser | «YAML, не pickle» без `safe_load`; подпись, проверяемая после `load`; allow-list классов, которую задаёт вызывающий |
| Upload | только `Content-Type` из запроса, только расширение, `secure_filename` на полном пути |
| Authz | auth ≠ authz (`login_required` для IDOR), GUID вместо проверки владельца, проверка роли вместо владения, проверка после fetch |
| Redirect | `startswith("/")` без `//` и `\`, проверка домена по `endswith("example.com")` |
| Secrets | «это тестовый ключ» без доказательства, что он не используется; секрет в env, но залогирован |

## 5. Ранжированные предложения

| # | Предложение | Precision / Recall | Effort | Файлы | Риск |
|---|---|---|---|---|---|
| 1 | Control-скиллы `control-*` по каталогу §1 (9 классов), `skill_for` отдаёт второй скилл Critic'у, `CRITIC_INSTRUCTION` грузит его | ↑↑ precision Critic (опровержения с настоящими контрфактами), ↓ ложных disprove по ловушкам §4 | M | scanner/skills/control-*.md, scanner/adapter/skills.py, scanner/app/instructions.py, tests/test_skills.py | ShareAlike: отдельный каталог с CC BY-SA LICENSE |
| 2 | `Finding.remediation(+url)` + таблица CWE→remediation в `owasp.py` + SARIF `fixes[]` + атрибуция | нейтрально к точности; ценность отчёта в CI | S | core/types.py, adapter/owasp.py, adapter/tools.py, adapter/store.py, THIRD_PARTY_NOTICES.md | нет |
| 3 | `ArchitectureModel.controls` по C1–C10 + вопросы §3 в `ARCHITECT_INSTRUCTION`; ThreatModeler ставит authz/CSRF/SSRF-угрозы туда, где контроль `absent` | ↑ recall дизайн-угроз (то, чего сканеры не видят: NodeGoat authz), ↑ precision (угроза не ставится там, где C1/C8 `present`) | M | core/types.py, app/instructions.py, app/reconcile.py, tests | больше токенов у Architect (+2–4 вызова) |
| 4 | Ловушки §4 в `counterevidence.md` как «Not a control by class» + в Critic rule 09/13 | ↑ precision, ↓ галлюцинированных контрфактов | S | scanner/skills/counterevidence.md | нет |
| 5 | Calibrate: `exposure` из `ArchitectureModel.controls` (C1 present → `privileged`, C5 debug → `exposed`) вместо дефолта `internal` | точнее score, не статус | S | core/calibrate.py, app/pipeline_v2.py | нет |
| 6 | Cookie/session/headers (C7/C8) как отдельный класс гипотез `config` с grep-детектором (semgrep уже даёт CWE-614/522), контрфакт = флаги в коде | ↑ recall низкой важности; шум | S | adapter/static.py | шум в очереди — только при пустой очереди |
| 7 | Docker_Security rules #2/#4/#8 как `deployment_signals`-детектор (USER, no-new-privileges, read-only) | только intent/exposure | S | adapter/static.py | нет |

## Handoff — top 3

1. **Control-скиллы для Critic** (предложение 1): 9 файлов `scanner/skills/control-*.md` по формату §1
   (три готовы выше: sql-parameterization, path-traversal, csrf), `skill_for(cwe, kind, role="critic")`
   → второй скилл, одна строка в `CRITIC_INSTRUCTION`. Это прямой ответ на baseline eval, где Critic
   0/2: ему нечего цитировать, потому что он не знает, как выглядит контроль в Go/Python/Node.
2. **Remediation + атрибуция** (предложение 2): `Finding.remediation/_url`, таблица в `owasp.py`,
   SARIF `fixes[]`, текст CC BY-SA 4.0 в `THIRD_PARTY_NOTICES.md`; control-скиллы вынести в каталог с
   собственным LICENSE (ShareAlike).
3. **C1–C10 как чек-лист Architect'а** (предложение 3): поле `controls[]` в `ArchitectureModel`,
   обязательные C1/C3/C8/C10; ThreatModeler ставит угрозы туда, где контроль `absent`, Critic использует
   `present` как контрфакт-маршрут. Закрывает дыру NodeGoat (authz/IDOR без якорей сканеров).
Вне области: WSTG-методики (другой участник), ASVS-покрытие, DAST-разделы листов.
