"""Domain skeleton extractors (pure text/regex over the target) and the deterministic consult over a DomainMap.

ponytail: regex per idiom, no AST — enough to seed the DomainModeler; the LLM grounds and completes it.
"""

from __future__ import annotations

import re
from pathlib import Path

from scanner.adapter import fs
from scanner.core.domain import DomainMap, Entity, Guard, RuleCandidate, Skeleton

OWNER = re.compile(r"^(?:user_?id|owner(?:_?id)?|tenant_?id|account_?id|created_?by)$", re.IGNORECASE)
_GO_STRUCT = re.compile(r"^type\s+(\w+)\s+struct\s*\{")
_GO_FIELD = re.compile(r"^\s*(\w+)\s+[\w.*\[\]]+")
_SQLC = re.compile(r"^--\s*name:\s*(\w+)")
_SQL_FROM = re.compile(r"\b(?:FROM|INTO|UPDATE)\s+(\w+)", re.IGNORECASE)
_CREATE = re.compile(r"CREATE TABLE(?: IF NOT EXISTS)?\s+\"?(\w+)\"?\s*\(", re.IGNORECASE)
_SQL_COL = re.compile(r"^\s*\"?(\w+)\"?\s+\w")
_PY_CLASS = re.compile(r"^class\s+(\w+)\((?:models\.Model|Base|db\.Model|DeclarativeBase)\)")
_PY_FIELD = re.compile(r"^\s{4}(\w+)\s*(?::\s*\w+)?\s*=\s*(?:models\.|Column|mapped_column|relationship|db\.)")
_PRISMA = re.compile(r"^model\s+(\w+)\s*\{")
_PRISMA_FIELD = re.compile(r"^\s+(\w+)\s+\w")
_MONGOOSE = re.compile(r"(\w+?)(?:Schema)?\s*=\s*new\s+(?:mongoose\.)?Schema\(\s*\{([^}]*)\}")
_MONGOOSE_MODEL = re.compile(r"mongoose\.model\(\s*['\"](\w+)['\"]\s*,\s*(\w+)")
_GUARD = re.compile(r"\b(login_required|permission_required|requires_auth|requireRole|requireAuth|ensureAuthenticated|"
                    r"ensureLoggedIn|isAdmin|isAuthenticated|passport\.authenticate|s\.auth|authRequired|jwt_required)\b")
_DEF = re.compile(r"^\s*(?:async\s+)?(?:def|func|function)\s+(\w+)")
_ROUTE_HANDLER = re.compile(r"\(\s*[\"'][^\"']*[\"']\s*,.*?([A-Za-z_$][\w$]*)\s*\)\s*;?\s*$")
_RULE_WORDS = re.compile(r"\b(only|must|cannot|can't|forbidden|owner|admin only|not allowed)\b", re.IGNORECASE)
_DOC_EXT = {".md", ".rst", ".txt"}


def _ent(name: str, fields: list[str], file: str, line: int) -> Entity:
    owner = next((f for f in fields if OWNER.match(f)), "")
    return Entity(name=name, fields=fields, owner_field=owner, symbol=name, file=file, line=line)


def _block(lines: list[str], start: int, close: str) -> list[str]:
    """Lines after `start` up to the first line starting with `close` (exclusive)."""
    out = []
    for ln in lines[start + 1:]:
        if ln.lstrip().startswith(close):
            break
        out.append(ln)
    return out


def _entities(rel: str, lines: list[str]) -> list[Entity]:
    out, ext = [], Path(rel).suffix
    for i, ln in enumerate(lines):
        if ext == ".go" and (m := _GO_STRUCT.match(ln)):
            fields = [f.group(1) for f in map(_GO_FIELD.match, _block(lines, i, "}")) if f and f.group(1) != "//"]
            out.append(_ent(m.group(1), fields, rel, i + 1))
        elif ext == ".sql" and (m := _CREATE.search(ln)):
            fields = [f.group(1) for f in map(_SQL_COL.match, _block(lines, i, ")")) if f and f.group(1).upper() not in ("PRIMARY", "FOREIGN", "CONSTRAINT", "UNIQUE")]
            out.append(_ent(m.group(1), fields, rel, i + 1))
        elif ext == ".py" and (m := _PY_CLASS.match(ln)):
            fields = [f.group(1) for f in map(_PY_FIELD.match, _block(lines, i, "class ")) if f]
            out.append(_ent(m.group(1), fields, rel, i + 1))
        elif ext == ".prisma" and (m := _PRISMA.match(ln)):
            fields = [f.group(1) for f in map(_PRISMA_FIELD.match, _block(lines, i, "}")) if f]
            out.append(_ent(m.group(1), fields, rel, i + 1))
        elif ext in (".js", ".ts") and (m := _MONGOOSE.search(ln)):
            fields = [f.split(":")[0].strip() for f in m.group(2).split(",") if ":" in f]
            out.append(_ent(m.group(1), fields, rel, i + 1))
    if ext in (".js", ".ts"):  # `mongoose.model("Memo", MemoSchema)` names the entity after the schema variable
        text = "\n".join(lines)
        for name, var in _MONGOOSE_MODEL.findall(text):
            for e in out:
                if var.startswith(e.name):
                    e.name = name
    return out


def _queries(rel: str, lines: list[str]) -> dict[str, list[str]]:
    """sqlc: `-- name: GetOrder :one` + the table in the statement → {table: [GetOrder]}."""
    out: dict[str, list[str]] = {}
    name = ""
    for ln in lines:
        if m := _SQLC.match(ln):
            name = m.group(1)
        elif name and (t := _SQL_FROM.search(ln)):
            out.setdefault(t.group(1).lower(), []).append(name)
            name = ""
    return out


def _guards(rel: str, lines: list[str]) -> list[Guard]:
    out = []
    for i, ln in enumerate(lines):
        for m in _GUARD.finditer(ln):
            wraps = ""
            if h := _ROUTE_HANDLER.search(ln):  # app.get("/x", isAdmin, handler)
                wraps = h.group(1) if h.group(1) != m.group(1) else ""
            elif i + 1 < len(lines) and (d := _DEF.match(lines[i + 1])):  # decorator on the previous line
                wraps = d.group(1)
            out.append(Guard(name=m.group(1), file=rel, line=i + 1, wraps=wraps))
    return out


def _handler_bodies(lines: list[str]) -> dict[str, str]:
    """name → body text for top-level functions (regex: from the def line to the next top-level def/`}`)."""
    out, name, body = {}, "", []
    for ln in lines:
        if m := _DEF.match(ln):
            if name:
                out[name] = "\n".join(body)
            name, body = m.group(1), [ln]
        elif name:
            body.append(ln)
    if name:
        out[name] = "\n".join(body)
    return out


def _ownership_candidates(rel: str, lines: list[str], entities: list[Entity]) -> list[RuleCandidate]:
    """A handler that touches an owned entity without ever mentioning its owner field is a rule candidate."""
    out = []
    for name, body in _handler_bodies(lines).items():  # ponytail: every top-level function, not only routed handlers
        for e in entities:
            if not e.owner_field or not re.search(rf"\b{re.escape(e.name)}\b", body, re.IGNORECASE):
                continue
            if re.search(rf"\b{re.escape(e.owner_field)}\b", body):
                continue
            line = next(i + 1 for i, ln in enumerate(lines) if _DEF.match(ln) and _DEF.match(ln).group(1) == name)
            out.append(RuleCandidate(text=f"{name} reads {e.name} without comparing {e.name}.{e.owner_field} to the caller", file=rel, line=line))
    return out


def extract(target: Path, index=None) -> Skeleton:
    """Deterministic domain skeleton of the target. `index` (optional) confirms entity symbols exist."""
    target = Path(target).resolve()
    entities: list[Entity] = []
    guards: list[Guard] = []
    cands: list[RuleCandidate] = []
    queries: dict[str, list[str]] = {}
    per_file: list[tuple[str, list[str]]] = []
    for p in fs.files(target):
        if p.suffix not in {*fs.LANG_EXT, ".sql", ".prisma", *_DOC_EXT} or p.stat().st_size > fs.FILE_CAP:
            continue
        rel = str(p.relative_to(target))
        try:
            lines = p.read_text(errors="replace").splitlines()
        except OSError:
            continue
        if p.suffix in _DOC_EXT or "test" in rel.lower():
            cands += [RuleCandidate(text=ln.strip(), file=rel, line=i + 1) for i, ln in enumerate(lines) if _RULE_WORDS.search(ln) and len(ln) < 300]
            if p.suffix in _DOC_EXT:
                continue
        entities += _entities(rel, lines)
        guards += _guards(rel, lines)
        for table, names in _queries(rel, lines).items():
            queries.setdefault(table, []).extend(names)
        per_file.append((rel, lines))
    for e in entities:
        e.queries = queries.get(e.name.lower(), []) + queries.get(e.name.lower() + "s", [])
        if index is not None and not index.has_symbol(e.symbol):
            e.symbol = ""
    for rel, lines in per_file:
        cands += _ownership_candidates(rel, lines, entities)
    guards.sort(key=lambda g: (g.file, g.line))
    return Skeleton(entities=entities, guards=guards, rule_candidates=cands)


def consult(dm: DomainMap, question: str) -> dict:
    """Deterministic answer from the DomainMap: the entity or rule the question names, its owner field,
    its rules and the roles/guards around it. Refs: domain:<entity> / domain:<rule id>."""
    q = question.strip().lower()
    rules = [r for r in dm.rules if r.id.lower() == q or r.id.lower() in q.split()]
    ent = next((e for e in dm.entities if e.name.lower() == q or re.search(rf"\b{re.escape(e.name.lower())}s?\b", q)), None)
    if ent is None and rules:
        ent = next((e for e in dm.entities if e.name == rules[0].entity), None)
    if ent is None and not rules:
        return {"status": "error", "reason": f"no entity or rule in the domain map matches {question!r}; known: "
                                              f"{[e.name for e in dm.entities]} / {[r.id for r in dm.rules]}"}
    if ent is not None:
        rules = rules or [r for r in dm.rules if r.entity == ent.name]
    return {
        "ref": f"domain:{ent.name}" if ent else f"domain:{rules[0].id}",
        "entity": ent.model_dump() if ent else None,
        "rules": [{**r.model_dump(), "ref": f"domain:{r.id}"} for r in rules],
        "roles": [r.model_dump() for r in dm.roles],
        "gaps": [g for g in dm.gaps if ent and ent.name.lower() in g.lower()],
    }
