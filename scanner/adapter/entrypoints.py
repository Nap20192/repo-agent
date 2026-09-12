"""Text detectors over source lines: entry points (trust boundaries) per language and symbol-definition grep.

Adding a language = one DETECTORS entry. Detectors are per-file functions because two of them carry state
across lines (a Python route decorator applies to the next `def`; a plain PHP page is one boundary).
Ported from git-agent3 internal/adapter/index/lsp/*entry.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterator
from pathlib import Path

from scanner.adapter.fs import LANG_EXT, MAX_DETECT_LINE, files
from scanner.core import Candidate

log = logging.getLogger("scanner.entrypoints")

_GO_ROUTE = re.compile(r"\.(?:HandleFunc|Handle|GET|POST|PUT|DELETE|PATCH|Any|Get|Post|Put|Delete|Patch|Options|Head)\(\s*\"[^\"]*\"\s*,\s*([\w.]+)")
_PY_ROUTE = re.compile(r"^\s*@\S+\.(?:route|get|post|put|delete|patch|api_route|websocket)\(\s*[\"'][^\"']+[\"']")
_PY_DEF = re.compile(r"^\s*(?:async\s+)?def\s+(\w+)")
_DJANGO_URL = re.compile(r"^\s*(?:path|re_path|url)\(\s*r?[\"'][^\"']*[\"']\s*,\s*([\w.]+)")
_JS_METHODS = r"(?:get|post|put|delete|patch|all|use)"
_JS_ROUTE = re.compile(rf"\b(?:app|router|server)\.({_JS_METHODS})\(\s*[\"'`]([^\"'`]*)[\"'`]\s*,[^;]{{0,200}}?([A-Za-z_$][\w$]*)\s*\)*\s*;?\s*$")
_JS_INLINE = re.compile(rf"\b(?:app|router|server)\.({_JS_METHODS})\(\s*[\"'`]([^\"'`]*)[\"'`]\s*,\s*(?:async\s*)?(?:\([^)]*\)\s*=>|\w+\s*=>|function\s*\()")
_JS_CHAIN = re.compile(rf"\.route\(\s*[\"'`]([^\"'`]*)[\"'`]\s*\)\.({_JS_METHODS})\(\s*([A-Za-z_$][\w$]*)")
_PHP_ROUTE = re.compile(r"Route::(get|post|put|delete|patch|any|match)\(\s*['\"]([^'\"]*)['\"]\s*,\s*\[\s*(\w+)::class\s*,\s*['\"](\w+)['\"]")
_PHP_INPUT = re.compile(r"\$_(?:GET|POST|REQUEST)\b")

Detector = Callable[[str, list[str]], list[Candidate]]  # (relative file, its lines) → entry points


def _numbered(lines: list[str]) -> Iterator[tuple[int, str]]:
    """1-based (line number, text), skipping lines too long to regex safely."""
    for i, ln in enumerate(lines, 1):
        if len(ln) <= MAX_DETECT_LINE:
            yield i, ln


def _go(rel: str, lines: list[str]) -> list[Candidate]:
    return [Candidate(kind="entry", file=rel, line=i, symbol=m.group(1)) for i, ln in _numbered(lines) if (m := _GO_ROUTE.search(ln))]


def _python(rel: str, lines: list[str]) -> list[Candidate]:
    out, pending = [], False
    for i, ln in _numbered(lines):
        if _PY_ROUTE.match(ln):
            pending = True
        elif pending and (m := _PY_DEF.match(ln)):
            out.append(Candidate(kind="entry", file=rel, line=i, symbol=m.group(1)))
            pending = False
        elif m := _DJANGO_URL.match(ln):
            out.append(Candidate(kind="entry", file=rel, line=i, symbol=m.group(1).rsplit(".", 1)[-1]))
    return out


def _js_line(rel: str, i: int, ln: str) -> list[Candidate]:
    if m := _JS_CHAIN.search(ln):
        return [Candidate(kind="entry", file=rel, line=i, symbol=m.group(3), route=[f"{m.group(2).upper()} {m.group(1)}"])]
    if m := _JS_INLINE.search(ln):  # inline handler: no symbol, the route is the identity
        return [Candidate(kind="entry", file=rel, line=i, symbol="", route=[f"{m.group(1).upper()} {m.group(2)}"])]
    if m := _JS_ROUTE.search(ln):
        return [Candidate(kind="entry", file=rel, line=i, symbol=m.group(3), route=[f"{m.group(1).upper()} {m.group(2)}"])]
    return []


def _js(rel: str, lines: list[str]) -> list[Candidate]:
    return [c for i, ln in _numbered(lines) for c in _js_line(rel, i, ln)]


def _php(rel: str, lines: list[str]) -> list[Candidate]:
    out, input_seen = [], False
    for i, ln in _numbered(lines):
        if m := _PHP_ROUTE.search(ln):
            out.append(Candidate(kind="entry", file=rel, line=i, symbol=f"{m.group(3)}.{m.group(4)}",
                                 route=[f"{m.group(1).upper()} {m.group(2)}"]))
        elif not input_seen and _PHP_INPUT.search(ln):  # plain PHP page: the file is the boundary
            input_seen = True
            out.append(Candidate(kind="entry", file=rel, line=i, symbol="", route=[rel]))
    return out


DETECTORS: dict[str, Detector] = {"go": _go, "python": _python, "javascript": _js, "typescript": _js, "php": _php}


def entry_points(target: Path) -> list[Candidate]:
    """Entry points of every source file the detectors know, one pass over the tree."""
    target = Path(target)
    out: list[Candidate] = []
    for p in files(target):
        detect = DETECTORS.get(LANG_EXT.get(p.suffix, ""))
        if detect is None:
            continue
        try:
            lines = p.read_text(errors="replace").splitlines()
        except OSError as e:
            log.warning("entry_points: unreadable %s: %s", p, e)
            continue
        out += detect(str(p.relative_to(target)), lines)
    return out


# --- symbol definitions by grep (fallback when no LSP server owns the language) ---------------------------

DEF_KW = r"(?:func(?:\s*\([^)]*\))?|def|function|class|const|var|let|type)"


def find_symbol(target: Path, fqn: str, extensions: tuple[str, ...] | None = None) -> tuple[str, int] | None:
    """(file, line) of the definition of fqn's last segment in the target (text grep), or None.
    `extensions` restricts the search to one language's files (per-language grep fallback)."""
    target = Path(target)
    name = fqn.rsplit(".", 1)[-1].strip()
    if not re.fullmatch(r"\w+", name):
        return None
    # ponytail: text grep over the tree, no index; swap for LSP/ctags if targets get big
    rx = re.compile(rf"^\s*(?:<\?php\s*)?(?:export\s+|async\s+)*{DEF_KW}\s+{re.escape(name)}\b")
    for p in files(target):
        if p.suffix not in LANG_EXT or (extensions and p.suffix not in extensions):
            continue
        try:
            with p.open(errors="replace") as fh:
                for i, ln in enumerate(fh, 1):
                    if rx.match(ln):
                        return str(p.relative_to(target)), i
        except OSError as e:
            log.warning("find_symbol: unreadable %s: %s", p, e)
            continue
    return None


def has_symbol(target: Path, fqn: str) -> bool:
    return find_symbol(target, fqn) is not None
