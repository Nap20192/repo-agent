"""GrepIndex: the Index port over text search — the fallback when no language server is available."""

from __future__ import annotations

import re
from pathlib import Path

from scanner.adapter import static
from scanner.core.ports import Symbol

_DEF = re.compile(rf"^(?P<indent>\s*)(?:export\s+|async\s+)*(?P<kw>{static._DEF_KW})\s+(?P<name>\w+)")
_KIND = {"func": "function", "def": "function", "function": "function", "class": "class", "type": "struct",
         "const": "constant", "var": "variable", "let": "variable"}


class GrepIndex:
    def __init__(self, target: Path, extensions: tuple[str, ...] | None = None):
        self.target = Path(target).resolve()
        self.extensions = extensions  # None = every known source extension; else one language's files only
        self.failed = False

    def _owns(self, p: Path) -> bool:
        return p.suffix in static.LANG_EXT and (not self.extensions or p.suffix in self.extensions)

    def find_symbol(self, fqn: str) -> tuple[str, int] | None:
        return static.find_symbol(self.target, fqn, self.extensions)

    def has_symbol(self, fqn: str) -> bool:
        return self.find_symbol(fqn) is not None

    def definition_range(self, fqn: str) -> tuple[str, int, int] | None:
        loc = self.find_symbol(fqn)
        if loc is None:
            return None
        file, line = loc
        lines = self._lines(file)
        end = min(len(lines), line + 40)  # ponytail: heuristic body = until the next top-level def or 40 lines
        for i in range(line + 1, min(len(lines), line + 40) + 1):
            if _DEF.match(lines[i - 1]) and not lines[i - 1][0].isspace():
                end = i - 1
                break
        return file, line, end

    def references(self, fqn: str) -> list[tuple[str, int, str]]:
        name = fqn.rsplit(".", 1)[-1].strip()
        if not re.fullmatch(r"\w+", name):
            return []
        rx, defn = re.compile(rf"\b{re.escape(name)}\b"), self.find_symbol(fqn)
        out = []
        for p in static.files(self.target):
            if not self._owns(p):
                continue
            rel = str(p.relative_to(self.target))
            for i, ln in enumerate(self._lines(rel), 1):
                if rx.search(ln) and (rel, i) != defn:
                    out.append((rel, i, ln))
        return out

    def symbols(self, file: str) -> list[Symbol]:
        out, stack = [], []  # stack of (indent, name) for nesting by indentation (Python/JS classes)
        for i, ln in enumerate(self._lines(file), 1):
            m = _DEF.match(ln)
            if not m:
                continue
            indent = len(m.group("indent"))
            while stack and stack[-1][0] >= indent:
                stack.pop()
            kind = _KIND.get(m.group("kw").split()[0], "symbol")
            out.append(Symbol(name=m.group("name"), kind="method" if stack and kind == "function" else kind, file=file,
                              line=i, end_line=i, container=stack[-1][1] if stack else ""))
            if kind in ("class", "struct"):
                stack.append((indent, m.group("name")))
        return out

    def close(self) -> None:
        return None

    def _lines(self, file: str) -> list[str]:
        try:
            p = (self.target / file).resolve()
            if not p.is_relative_to(self.target) or p.stat().st_size > 2 * 1024 * 1024:
                return []  # symlink or '..' escaping the target, or too big to slurp
            return p.read_text(errors="replace").splitlines()
        except OSError:
            return []
