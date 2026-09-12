"""Static dominance check for the Critic: does a control line (sanitizer, validator, guard) dominate
the sink line, i.e. is it on every path to the sink?

Approximation without a CFG (ponytail: brace/indent nesting, no data flow):
1. both lines lie in the same function (index symbols if given, else a header heuristic);
2. control comes before the sink;
3. the control's block chain is a prefix of the sink's — or its first non-shared block is an `if`
   guard whose body terminates (return/raise/throw/panic/exit/continue/break/res.status().send);
4. a control inside an else/elif/catch/except/default sibling branch never dominates.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from scanner.adapter import fs

_BRACE_LANGS = {"go", "javascript", "typescript", "php", "java", "c", "cpp", "rust"}
_EXT = {".go": "go", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".ts": "typescript",
        ".tsx": "typescript", ".py": "python", ".php": "php"}
_TERMINATOR = re.compile(r"\b(return|raise|throw|panic|continue|break|os\.Exit|sys\.exit|process\.exit|abort)\b"
                         r"|\.(send|end|json|redirect)\s*\(")
_BRANCH = re.compile(r"^\s*\}?\s*(else\b|elif\b|catch\b|except\b|default\b|finally\b)")
_IF = re.compile(r"^\s*(if|unless)\b")
_FUNC = {
    "go": re.compile(r"^\s*func\b(?:\s*\([^)]*\))?\s*(\w+)"),
    "python": re.compile(r"^\s*(?:async\s+)?def\s+(\w+)"),
    "javascript": re.compile(r"^\s*(?:export\s+)?(?:async\s+)?(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=.*=>|(\w+)\s*\([^)]*\)\s*\{)"),
}
_FUNC["typescript"] = _FUNC["javascript"]
_FUNC["php"] = re.compile(r"^\s*(?:public|private|protected|static|\s)*function\s+(\w+)")
_STRIP = re.compile(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`[^`]*`|//.*$|#.*$")


def _blocks_brace(lines: list[str]) -> list[list[int]]:
    """chain[i] = header line numbers (1-based) of the blocks enclosing line i+1, innermost last."""
    stack: list[int] = []
    chains = []
    for n, raw in enumerate(lines, 1):
        for ch in _STRIP.sub("", raw):
            if ch == "{":
                stack.append(n)
            elif ch == "}" and stack:
                stack.pop()
        chains.append(list(stack))
    return chains


def _blocks_indent(lines: list[str]) -> list[list[int]]:
    stack: list[tuple[int, int]] = []  # (indent, header line)
    chains = []
    for n, raw in enumerate(lines, 1):
        s = raw.strip()
        if not s or s.startswith("#"):
            chains.append([h for _, h in stack])
            continue
        ind = len(raw) - len(raw.lstrip())
        while stack and ind <= stack[-1][0]:
            stack.pop()
        chains.append([h for _, h in stack])
        if s.endswith(":"):
            stack.append((ind, n))
    return chains


def _block_body(lines: list[str], chains: list[list[int]], header: int) -> list[int]:
    return [n for n in range(header + 1, len(lines) + 1) if header in chains[n - 1]]


def _terminates(lines: list[str], chains: list[list[int]], header: int) -> bool:
    body = _block_body(lines, chains, header)
    if not body:  # one-liner `if x { return }`
        return bool(_TERMINATOR.search(_STRIP.sub("", lines[header - 1])))
    last = [n for n in body if lines[n - 1].strip() and not lines[n - 1].strip().startswith(("#", "//", "}"))]
    return bool(last and _TERMINATOR.search(lines[last[-1] - 1]))


def _function_of(lines: list[str], chains: list[list[int]], lang: str, line: int, symbols) -> tuple[str | None, int | None]:
    for s in sorted(symbols or [], key=lambda s: (s.end_line or s.line) - s.line):
        if s.kind in ("function", "method", "") and s.line <= line <= (s.end_line or s.line):
            return s.name, s.line
    rx = _FUNC.get(lang, _FUNC["javascript"])
    for h in reversed(chains[line - 1]):
        m = rx.match(lines[h - 1])
        if m:
            return next((g for g in m.groups() if g), None), h
    return None, None


def check(lines: list[str], lang: str, sink_line: int, control_line: int, symbols=None) -> dict:
    """Pure check over file lines; see module docstring for the rules."""
    if not (1 <= sink_line <= len(lines) and 1 <= control_line <= len(lines)):
        return {"status": "error", "reason": f"line out of range (file has {len(lines)} lines)"}
    chains = _blocks_indent(lines) if lang == "python" else _blocks_brace(lines)
    c_chain, s_chain = chains[control_line - 1], chains[sink_line - 1]
    fn_c, fn_s = _function_of(lines, chains, lang, control_line, symbols), _function_of(lines, chains, lang, sink_line, symbols)
    out = {"dominates": False, "function": fn_s[0], "control_depth": len(c_chain), "sink_depth": len(s_chain), "guard": False}
    if fn_c[1] != fn_s[1] or fn_s[1] is None:
        return {**out, "reason": f"control is in function {fn_c[0]!r}, sink in {fn_s[0]!r} — not the same function"}
    if control_line >= sink_line:
        return {**out, "reason": "control comes after the sink (or is the sink line)"}
    shared = 0
    while shared < min(len(c_chain), len(s_chain)) and c_chain[shared] == s_chain[shared]:
        shared += 1
    if shared == len(c_chain):
        return {**out, "dominates": True, "reason": "control precedes the sink in an enclosing block"}
    header = c_chain[shared]  # first block of the control that the sink is not inside
    text = lines[header - 1]
    if _BRANCH.match(text):
        return {**out, "reason": f"control sits in a sibling branch ({text.strip()[:40]!r}) the sink path may skip"}
    if _IF.match(text) and _terminates(lines, chains, header):
        return {**out, "dominates": True, "guard": True, "reason": "control sits in a guard clause whose body terminates"}
    return {**out, "reason": f"control is nested in a skippable block ({text.strip()[:40]!r}); sink is outside it"}


def make_check_dominance(target: Path, index) -> Callable[[str, int, int], dict]:
    """Build the `check_dominance` tool for the Critic (wire into critic_tools)."""
    target = Path(target).resolve()

    def check_dominance(file: str, sink_line: int, control_line: int) -> dict:
        """Does the control at control_line (sanitizer, validator, allow-list, parameterization, guard)
        DOMINATE the sink at sink_line — is it executed on every path to the sink? Static approximation:
        same function, control before sink, not nested in a branch the sink path can skip, unless it is a
        guard clause that returns/raises/throws. Returns {"dominates": bool, "reason", "function",
        "control_depth", "sink_depth", "guard"}. Call it before disprove_finding whenever your disproof is a
        control on the path; a control with dominates=false does NOT disprove the finding."""
        try:
            p = fs.inside(target, file)
            if p is None or not p.is_file():
                return {"status": "error", "reason": f"{file}: not a file inside the target"}
            try:
                syms = index.symbols(file) if index is not None else []
            except Exception:  # noqa: BLE001 — the index is optional here
                syms = []
            if p.stat().st_size > fs.FILE_CAP:
                return {"status": "error", "reason": f"{file}: file larger than {fs.FILE_CAP} bytes"}
            return check(p.read_text(errors="replace").splitlines(), _EXT.get(p.suffix, "javascript"),
                         int(sink_line), int(control_line), syms)
        except Exception as e:  # noqa: BLE001 — a tool never raises into the model
            return {"status": "error", "reason": f"check_dominance: {e}"}

    return check_dominance
