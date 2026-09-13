"""Shared pieces of the agent tools: output caps, path confinement, shell quoting, default reader/index.
Every tool returns a dict; errors are {"status": "error", "reason": ...}, never raised into the model."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from scanner.adapter import static
from scanner.adapter.fs import (
    inside,
)
from scanner.core.ports import Index

OUT_CAP = 20_000
FILE_CAP = static.FILE_CAP
GREP_CAP = 4_000
DEF_CAP = 120  # lines of a definition body returned by lsp_definition
SYM_CAP = 200  # symbols listed by lsp_symbols
READ_WINDOW = 60
SHELL_TIMEOUT = 60


def err(reason: str) -> dict:
    return {"status": "error", "reason": reason}


def shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def default_reader(target: Path) -> Callable[[str, int], str]:
    return lambda file, line: static.read_lines(target, file, line, 3)


def default_index(target: Path) -> Index:
    """The real multiplexer (LSP per language, grep fallback) when a caller passed no Index."""
    from scanner.adapter.index import (
        build_index,  # tools ↔ index: import here keeps the module graph acyclic
    )

    return build_index(target)


def quotes_in_target(target: Path, quotes: list[str]) -> bool:
    """Is at least one quote present verbatim somewhere in the target? One pass over the files."""
    for f in static.files(target):
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        if any(q in text for q in quotes):
            return True
    return False




def confined(target: Path, rows: list[tuple]) -> list[tuple]:
    """Keep only rows whose file is inside the target (never leak files outside it); capped at 50."""
    return [r for r in rows if inside(target, r[0]) is not None][:50]
