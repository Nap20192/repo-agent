"""consult_owasp: the OWASP tables (WSTG / ASVS / Cheat Sheets) — a plain function, the same for every run."""

from __future__ import annotations

from scanner.adapter.owasp import consult_owasp
from scanner.adapter.tools.context import ToolContext


def make(ctx: ToolContext):
    return consult_owasp
