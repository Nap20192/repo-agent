"""list_skills: the skills corpus index (WSTG tests, classes, controls) — a plain function."""

from __future__ import annotations

from scanner.adapter.skills import list_skills
from scanner.adapter.tools.context import ToolContext


def make(ctx: ToolContext):
    return list_skills
