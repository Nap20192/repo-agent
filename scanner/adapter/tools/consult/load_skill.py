"""load_skill: one skill's playbook text — a plain function."""

from __future__ import annotations

from scanner.adapter.skills import load_skill
from scanner.adapter.tools.context import ToolContext


def make(ctx: ToolContext):
    return load_skill
