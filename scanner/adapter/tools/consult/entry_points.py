"""list_entry_points: the deterministic trust boundaries (routes, handlers) the text detectors found."""

from __future__ import annotations

from scanner.adapter import entrypoints
from scanner.adapter.tools.context import ToolContext


def make(ctx: ToolContext):
    target = ctx.target

    def list_entry_points() -> dict:
        """List the deterministic entry points (trust boundaries) found by the text detectors:
        route registrations and handlers, with file:line and the handler symbol."""
        return {"entry_points": [c.model_dump() for c in entrypoints.entry_points(target)]}

    return list_entry_points
