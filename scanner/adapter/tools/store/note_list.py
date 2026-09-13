"""note_list: read the run's shared scratchpad."""

from __future__ import annotations

from scanner.adapter.tools.context import ToolContext


def make(ctx: ToolContext):
    run = ctx.run

    def note_list() -> dict:
        """List notes from the run's shared scratchpad."""
        return {"notes": run.notes()}

    return note_list
