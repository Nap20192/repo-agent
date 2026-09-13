"""note_add: write to the run's shared scratchpad."""

from __future__ import annotations

from scanner.adapter.tools.context import ToolContext


def make(ctx: ToolContext):
    run = ctx.run

    def note_add(text: str, ref: str = "") -> dict:
        """Add a note to the run's shared scratchpad (survives rounds). ref: anchor/file it is about."""
        run.add_note(text, ref)
        return {"status": "ok"}

    return note_add
