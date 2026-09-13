"""read_file: a numbered window of one file inside the target."""

from __future__ import annotations

from scanner.adapter.tools.common import FILE_CAP, OUT_CAP, READ_WINDOW, err, inside
from scanner.adapter.tools.context import ToolContext


def make(ctx: ToolContext):
    def read_file(path: str, start: int = 1, end: int = 0) -> dict:
        """Read lines [start, end] of a file inside the target, numbered (default window: 60 lines from start).
        Prefer lsp_definition for a symbol's body; use read_file for context around a line. Quote these lines
        as evidence."""
        p = inside(ctx.target, path)
        if p is None or not p.is_file():
            return err(f"{path}: not a file inside the target")
        if p.stat().st_size > FILE_CAP:
            return err(f"{path}: file larger than {FILE_CAP} bytes; use grep or lsp_definition")
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        if start > len(lines):
            return err(f"{path}: start {start} is past the last line ({len(lines)})")
        start = max(start, 1)
        end = min(end or start + READ_WINDOW - 1, len(lines))
        text = "\n".join(f"{i}: {lines[i - 1]}" for i in range(start, end + 1))
        return {"path": path, "start": start, "end": end, "text": text[:OUT_CAP]}

    return read_file
