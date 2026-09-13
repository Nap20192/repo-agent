"""list_anchors: the static-analysis facts every finding must reference."""

from __future__ import annotations

from scanner.adapter.tools.context import ToolContext


def make(ctx: ToolContext):
    run = ctx.run

    def list_anchors(cwe: str = "", severity: str = "", file: str = "", limit: int = 0) -> dict:
        """List static-analysis anchors (facts file:line found by scanners). Every finding
        must reference one of these by anchor_id. Filter by cwe, severity, file; limit the count."""
        all_ = run.anchors()
        out = [
            a.model_dump()
            for a in all_
            if (not cwe or a.cwe == cwe)
            and (not severity or a.severity == severity)
            and (not file or a.file == file)
        ]
        return {"anchors": out[:limit] if limit > 0 else out, "total": len(all_)}

    return list_anchors
