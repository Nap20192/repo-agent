"""list_findings: everything reported so far in this run."""

from __future__ import annotations

from scanner.adapter.tools.context import ToolContext


def make(ctx: ToolContext):
    run = ctx.run

    def list_findings() -> dict:
        """List all findings reported so far in this run."""
        return {"findings": [f.model_dump() for f in run.findings()]}

    return list_findings
