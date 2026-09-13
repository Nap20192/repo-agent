"""lsp_callees: what a symbol calls (call hierarchy, outgoing)."""

from __future__ import annotations

from scanner.adapter.tools.common import confined
from scanner.adapter.tools.context import ToolContext


def make(ctx: ToolContext):
    def lsp_callees(symbol: str) -> dict:
        """Symbols a function calls (callee file, definition line, callee symbol) — walk from an entry point
        down towards sinks without reading whole files; capped at 50."""
        refs = confined(ctx.target, ctx.idx.callees(symbol))
        return {"symbol": symbol, "callees": [{"file": f, "line": ln, "symbol": s} for f, ln, s in refs]}

    return lsp_callees
