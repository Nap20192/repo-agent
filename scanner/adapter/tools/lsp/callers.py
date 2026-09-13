"""lsp_callers: who invokes a symbol (call hierarchy, incoming)."""

from __future__ import annotations

from scanner.adapter.tools.common import confined
from scanner.adapter.tools.context import ToolContext


def make(ctx: ToolContext):
    def lsp_callers(symbol: str) -> dict:
        """Call sites of a symbol (file, line, calling symbol) from the language server's call hierarchy — who
        invokes it. Use it to walk from a sink back towards the trust boundary; capped at 50."""
        refs = confined(ctx.target, ctx.idx.callers(symbol))
        return {"symbol": symbol, "callers": [{"file": f, "line": ln, "symbol": s} for f, ln, s in refs]}

    return lsp_callers
