"""lsp_references: every use of a symbol, confined to the target."""

from __future__ import annotations

from scanner.adapter.tools.common import confined
from scanner.adapter.tools.context import ToolContext


def make(ctx: ToolContext):
    def lsp_references(symbol: str) -> dict:
        """Every place a symbol is used or called (file, line, line text), resolved by the language server — the
        exhaustive call-site list the proof standard requires. Capped at 50; [] when the symbol is unknown."""
        refs = confined(ctx.target, ctx.idx.references(symbol))
        return {"symbol": symbol, "references": [{"file": f, "line": ln, "text": t} for f, ln, t in refs]}

    return lsp_references
