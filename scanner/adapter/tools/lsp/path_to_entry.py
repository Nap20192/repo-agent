"""lsp_path_to_entry: the shortest caller chain from an entry point to a symbol (reachability)."""

from __future__ import annotations

from scanner.adapter import entrypoints
from scanner.adapter.tools.context import ToolContext


def make(ctx: ToolContext):
    entries_fn = ctx.entries_fn or (lambda: [c.symbol for c in entrypoints.entry_points(ctx.target) if c.symbol])

    def lsp_path_to_entry(symbol: str) -> dict:
        """Shortest caller chain from an entry point (route handler / main) to the symbol, e.g.
        ["main", "pingHandler", "runCmd"]; null when no entry reaches it within 6 hops. The Investigator
        uses it for reachability claims; the Critic uses a null path as the "unreachable" disproof, after
        confirming with lsp_callers that the chain is not merely cut by dynamic dispatch."""
        entries = entries_fn()
        return {"symbol": symbol, "entries": entries[:50], "path": ctx.idx.path_to_entry(symbol, entries)}

    return lsp_path_to_entry
