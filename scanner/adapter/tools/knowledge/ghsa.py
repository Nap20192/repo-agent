"""ghsa: GitHub Advisory DB."""

from __future__ import annotations

from scanner.adapter import knowledge as kn
from scanner.adapter.tools.context import ToolContext


def make(ctx: ToolContext):
    def ghsa(query: str) -> dict:
        """GitHub Advisory DB: a GHSA id → cvss, cwes, vulnerable functions, patched versions; 'name@version' → ids."""
        return kn.ghsa(query.strip()) or {"status": "error", "reason": f"no GHSA data for {query!r}"}

    return ghsa
