"""epss: FIRST exploit-probability scores."""

from __future__ import annotations

from scanner.adapter import knowledge as kn
from scanner.adapter.tools.context import ToolContext


def make(ctx: ToolContext):
    def epss(cves: list[str]) -> dict:
        """FIRST EPSS: probability (0..1) that each CVE is exploited in the next 30 days."""
        return {"epss": kn.epss([c.strip() for c in cves])}

    return epss
