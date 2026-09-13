"""kev: CISA Known Exploited Vulnerabilities membership."""

from __future__ import annotations

from scanner.adapter import knowledge as kn
from scanner.adapter.tools.context import ToolContext


def make(ctx: ToolContext):
    def kev(cve: str) -> dict:
        """CISA KEV: is this CVE in the Known Exploited Vulnerabilities catalog?"""
        return {"cve": cve.strip(), "known_exploited": cve.strip() in kn.kev()}

    return kev
