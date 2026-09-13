"""nvd_cve: NVD CVSS and CWE for a CVE."""

from __future__ import annotations

from scanner.adapter import knowledge as kn
from scanner.adapter.tools.context import ToolContext


def make(ctx: ToolContext):
    def nvd_cve(cve: str) -> dict:
        """NVD: CVSS v3.1 score/vector and CWE ids for a CVE."""
        return kn.nvd_cve(cve.strip()) or {"status": "error", "reason": f"no NVD entry for {cve!r}"}

    return nvd_cve
