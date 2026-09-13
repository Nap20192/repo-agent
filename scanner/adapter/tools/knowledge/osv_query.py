"""osv_query: OSV by advisory id or ecosystem:name@version."""

from __future__ import annotations

from scanner.adapter import knowledge as kn
from scanner.adapter.tools.context import ToolContext


def make(ctx: ToolContext):
    def osv_query(query: str) -> dict:
        """OSV: an advisory id (GHSA-/CVE-/PYSEC-/GO-) → aliases, summary, fixed versions, CVSS vector, CWEs; or
        'ecosystem:name@version' (e.g. 'npm:tar@4.4.8') → the advisory ids affecting it."""
        q = query.strip()
        if ":" in q and "@" in q and not q.upper().startswith(("GHSA-", "CVE-")):
            eco, rest = q.split(":", 1)
            name, ver = rest.rsplit("@", 1)
            return {"ids": kn.osv_batch([(eco, name, ver)]).get(f"{name}@{ver}", [])}
        return kn.osv_vuln(q) or {"status": "error", "reason": f"no advisory {q!r}"}

    return osv_query
