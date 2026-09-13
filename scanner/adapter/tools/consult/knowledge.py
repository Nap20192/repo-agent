"""consult_knowledge: osv.dev lookup (cache-first) for dependency findings."""

from __future__ import annotations

import re

from scanner.adapter import knowledge as kn
from scanner.adapter.tools.common import err
from scanner.adapter.tools.context import ToolContext

_ADVISORY_ID = re.compile(r"^(GHSA|CVE|PYSEC|GO|RUSTSEC|OSV)-", re.IGNORECASE)


def _advisories(vulns: list[dict]) -> dict:
    out = []
    for v in vulns[:5]:
        patched = v.get("fixed") or [
            ev.get("fixed")
            for aff in v.get("affected", [])
            for rg in aff.get("ranges", [])
            for ev in rg.get("events", [])
            if ev.get("fixed")
        ]
        out.append({
            "ref": f"knowledge:{v['id']}",
            "summary": (v.get("summary") or v.get("details") or "")[:300],
            "affected": [a.get("package", {}).get("name") for a in v.get("affected", [])][:5],
            "patched": patched[:5],
        })
    return {"advisories": out}


def make(ctx: ToolContext):
    def consult_knowledge(query: str) -> dict:
        """Look up a known vulnerability at osv.dev (cache-first). query: an advisory id (GHSA-/CVE-/PYSEC-/GO-)
        or a package name. Cite the returned ref ('knowledge:<id>') in evidence — required by the
        gate for dependency findings."""
        q = query.strip()
        if _ADVISORY_ID.match(q):
            v = kn.osv_vuln(q)
            vulns = [v] if v.get("id") else []
        else:
            data = kn.osv_query_package(q)
            vulns = data.get("vulns") or []
        if not vulns:
            return err(f"no advisory for {q!r}")
        return _advisories(vulns)

    return consult_knowledge
