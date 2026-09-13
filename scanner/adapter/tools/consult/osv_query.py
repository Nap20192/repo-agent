"""osv_query: osv.dev by advisory id or ecosystem:name@version — the reference the gate wants for dependency verdicts."""

from __future__ import annotations

import re

from scanner.adapter import osv
from scanner.adapter.tools.common import err
from scanner.adapter.tools.context import ToolContext

# the only two shapes that leave the process (the query is model-written text: validate, never forward as is)
ADVISORY = re.compile(r"^[A-Za-z]{2,10}-[A-Za-z0-9.-]{1,60}$")  # GHSA-xxxx-xxxx-xxxx, CVE-2024-1234, PYSEC-…, GO-…
PACKAGE = re.compile(r"^([A-Za-z0-9._-]{1,30}):([A-Za-z0-9._/@-]{1,120})@([A-Za-z0-9._+-]{1,60})$")  # npm:@scope/name@1.2.3


def make(ctx: ToolContext):
    def osv_query(query: str) -> dict:
        """osv.dev: an advisory id (GHSA-/CVE-/PYSEC-/GO-) → ref 'knowledge:<id>', aliases, summary, fixed versions,
        CVSS vector, CWEs; or 'ecosystem:name@version' (e.g. 'npm:tar@4.4.8', 'PyPI:django@3.2') → the advisory ids
        affecting it. Cite the ref ('knowledge:<id>') in evidence — required by the gate for dependency findings."""
        q = query.strip()
        if m := PACKAGE.match(q):
            eco, name, ver = m.groups()
            ids = osv.batch([(eco, name, ver)]).get(f"{name}@{ver}", [])
            return {"ids": ids, "refs": [f"knowledge:{i}" for i in ids]} if ids else err(f"no advisory for {q!r}")
        if not ADVISORY.match(q):
            return err("query must be an advisory id (GHSA-…, CVE-…) or ecosystem:name@version (npm:tar@4.4.8)")
        v = osv.vuln(q)
        return {"ref": f"knowledge:{v['id']}", **v} if v.get("id") else err(f"no advisory {q!r}")

    return osv_query
