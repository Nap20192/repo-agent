"""Shared pieces of the agent tools: caps, path confinement, shell quoting, and the tools every role gets
(anchors, findings, notes, consult_knowledge, consult_owasp). Every tool returns a dict; errors are
{"status": "error", "reason": ...}, never raised into the model."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from scanner.adapter import knowledge as kn
from scanner.adapter import static
from scanner.adapter.fs import (
    inside,  # noqa: F401 — re-export: the one path-confinement helper
)
from scanner.adapter.owasp import consult_owasp
from scanner.core.ports import Index

OUT_CAP = 20_000
FILE_CAP = static.FILE_CAP
GREP_CAP = 4_000
DEF_CAP = 120  # lines of a definition body returned by lsp_definition
SYM_CAP = 200  # symbols listed by lsp_symbols
READ_WINDOW = 60
SHELL_TIMEOUT = 60
_ADVISORY_ID = re.compile(r"^(GHSA|CVE|PYSEC|GO|RUSTSEC|OSV)-", re.IGNORECASE)


def err(reason: str) -> dict:
    return {"status": "error", "reason": reason}


def shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def default_reader(target: Path) -> Callable[[str, int], str]:
    return lambda file, line: static.read_lines(target, file, line, 3)


def default_index(target: Path) -> Index:
    """The real multiplexer (LSP per language, grep fallback) when a caller passed no Index."""
    from scanner.adapter.index import (
        build_index,  # tools ↔ index: import here keeps the module graph acyclic
    )

    return build_index(target)


def quotes_in_target(target: Path, quotes: list[str]) -> bool:
    """Is at least one quote present verbatim somewhere in the target? One pass over the files."""
    for f in static.files(target):
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        if any(q in text for q in quotes):
            return True
    return False


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


def common_tools(run) -> list[Callable]:
    """Tools shared by every role: anchors, findings, notes, knowledge and OWASP consultants."""

    def list_anchors(cwe: str = "", severity: str = "", file: str = "", limit: int = 0) -> dict:
        """List static-analysis anchors (facts file:line found by scanners). Every finding
        must reference one of these by anchor_id. Filter by cwe, severity, file; limit the count."""
        all_ = run.anchors()
        out = [
            a.model_dump()
            for a in all_
            if (not cwe or a.cwe == cwe)
            and (not severity or a.severity == severity)
            and (not file or a.file == file)
        ]
        return {"anchors": out[:limit] if limit > 0 else out, "total": len(all_)}

    def list_findings() -> dict:
        """List all findings reported so far in this run."""
        return {"findings": [f.model_dump() for f in run.findings()]}

    def note_add(text: str, ref: str = "") -> dict:
        """Add a note to the run's shared scratchpad (survives rounds). ref: anchor/file it is about."""
        run.add_note(text, ref)
        return {"status": "ok"}

    def note_list() -> dict:
        """List notes from the run's shared scratchpad."""
        return {"notes": run.notes()}

    def consult_knowledge(query: str) -> dict:
        """Look up a known vulnerability at osv.dev (cache-first). query: an advisory id (GHSA-/CVE-/PYSEC-/GO-)
        or a package name. Cite the returned ref ('knowledge:<id>') in evidence — required by the
        gate for dependency findings."""
        q = query.strip()
        if _ADVISORY_ID.match(q):
            v = kn.osv_vuln(q)
            vulns = [v] if v.get("id") else []
        else:
            data = kn._cached("osv-query", q, lambda: kn.fetch("https://api.osv.dev/v1/query", data={"package": {"name": q}}))
            vulns = data.get("vulns") or []
        if not vulns:
            return err(f"no advisory for {q!r}")
        return _advisories(vulns)

    return [list_anchors, list_findings, note_add, note_list, consult_knowledge, consult_owasp]
