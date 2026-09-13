"""osv-scanner over the explicit dependency manifests: one anchor per vulnerable package, capped at OSV_MAX."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path

from scanner.adapter.fs import files, rel
from scanner.core import Anchor, new_anchor_id

log = logging.getLogger("scanner.scanners.osv")

_MANIFESTS = {"go.mod", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "poetry.lock",
              "Pipfile.lock", "composer.lock", "Cargo.lock", "Gemfile.lock", "pom.xml", "gradle.lockfile"}


def run(target: Path) -> list[Anchor]:
    if shutil.which("osv-scanner") is None:
        raise FileNotFoundError("osv-scanner not installed")
    # explicit lockfiles: osv-scanner's git-aware directory walk finds nothing inside a shallow clone
    manifests = [str(p.relative_to(target)) for p in files(target) if p.name in _MANIFESTS]
    if not manifests:
        raise RuntimeError("no dependency manifests (go.mod, package-lock.json, requirements.txt, ...)")
    args = [a for m in manifests for a in ("-L", m)]
    p = subprocess.run(["osv-scanner", "--format", "json", *args], cwd=target, capture_output=True, text=True,
                       timeout=600, check=False)  # exit 1 = vulnerabilities found, JSON still on stdout
    if not p.stdout.strip():
        raise RuntimeError(p.stderr.strip()[:300] or "no output")
    return anchors_from_osv(json.loads(p.stdout), target)


OSV_MAX = int(os.environ.get("OSV_MAX", "40"))


def anchors_from_osv(data: dict, target: Path) -> list[Anchor]:
    """One anchor per vulnerable (manifest, package@version), all advisory ids merged into rule_ids;
    capped at OSV_MAX packages (most advisories first) — a stale lockfile must not flood the queue."""
    out = []
    for res in data.get("results", []):
        file = rel(target, res.get("source", {}).get("path", ""))
        for pkg in res.get("packages", []):
            name = pkg.get("package", {}).get("name", "")
            ver = pkg.get("package", {}).get("version", "")
            vulns = pkg.get("vulnerabilities", [])
            ids = [v.get("id", "") for v in vulns if v.get("id")]
            if not ids:
                continue
            first = next((v for v in vulns if v.get("id", "").startswith("GHSA-")), vulns[0])
            out.append(Anchor(
                id=new_anchor_id("osv", f"{name}@{ver}", file, 1), tool="osv", rule_id=first.get("id", ""), rule_ids=ids,
                severity="high", file=file, line=1, snippet=f"{name} {ver}",
                message=f"{name}@{ver}: {len(ids)} advisories ({', '.join(ids[:4])}{'…' if len(ids) > 4 else ''}) — "
                        f"{first.get('summary', '')}".strip(),
            ))
    out.sort(key=lambda a: -len(a.rule_ids))
    if len(out) > OSV_MAX:
        log.warning("osv: %d vulnerable packages, keeping the %d with most advisories (OSV_MAX)", len(out), OSV_MAX)
    return out[:OSV_MAX]
