"""scan(): every applicable scanner concurrently (one thread each — they are subprocesses); a failed or missing
scanner lands in `failed`, never raises; secret-class anchors are redacted and duplicates merged."""

from __future__ import annotations

import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from pydantic import BaseModel, Field

from scanner.adapter.fs import detect_langs
from scanner.adapter.scanners import gitleaks, gosec, osv, semgrep
from scanner.core import Anchor, merge_duplicates, redact_secrets

log = logging.getLogger("scanner.scanners")


class ScanResult(BaseModel):
    anchors: list[Anchor] = Field(default_factory=list)
    ran: list[str] = Field(default_factory=list)
    failed: dict[str, str] = Field(default_factory=dict)


def scan(target: Path, skip_deps: bool = False) -> ScanResult:
    """Run every applicable scanner; a failed/missing scanner lands in `failed`, never raises."""
    target = Path(target)
    langs = detect_langs(target)
    semgrep_cfg = os.environ.get("SEMGREP_CONFIG")
    jobs = []
    if "go" in langs or not langs:
        jobs.append(("gosec", gosec.run))
    if semgrep_cfg or (langs - {"go"}):
        jobs.append(("semgrep", lambda t: semgrep.run(t, semgrep_cfg)))
    if not skip_deps:
        jobs.append(("osv", osv.run))
    jobs.append(("gitleaks", gitleaks.run))
    return run_jobs(target, jobs)


def run_jobs(target: Path, jobs) -> ScanResult:
    """Scanners run concurrently (one thread each: they are subprocesses); results are merged in job order."""
    res = ScanResult()

    def one(tool, fn):
        t0 = time.monotonic()
        try:
            return fn(target), None, time.monotonic() - t0
        except Exception as e:  # noqa: BLE001 — scanner failure is a result, not a crash
            return [], f"{type(e).__name__}: {e}"[:300], time.monotonic() - t0

    with ThreadPoolExecutor(max_workers=max(1, len(jobs))) as ex:
        futures = [(tool, ex.submit(one, tool, fn)) for tool, fn in jobs]
        for tool, fut in futures:
            anchors, err, secs = fut.result()
            log.info("static: %s %s in %.1fs", tool, "failed" if err else f"{len(anchors)} anchors", secs)
            if err:
                res.failed[tool] = err
            else:
                res.anchors += anchors
                res.ran.append(tool)
    for a in res.anchors:  # a secret-class anchor (semgrep private-key, gitleaks…) must not carry the secret itself
        if a.cwe == "CWE-798":
            a.snippet, a.message = redact_secrets(a.snippet), redact_secrets(a.message)
    res.anchors = merge_duplicates(res.anchors)
    return res
