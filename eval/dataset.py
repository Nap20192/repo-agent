"""Eval dataset: loading, validation (`--dry`), clone-on-demand of remote targets, and scoring.

Use-case logic of `scanner eval`; scanner/main.py only parses arguments and maps results to exit codes."""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from pathlib import Path

from scanner import core

log = logging.getLogger("scanner.eval")

SAFE_URL = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+(?:\.git)?$")


def load_dataset(path: str | Path) -> list[dict]:
    return json.loads(Path(path).read_text())["cases"]


def score(findings: list[dict], expected: list[dict], tolerance: int) -> dict:
    """precision/recall/F1 of confirmed findings vs ground truth by (cwe, file, |line| <= tolerance)."""
    conf = [f for f in findings if f.get("status") == core.CONFIRMED]
    used, tp = set(), 0
    for e in expected:
        for i, f in enumerate(conf):
            if i in used:
                continue
            if f.get("cwe") == e["cwe"] and f.get("file") == e["file"] and abs(int(f.get("line", 0)) - e["line"]) <= tolerance:
                used.add(i)
                tp += 1
                break
    fp, fn = len(conf) - tp, len(expected) - tp
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r, "f1": f1}


def ensure_target(case: dict) -> Path:
    """Clone `url` into `target` when the case is remote and the directory is missing.

    The dataset is untrusted: only https://github.com/<org>/<repo> (no `ext::`, `file://`, option-shaped
    strings), only into `.targets/` under the working directory, `--` before positionals, no auth prompts."""
    target = Path(case["target"])
    if not target.is_dir() and case.get("url"):
        url = str(case["url"])
        if not SAFE_URL.match(url):
            raise ValueError(f"refusing to clone {url!r}: only https://github.com/<org>/<repo>")
        root = Path(".targets").resolve()
        if not target.resolve().is_relative_to(root):
            raise ValueError(f"refusing to clone into {target}: outside {root}")
        log.info("eval: cloning %s → %s", url, target)
        subprocess.run(["git", "clone", "--depth", "1", "--", url, str(target)], check=True, capture_output=True,
                       text=True, timeout=300, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    return target


def validate_case(case: dict) -> list[str]:
    """Dataset sanity without a model: target exists, every expected file exists and the line is inside it."""
    try:
        target = ensure_target(case)
    except subprocess.CalledProcessError as e:
        return [f"clone failed: {e.stderr.strip()[:200]}"]
    if not target.is_dir():
        return [f"target missing: {target}"]
    problems = []
    for e in case["expected"]:
        f = target / e["file"]
        if not f.is_file():
            problems.append(f"{e['file']}: missing")
            continue
        n = len(f.read_text(errors="replace").splitlines())
        if e["line"] > n:
            problems.append(f"{e['file']}:{e['line']} past EOF ({n} lines)")
    return problems


def run_case(case: dict, scan) -> dict:
    """Scan one case with `scan(target) -> summary` and score it; errors become a zero-score row."""
    try:
        s = scan(ensure_target(case))
        sc = score(s.get("findings", []), case["expected"], case.get("tolerance", 6))
    except Exception as e:  # noqa: BLE001 — one broken case must not stop the dataset
        sc = {"error": str(e), "tp": 0, "fp": 0, "fn": len(case["expected"]), "precision": 0, "recall": 0, "f1": 0}
    return {"case": case["name"], **sc}
