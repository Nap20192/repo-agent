"""CLI: `python -m scanner full --target <path> [--deps]` and `python -m scanner eval [dataset]`.
Exit codes of `full`: 0 clean, 2 confirmed findings, 1 error."""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path

from scanner import core
from scanner.app.runner import load_env, scan_full

log = logging.getLogger("scanner")


def cmd_full(args) -> int:
    try:
        s = scan_full(Path(args.target), deps=args.deps)
    except Exception as e:  # noqa: BLE001
        log.error("run failed: %s", e)
        return 1
    print(json.dumps({k: s[k] for k in ("run_id", "confirmed", "rejected", "uncertain", "stop_reason", "sarif_path")}, indent=2))
    return 2 if s["confirmed"] else 0

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

_SAFE_URL = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+(?:\.git)?$")


def _ensure_target(case: dict) -> Path:
    """Clone `url` into `target` when the case is remote and the directory is missing.

    The dataset is untrusted: only https://github.com/<org>/<repo> (no `ext::`, `file://`, option-shaped
    strings), only into `.targets/` under the working directory, `--` before positionals, no auth prompts."""
    target = Path(case["target"])
    if not target.is_dir() and case.get("url"):
        url = str(case["url"])
        if not _SAFE_URL.match(url):
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
    problems = []
    try:
        target = _ensure_target(case)
    except subprocess.CalledProcessError as e:
        return [f"clone failed: {e.stderr.strip()[:200]}"]
    if not target.is_dir():
        return [f"target missing: {target}"]
    for e in case["expected"]:
        f = target / e["file"]
        if not f.is_file():
            problems.append(f"{e['file']}: missing")
            continue
        n = len(f.read_text(errors="replace").splitlines())
        if e["line"] > n:
            problems.append(f"{e['file']}:{e['line']} past EOF ({n} lines)")
    return problems


def cmd_eval(args) -> int:
    data = json.loads(Path(args.dataset).read_text())
    ok = True
    rows = []
    for case in data["cases"]:
        if args.dry:
            problems = validate_case(case)
            ok &= not problems
            print(json.dumps({"case": case["name"], "ok": not problems, "problems": problems}))
            continue
        try:
            target = _ensure_target(case)
            s = scan_full(target)
            sc = score(s.get("findings", []), case["expected"], case.get("tolerance", 6))
        except Exception as e:  # noqa: BLE001
            sc = {"error": str(e), "tp": 0, "fp": 0, "fn": len(case["expected"]), "precision": 0, "recall": 0, "f1": 0}
        ok &= sc["fp"] == 0 and sc["fn"] == 0
        rows.append({"case": case["name"], **sc})
        print(json.dumps(rows[-1]))
    print(json.dumps({"all_ok": ok}))
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    load_env()
    ap = argparse.ArgumentParser(prog="scanner")
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("full", help="full scan of a local path")
    f.add_argument("--target", "-target", required=True)
    f.add_argument("--deps", "-deps", action="store_true", help="run osv-scanner even if SKIP_DEPS=1")
    f.set_defaults(fn=cmd_full)
    e = sub.add_parser("eval", help="precision/recall over eval/dataset.json")
    e.add_argument("dataset", nargs="?", default="eval/dataset.json")
    e.add_argument("--dry", action="store_true", help="validate the dataset (clone remote targets) without running the model")
    e.set_defaults(fn=cmd_eval)
    args = ap.parse_args(argv)
    return args.fn(args)
