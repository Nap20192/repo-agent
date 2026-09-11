"""CLI: `python -m scanner full --target <path> [--deps]` and `python -m scanner eval [dataset]`.
Exit codes of `full`: 0 clean, 2 confirmed findings, 1 error."""

from __future__ import annotations

import argparse
import json
import logging
import os
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

def cmd_eval(args) -> int:
    data = json.loads(Path(args.dataset).read_text())
    ok = True
    rows = []
    for case in data["cases"]:
        try:
            s = scan_full(Path(case["target"]))
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
    e.set_defaults(fn=cmd_eval)
    args = ap.parse_args(argv)
    return args.fn(args)
