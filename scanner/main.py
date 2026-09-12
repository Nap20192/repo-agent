"""CLI: `python -m scanner full --target <path> [--deps]` and `python -m scanner eval [dataset]`.
Exit codes of `full`: 0 clean, 2 confirmed findings, 1 error."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from eval.dataset import load_dataset, run_case, validate_case
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

def cmd_eval(args) -> int:
    ok = True
    for case in load_dataset(args.dataset):
        if args.dry:
            problems = validate_case(case)
            ok &= not problems
            print(json.dumps({"case": case["name"], "ok": not problems, "problems": problems}))
            continue
        row = run_case(case, scan_full)
        ok &= row["fp"] == 0 and row["fn"] == 0
        print(json.dumps(row))
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
