"""semgrep: registry packs per detected language (or SEMGREP_CONFIG), noise directories excluded, SARIF out."""

from __future__ import annotations

import os
from pathlib import Path

from scanner.adapter.fs import SKIP_DIRS, detect_langs
from scanner.adapter.scanners import process
from scanner.adapter.scanners.sarif import anchors_from_sarif
from scanner.core import Anchor

# registry packs per language (validated against the registry; p/express does not exist)
_SEMGREP_PACKS = {"go": ["p/golang"], "python": ["p/python", "p/flask", "p/django"],
                  "javascript": ["p/javascript", "p/nodejs"], "typescript": ["p/typescript", "p/nodejs"], "php": ["p/php"]}
# noise sources semgrep should not scan: CI, docs, fixtures, tests, templates
_SEMGREP_EXCLUDES = [".github", "docs", "artifacts", "*.md", "*.html", "*.yml", "*.yaml", "*.txt",
                     "**/test/**", "**/tests/**", "*_test.go", "*.test.js", "test_*.py", *sorted(SKIP_DIRS)]


def run(target: Path, cfg: str | None = None) -> list[Anchor]:
    # cfg is read once in `scan` and passed down; a direct caller (tests) may omit it and fall back to the env.
    cfg = cfg if cfg is not None else os.environ.get("SEMGREP_CONFIG")
    if cfg:
        cfgs, metrics = [cfg], ([] if cfg == "auto" else ["--metrics=off"])  # semgrep refuses `auto` with metrics off
    else:
        cfgs = sorted({p for lang in detect_langs(target) for p in _SEMGREP_PACKS.get(lang, [])}) or ["p/default"]
        metrics = ["--metrics=off"]
    args = [a for c in cfgs for a in ("--config", c)] + [a for e in _SEMGREP_EXCLUDES for a in ("--exclude", e)]
    out = process.run_cmd(["semgrep", "--sarif", "--quiet", *metrics, *args, "."], target)
    return anchors_from_sarif(out, "semgrep", target)
