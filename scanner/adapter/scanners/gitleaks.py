"""gitleaks over the working tree (no git history): CWE-798 anchors, the matched secret redacted."""

from __future__ import annotations

import json
from pathlib import Path

from scanner.adapter.fs import rel
from scanner.adapter.scanners import process
from scanner.core import Anchor, new_anchor_id, redact_secrets


def run(target: Path) -> list[Anchor]:
    out = process.run_cmd(["gitleaks", "detect", "--no-banner", "--no-git", "--report-format", "json",
                "--report-path", "/dev/stdout", "--exit-code", "0"], target)
    out = out[out.find("["):] if "[" in out else "[]"
    anchors = []
    for leak in json.loads(out or "[]"):
        file, line, rule = rel(target, leak.get("File", "")), int(leak.get("StartLine", 0)), leak.get("RuleID", "")
        if not file or not line:
            continue
        anchors.append(Anchor(
            id=new_anchor_id("gitleaks", rule, file, line), tool="gitleaks", rule_id=rule, cwe="CWE-798",
            severity="high", file=file, line=line, message=leak.get("Description", ""),
            snippet=redact_secrets((leak.get("Match") or "")[:200]),
        ))
    return anchors
