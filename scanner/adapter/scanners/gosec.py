"""gosec: one run per Go module (cwd = the module root), SARIF out."""

from __future__ import annotations

from pathlib import Path

from scanner.adapter.fs import files
from scanner.adapter.scanners import process
from scanner.adapter.scanners.sarif import anchors_from_sarif
from scanner.core import Anchor, new_anchor_id


def run(target: Path) -> list[Anchor]:
    """gosec needs a module root as cwd: one run per go.mod (Photoview keeps its module in api/); the root
    is used only when no go.mod exists. Reported paths are module-relative and get re-rooted to the target."""
    out = []
    for mod in sorted({p.parent for p in files(target) if p.name == "go.mod"}) or [target]:
        sub = "" if mod == target else str(mod.relative_to(target))
        for a in anchors_from_sarif(process.run_cmd(["gosec", "-fmt", "sarif", "-quiet", "-no-fail", "./..."], mod), "gosec", mod):
            if sub:
                file = f"{sub}/{a.file}"
                a = a.model_copy(update={"file": file, "id": new_anchor_id("gosec", a.rule_id, file, a.line)})
            out.append(a)
    return out
