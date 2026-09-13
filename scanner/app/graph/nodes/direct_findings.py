"""direct_findings: the deterministic lane (card 42) — osv / gitleaks / semgrep-ERROR anchors become findings
through the store's dedup, no model, no gate; the rest go on to the modelling stages."""

from __future__ import annotations

import logging
from pathlib import Path

from google.adk.workflow import FunctionNode

from scanner.adapter.fs import imported_by
from scanner.app.graph.reconcile import direct_finding, split_direct
from scanner.core import Anchor
from scanner.core.ports import RunStore

log = logging.getLogger("scanner.graph.direct")


def report_direct(store: RunStore, target: str, direct: list[Anchor]) -> list[str]:
    """Direct anchors → confirmed findings through the store's dedup, no model: osv with an import count,
    gitleaks/semgrep as they are. Artifact `direct_findings` lists the ids (card 42)."""
    ids = []
    for a in direct:
        pkg = (a.snippet.split() or [""])[0]
        n = imported_by(Path(target), pkg) if a.tool == "osv" and pkg and target else None
        ids.append(store.report(direct_finding(a, n)).id)
    store.put_artifact("direct_findings", {"ids": ids})
    if direct:
        log.info("direct findings: %d scanner results reported without the model (%s)", len(direct),
                 ", ".join(f"{t} {sum(a.tool == t for a in direct)}" for t in dict.fromkeys(a.tool for a in direct)))
    return ids


def direct_findings_node(store: RunStore, target: str) -> FunctionNode:
    """On a static edge after build_skeleton: the store's anchors → DirectResult {remaining, reported} plus the
    skeleton fields passed through (target, entry_points) so the Architect's payload needs no side channel.
    Called dynamically with a list of anchor dicts (tests), it classifies that list instead."""
    def direct_findings(node_input) -> dict:
        given = node_input if isinstance(node_input, list) else None
        anchors = [Anchor.model_validate(a) for a in given] if given is not None else store.anchors()
        direct, rest = split_direct(anchors)
        out = {"remaining": [a.model_dump() for a in rest], "reported": report_direct(store, target, direct)}
        if isinstance(node_input, dict):
            out.update({k: node_input[k] for k in ("target", "entry_points") if k in node_input})
        return out
    return FunctionNode(func=direct_findings, name="direct_findings", rerun_on_resume=True)
