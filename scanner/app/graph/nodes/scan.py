"""scan: START → the static pre-pass as a graph node (scanners → anchors → store)."""

from __future__ import annotations

import logging
from collections.abc import Callable

from google.adk.workflow import FunctionNode

from scanner.adapter.static import ScanResult
from scanner.core.ports import RunStore

log = logging.getLogger("scanner.graph.scan")


def scan_node(store: RunStore, scan_fn: Callable[[], ScanResult] | None) -> FunctionNode:
    """START → the pre-pass as a graph node: run the static scanners, save their anchors, record what ran and
    what failed in the `scan` artifact. Resume: an existing artifact means the anchors are already in the store.
    `scan_fn` None (tests) means the anchors are already in the store."""
    if scan_fn is None:
        return FunctionNode(func=lambda node_input: {"anchors": len(store.anchors())}, name="scan")

    def scan(node_input) -> dict:  # node_input: the user turn that started the run, unused
        if (cached := store.artifact("scan")) is not None:
            return {k: cached[k] for k in ("anchors", "ran", "failed")}
        res = scan_fn()
        for tool, why in res.failed.items():
            log.warning("static: %s failed: %s", tool, why)
        store.save_anchors(res.anchors)
        by_tool = {t: n for t in res.ran if (n := sum(a.tool == t for a in res.anchors))}
        log.info("pre-pass: %d anchors — %s%s", len(res.anchors), ", ".join(f"{t} {n}" for t, n in by_tool.items()),
                 f"; failed: {', '.join(res.failed)}" if res.failed else "")
        store.put_artifact("scan", {"anchors": len(res.anchors), "by_tool": by_tool, "ran": res.ran, "failed": res.failed})
        return {"anchors": len(res.anchors), "ran": res.ran, "failed": res.failed}
    return FunctionNode(func=scan, name="scan")
