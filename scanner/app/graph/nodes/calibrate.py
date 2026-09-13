"""calibrate: deterministic severity / exposure calibration → annotation `calibration` on every finding."""

from __future__ import annotations

from google.adk.workflow import FunctionNode

from scanner.app.graph import planning
from scanner.core.ports import RunStore


def calibrate_node(store: RunStore, knowledge_cfg) -> FunctionNode:
    def calibrate(node_input) -> dict:
        intent = (store.artifact("threat_model") or {}).get("intent", "production")
        cal = planning.calibrate_all(store.findings(), intent, store.artifact("architecture_model"), knowledge_cfg)
        for fid, c in cal.items():
            store.annotate(fid, calibration=c)
        return {"calibrated": len(cal)}
    return FunctionNode(func=calibrate, name="calibrate")
