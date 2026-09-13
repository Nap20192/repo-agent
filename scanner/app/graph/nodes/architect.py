"""architect: the ArchitectureModel stage (the Architect agent as a child of a dynamic node)."""

from __future__ import annotations

from scanner.app.graph.nodes.build_skeleton import anchor_view
from scanner.app.graph.stage import stage_node
from scanner.core.ports import RunStore
from scanner.core.workflow import DirectResult, ScanSkeleton


def architect_payload(direct: dict) -> dict:
    d = DirectResult.model_validate(direct)  # direct_findings passes the skeleton through (target, entry_points)
    sk = ScanSkeleton.model_validate(direct)
    return {"target": sk.target, "entry_points": [c.model_dump() for c in sk.entry_points], "anchors": anchor_view(d.remaining)}


def architect_node(store: RunStore, agent, stage_timeout: float, timings: dict[str, float]):
    return stage_node(store, agent, "architect", "architecture_model", architect_payload, stage_timeout, timings)
