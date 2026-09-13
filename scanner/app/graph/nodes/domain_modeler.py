"""domain_modeler: the DomainMap stage — ArchitectureModel + the deterministic domain skeleton → business rules."""

from __future__ import annotations

from pathlib import Path

from scanner.app.graph.stage import stage_node
from scanner.core import ArchitectureModel
from scanner.core.ports import RunStore


def domain_modeler_node(store: RunStore, agent, target: str, index, stage_timeout: float, timings: dict[str, float]):
    def domain_payload(joined: dict) -> dict:
        am = (joined or {}).get("architect") or ArchitectureModel().model_dump()
        from scanner.adapter.domain import extract  # adapter stays importable without the graph

        skeleton = extract(Path(target), index).model_dump() if Path(target).is_dir() else {}
        return {"architecture_model": am, "skeleton": skeleton, "recon": (joined or {}).get("recon") or {}}
    return stage_node(store, agent, "domain_modeler", "domain_map", domain_payload, stage_timeout, timings)
