"""threat_modeler: the ThreatModel stage — ArchitectureModel + DomainMap (+ recon auth) → grounded threats and intent."""

from __future__ import annotations

from scanner.app.graph.stage import stage_node
from scanner.core import ArchitectureModel
from scanner.core.ports import RunStore


def threat_modeler_node(store: RunStore, agent, stage_timeout: float, timings: dict[str, float]):
    def threat_payload(_dm) -> dict:
        am = store.artifact("architecture_model") or ArchitectureModel().model_dump()
        rec = store.artifact("recon") or {}
        return {"architecture_model": am, "domain_map": store.artifact("domain_map") or {}, "auth": rec.get("auth", [])}
    return stage_node(store, agent, "threat_modeler", "threat_model", threat_payload, stage_timeout, timings)
