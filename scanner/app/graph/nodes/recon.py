"""recon: Shannon pre-recon deliverables without a model — sinks by class, guards, config files (adapter/recon)."""

from __future__ import annotations

import logging
from collections.abc import Callable

from google.adk.workflow import FunctionNode

from scanner.core.ports import RunStore
from scanner.core.workflow import ReconMap

log = logging.getLogger("scanner.graph.recon")


def recon_node(store: RunStore, recon_fn: Callable[[], dict] | None) -> FunctionNode:
    def recon(node_input) -> dict:
        """Shannon pre-recon deliverables without a model: sinks by class, guards, config files (adapter/recon)."""
        if (cached := store.artifact("recon")) is not None:
            return cached
        rec = {"sources": [], "sinks": {}, "auth": [], "config_files": []}
        if recon_fn is not None:
            try:
                rec = ReconMap.model_validate(recon_fn()).model_dump()  # JSON-native: the artifact store dumps it
            except Exception as e:  # noqa: BLE001 — recon is an inventory; an error is an empty inventory
                log.warning("recon failed: %s", e)
                store.add_note(f"recon failed: {e}")
        store.put_artifact("recon", rec)
        return rec
    return FunctionNode(func=recon, name="recon")
