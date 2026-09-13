"""ground: rewrite the three modelling artifacts in place — ungrounded entities / rules / threats dropped, fabricated
WSTG ids corrected (reconcile.ground_artifacts)."""

from __future__ import annotations

import logging
from collections.abc import Callable

from google.adk.workflow import FunctionNode

from scanner.app.graph.reconcile import KNOWN_WSTG, ground_artifacts
from scanner.core import ThreatModel
from scanner.core.ports import RunStore

log = logging.getLogger("scanner.graph.ground")
STAGES = ("architecture_model", "domain_map", "threat_model")


def ground_node(store: RunStore, has_symbol: Callable[[str], bool], locate: Callable[[str], tuple[str, int] | None] | None) -> FunctionNode:
    def ground(node_input) -> dict:
        def grounded(symbol: str) -> bool:
            return has_symbol(symbol) or bool(locate and locate(symbol))

        am_g, dm_g, tm_g, notes = ground_artifacts(*(store.artifact(s) for s in STAGES), grounded, KNOWN_WSTG)
        for st, art in zip(STAGES, (am_g, dm_g, tm_g), strict=True):
            if art is not None:
                store.put_artifact(st, art)
        for n in notes:
            store.add_note(n)
        if notes:
            log.info("grounding: %d items dropped or corrected", len(notes))
        if tm_g:
            try:
                tm = ThreatModel.model_validate(tm_g)
                log.info("threat model: %d threats, intent=%s", len(tm.threats), tm.intent)
            except ValueError as e:
                log.warning("threat_model: invalid: %s", e)
        return {"dropped": len(notes)}
    return FunctionNode(func=ground, name="ground")
