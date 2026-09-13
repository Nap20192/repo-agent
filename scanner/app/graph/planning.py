"""Pure planning helpers of the graph: near-duplicate merging and the deterministic calibration of every finding."""

from __future__ import annotations

import difflib
import logging

from scanner import core
from scanner.adapter.knowledge import KnowledgeConfig, enrichment_for
from scanner.adapter.store import NEAR_LINES
from scanner.core import Finding, calibrate, exposure_for

log = logging.getLogger("scanner.graph.planning")
TITLE_SIMILARITY = 0.6  # dedupe: SequenceMatcher ratio at/above which two near, same-class findings are one bug


def dedupe(findings: list[Finding]) -> list[tuple[str, str]]:
    """(keeper_id, duplicate_id) pairs among the model's confirmed findings: same file and CWE, lines within
    NEAR_LINES, similar titles. The store already collapses same-anchor / same-coordinate writes; this catches
    the same bug reported from two anchors. Keeper = higher confidence, then the earlier id. ponytail: O(n²)
    over confirmed llm findings — dozens, not thousands."""
    fs = [f for f in findings if f.status == core.CONFIRMED and f.source != "direct"]
    pairs, taken = [], set()
    for i, a in enumerate(fs):
        if a.id in taken:
            continue
        for b in fs[i + 1:]:
            if b.id in taken or (a.file, a.cwe) != (b.file, b.cwe) or abs(a.line - b.line) > NEAR_LINES:
                continue
            if difflib.SequenceMatcher(None, a.title.lower(), b.title.lower()).ratio() < TITLE_SIMILARITY:
                continue
            keeper, dup = (a, b) if a.confidence >= b.confidence else (b, a)
            pairs.append((keeper.id, dup.id))
            taken.add(dup.id)
    return pairs



def calibrate_all(findings: list[Finding], intent: str, am: dict | None, knowledge_cfg: KnowledgeConfig | None) -> dict[str, dict]:
    """finding id → report-only calibration, exactly as Store._calibrate computes it at export time."""
    out = {}
    for f in findings:
        exp, rules = exposure_for(f, am)
        knowledge = enrichment_for(f.anchor_id, knowledge_cfg) if knowledge_cfg is not None else {}
        out[f.id] = calibrate(f, intent, exposure=exp, knowledge=knowledge, extra_rules=rules)
    return out
