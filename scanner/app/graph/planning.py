"""Pure planning helpers of the graph: near-duplicate merging of the model's confirmed findings."""

from __future__ import annotations

import difflib

from scanner import core
from scanner.adapter.store import NEAR_LINES
from scanner.core import Finding

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
