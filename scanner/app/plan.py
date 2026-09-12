"""Shannon's plan / fold / route / dedupe / calibrate steps as pure functions (card 45, docs/plans/shannon-graph.md §3).

No ADK here: the graph nodes in graph_nodes.py wrap these. Everything takes and returns plain data or the
core types, so the functions run before and after the node schemas (PlanState, TriageBatch, TriageCoverage,
ExportResult) land in scanner.core.workflow."""

from __future__ import annotations

import difflib
import logging

from scanner import core
from scanner.adapter.knowledge import KnowledgeConfig, enrichment_for
from scanner.adapter.store import NEAR_LINES
from scanner.core import Finding, Hypothesis, calibrate, exposure_for

log = logging.getLogger("scanner.plan")

TITLE_SIMILARITY = 0.6  # dedupe: SequenceMatcher ratio at/above which two near, same-class findings are one bug


# --- plan ----------------------------------------------------------------------------------------------------

def batch_files(files: list[str], size: int) -> list[list[str]]:
    """Stable, deduplicated batches (sorted paths) of the planned target files for the triage sweep."""
    uniq = sorted(set(files))
    size = max(size, 1)
    return [uniq[i:i + size] for i in range(0, len(uniq), size)]


def plan_state(queue: list[Hypothesis], done: set[str], files: list[str], batch_size: int) -> dict:
    """QueueState fields + `batches`: what the plan node emits (PlanState in the schema)."""
    return {"queue": list(queue), "done": sorted(done), "batches": batch_files(files, batch_size)}


# --- fold_triage ---------------------------------------------------------------------------------------------

def _usable(batch_out, planned: set[str], seen: set[str]) -> list[dict]:
    """Shannon `usableClassifications`: assigned file, first occurrence, `flagged` a real bool."""
    cls = batch_out.get("classifications") if isinstance(batch_out, dict) else None
    out = []
    for c in cls if isinstance(cls, list) else []:
        if not isinstance(c, dict) or c.get("file") not in planned or c["file"] in seen or not isinstance(c.get("flagged"), bool):
            continue
        seen.add(c["file"])
        out.append(c)
    return out


def fold_triage(batches_out: list, planned_files: list[str], queue: list[Hypothesis]) -> tuple[list[Hypothesis], list[dict], dict]:
    """Fold the triage sweep back into the queue (the semantics of the per-round `triage_batch`, as a pure step).

    Unflagged file → its entry/file baselines leave the queue as rejected dossiers (coverage stays provable);
    flagged → the baseline's claim gets the reason and `cwe` the first triage class; a file with no usable
    classification is `missing` and its baselines stay (fail open: the audit decides). Coverage per Shannon
    `computeTriageCoverage`: considered/classified/missing, `reduced` when anything is missing."""
    planned = set(planned_files)
    by_file: dict[str, dict] = {}
    seen: set[str] = set()
    for b in batches_out:
        for c in _usable(b, planned, seen):
            by_file[c["file"]] = c
    kept, rejected = [], []
    for h in queue:
        c = by_file.get(h.reads[0]) if h.kind == "entry" and h.reads else None
        if c is None:
            kept.append(h)
            continue
        if c["flagged"]:
            if c.get("why"):
                h.claim += f". Triage: {c['why']}"
            classes = [x for x in c.get("classes") or [] if isinstance(x, str) and x.upper().startswith("CWE-")]
            if classes:
                h.cwe = classes[0]
            kept.append(h)
        else:
            rejected.append({"hypothesis_id": h.id, "verdict": core.REJECTED, "notes": f"triage: {c.get('why', '')}", "specialist": "triage"})
    missing = sorted(planned - set(by_file))
    coverage = {"considered": len(planned), "classified": len(by_file), "missing": missing,
                "flagged": sorted(f for f, c in by_file.items() if c["flagged"]),
                "coverage": "reduced" if missing else "complete"}
    log.info("triage: %d of %d files classified, %d flagged, %d missing", len(by_file), len(planned), len(coverage["flagged"]), len(missing))
    return kept, rejected, coverage


# --- routes (closed decisions on data; Capella workflow.ts) ---------------------------------------------------

def route_plan(queue: list) -> str:
    return "empty" if not queue else "default"


def route_research(findings_llm: int, budget: bool) -> str:
    return "none" if findings_llm == 0 else "budget" if budget else "default"


def route_survivors(confirmed_llm: int) -> str:
    return "none" if confirmed_llm == 0 else "default"


def route_intent(threat_model: dict | None) -> str:
    intent = str((threat_model or {}).get("intent", "production")).lower()
    return "sample" if intent.startswith("sample") else "default"


# --- dedupe --------------------------------------------------------------------------------------------------

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


# --- calibrate -----------------------------------------------------------------------------------------------

def calibrate_all(findings: list[Finding], intent: str, am: dict | None, knowledge_cfg: KnowledgeConfig | None) -> dict[str, dict]:
    """finding id → report-only calibration, exactly as Store._calibrate computes it at export time."""
    out = {}
    for f in findings:
        exp, rules = exposure_for(f, am)
        knowledge = enrichment_for(f.anchor_id, knowledge_cfg) if knowledge_cfg is not None else {}
        out[f.id] = calibrate(f, intent, exposure=exp, knowledge=knowledge, extra_rules=rules)
    return out
