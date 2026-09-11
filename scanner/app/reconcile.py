"""Reconciler (v2): two candidate streams — scanner Anchors and modeled Threats — plus Verifier
new_hypotheses, merged into one prioritized queue of Hypotheses without duplicates. Pure functions."""

from __future__ import annotations

import math
import random
from collections.abc import Callable

from scanner import core
from scanner.core import Anchor, Candidate, Hypothesis, Threat, new_anchor_id

_KIND_CONSULT = {"dependency": "knowledge", "authz": "domain"}


def anchor_kind(a: Anchor) -> str:
    if a.tool == "osv" or a.rule_id.upper().startswith(("CVE-", "GHSA-")):
        return "dependency"
    if a.cwe == "CWE-798":
        return "secret"
    if a.cwe in core.AUTHZ_CWES:
        return "authz"
    return "sink"


def key(h: Hypothesis) -> str:
    """Identity of a queue item: the anchor, else symbol+cwe."""
    return h.anchor_id or f"{h.symbol}|{h.cwe}"


def from_anchors(anchors: list[Anchor]) -> list[Hypothesis]:
    """Every anchor is a task: kind by class, consult by kind, claim from the scanner message."""
    out = []
    for a in anchors:
        kind = anchor_kind(a)
        out.append(Hypothesis(
            kind=kind, cwe=a.cwe, anchor_id=a.id, consult=_KIND_CONSULT.get(kind, ""),
            claim=f"{a.message or a.rule_id} at {a.file}:{a.line} is exploitable" + (f" ({a.cwe})" if a.cwe else ""),
            reads=[a.file], priority=core.SEVERITY_RANK.get(a.severity, 0) * 20,
        ))
    return out


def from_threats(
    threats: list[Threat], anchors: list[Anchor], locate: Callable[[str], tuple[str, int] | None] | None = None
) -> tuple[list[Hypothesis], list[Anchor]]:
    """Threats → hypotheses, plus the synthetic anchors minted for them.

    A threat matching a scanner anchor by (file, cwe) is grounded on it (claim from the threat, +10 priority).
    Otherwise, if `locate` finds the definition of its symbol, a synthetic anchor (tool "threatmodel",
    file:line of the definition) is minted so the single anchor-only report_finding gate still applies.
    A threat with neither stays symbol-grounded and the dispatch gate decides its fate."""
    by_line = {(a.file, a.line, a.cwe): a for a in anchors if a.cwe}
    by_loc: dict[tuple[str, str], list[Anchor]] = {}
    for a in anchors:
        if a.cwe:
            by_loc.setdefault((a.file, a.cwe), []).append(a)
    hyps: list[Hypothesis] = []
    minted: list[Anchor] = []
    for t in threats:
        # exact (file, line, cwe) first; (file, cwe) only when unambiguous — never guess between two sinks
        a = by_line.get((t.file, t.line, t.cwe))
        if a is None and t.line == 0 and len(by_loc.get((t.file, t.cwe), [])) == 1:
            a = by_loc[(t.file, t.cwe)][0]
        if a is None and t.symbol and locate and (loc := locate(t.symbol)):
            sev = "high" if t.priority >= 70 else "medium" if t.priority >= 40 else "low"
            a = Anchor(id=new_anchor_id("threatmodel", t.wstg_id or t.cwe, loc[0], loc[1]), tool="threatmodel",
                       rule_id=t.wstg_id or "threat", cwe=t.cwe, severity=sev, file=loc[0], line=loc[1],
                       message=t.claim, snippet="")
            minted.append(a)
        kind = anchor_kind(a) if a else ("authz" if t.cwe in core.AUTHZ_CWES else "sink")
        hyps.append(Hypothesis(
            kind=kind, cwe=t.cwe, claim=t.claim, anchor_id=a.id if a else "", symbol="" if a else t.symbol,
            consult=_KIND_CONSULT.get(kind, ""), reads=t.reads or ([a.file] if a else [t.file] if t.file else []),
            priority=t.priority + (10 if a and a.tool != "threatmodel" else 0),
        ))
    return hyps, minted


def reconcile(new: list[Hypothesis], queue: list[Hypothesis], done: set[str]) -> list[Hypothesis]:
    """Merge `new` into `queue`: drop items already done or already queued (same key; the higher priority
    wins), sort by priority desc (stable). Ungrounded items are kept — the gate drops them when batched."""
    merged: dict[str, Hypothesis] = {key(h): h for h in queue if key(h) not in done}
    for h in new:
        k = key(h)
        if k in done or k == "|":
            continue
        if k not in merged or h.priority > merged[k].priority:
            merged[k] = h
    return sorted(merged.values(), key=lambda h: -h.priority)


def coverage(entry_points: list[Candidate], queue: list[Hypothesis], done: set[str]) -> tuple[list[Hypothesis], list[Anchor]]:
    """Plan-stage rule (Shannon): an entry point no item examines is never examined by anything downstream.
    Every entry point not covered by a queued/done item (same symbol, or its file in `reads`) becomes a
    low-priority baseline "entry" hypothesis: on its handler symbol, or — for inline handlers and plain
    PHP pages that have no symbol — on a synthetic anchor (tool "entrypoint") minted at file:line so the
    anchor-only gate still applies. Returns (hypotheses, minted anchors)."""
    covered_syms = {h.symbol for h in queue if h.symbol} | {k.split("|", 1)[0] for k in done if "|" in k}
    covered_files = {f for h in queue for f in h.reads}
    hyps: list[Hypothesis] = []
    minted: list[Anchor] = []
    for c in entry_points:
        if (c.symbol and (c.symbol in covered_syms or c.file in covered_files)) or (not c.symbol and not c.file):
            continue
        where = c.symbol or " ".join(c.route) or c.file
        claim = f"Baseline: untrusted input entering {where} ({c.file}:{c.line}) reaches a dangerous sink unsanitized"
        h = Hypothesis(kind="entry", symbol=c.symbol, reads=[c.file] if c.file else [], priority=10, claim=claim)
        if not c.symbol:
            a = Anchor(id=new_anchor_id("entrypoint", where, c.file, c.line), tool="entrypoint", rule_id=where,
                       severity="low", file=c.file, line=c.line, message=claim)
            minted.append(a)
            h.anchor_id = a.id
        hyps.append(h)
    return hyps, minted


def adversarial_sweep(candidates: list[Candidate], fraction: float = 0.25, seed: int = 0) -> list[Hypothesis]:
    """Plan-stage rule (Shannon): a deterministic fraction of otherwise-uncovered candidates gets an unconstrained
    sweep — ignore assumed safety, treat every input as untrusted. Same seed → same pick."""
    pool = [c for c in candidates if c.symbol]
    if not pool or fraction <= 0:
        return []
    picked = random.Random(seed).sample(pool, min(len(pool), math.ceil(len(pool) * fraction)))
    return [Hypothesis(
        kind="entry", symbol=c.symbol, reads=[c.file] if c.file else [], priority=5,
        claim=f"Adversarial sweep of {c.symbol} ({c.file}:{c.line}): ignore assumed safety and trust boundaries, "
              "treat every input as untrusted and malformed, look for any sink it can reach",
    ) for c in picked]
