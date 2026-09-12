"""Shared graph helpers: JSON parsing, the specialist pick, the hypothesis gate and the verdict-from-store
rule. The graph itself is the ADK Workflow in pipeline_v3 (nodes in graph_nodes)."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable

from google.adk.events import Event

from scanner import core
from scanner.adapter import fs
from scanner.core import Dossier, Finding, Hypothesis
from scanner.core.ports import Router, RunStore

log = logging.getLogger("scanner.graph")


_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)

def parse_json(text: str) -> dict | None:
    """Best-effort: strip fences, take first '{' … last '}'."""
    if not text:
        return None
    text = _FENCE.sub("", text.strip())
    i, j = text.find("{"), text.rfind("}")
    if i < 0 or j <= i:
        return None
    try:
        v = json.loads(text[i : j + 1])
    except json.JSONDecodeError:
        return None
    return v if isinstance(v, dict) else None

def text_of(ev: Event) -> str:
    if not ev.content or not ev.content.parts or ev.get_function_calls():
        return ""
    return "".join(p.text or "" for p in ev.content.parts)

_RANK = {core.CONFIRMED: 2, core.REJECTED: 1}

def pick_agent(item, role: str, specialists: dict, router: Router | None, fallback):
    """(agent, specialist name or "", instruction suffix): the router's choice for `item` (a Hypothesis for
    role "investigate", a Finding for "critique") among `specialists`, else the generic `fallback`."""
    if router is None:
        return fallback, "", ""
    files = list(getattr(item, "reads", None) or []) or [getattr(item, "file", "") or ""]
    lang = next((fs.LANG_EXT[s] for f in files if (s := "." + f.rsplit(".", 1)[-1]) in fs.LANG_EXT), "")
    name, suffix = router(item, lang, role)
    agent = specialists.get(name) if name else None
    if agent is None:
        if name:
            log.warning("router: unknown specialist %r for %s — using the generic %s", name, role, getattr(fallback, "name", "?"))
        return fallback, "", ""
    return agent, name, suffix


def gate_hypotheses(hs: list[Hypothesis], rnd: int, store: RunStore, has_anchor: Callable[[str], bool],
                    has_symbol: Callable[[str], bool], max_hyps: int) -> list[Hypothesis]:
    """Belt over the dispatch tool: drop ungrounded, cap at max_hyps, assign ids h<round>-<n>. Used by the Workflow
    `investigate` node."""
    out = []
    for n, h in enumerate(hs, 1):
        h.id = h.id or f"h{rnd}-{n}"
        if reason := core.ground_hypothesis(h, has_anchor, has_symbol):
            log.warning("gate: dropped ungrounded hypothesis %s: %s", h.id, reason)
            store.add_note(f"dropped ungrounded hypothesis {h.id}: {reason}", h.id)
            continue
        out.append(h)
        if len(out) >= max_hyps:
            break
    return out


def dossier_from_store(findings: list[Finding], h: Hypothesis) -> Dossier:
    """Verdict from facts: findings bound to the hypothesis (id, else anchor without foreign id)."""
    d = Dossier(hypothesis_id=h.id)
    best: Finding | None = None
    for f in findings:
        mine = (h.id and f.hypothesis_id == h.id) or (
            h.anchor_id and not f.hypothesis_id and f.anchor_id == h.anchor_id
        )
        if mine and (best is None or _RANK.get(f.status, 0) > _RANK.get(best.status, 0)):
            best = f
    if best:
        d.verdict, d.finding_id, d.evidence = best.status, best.id, list(best.evidence)
    return d
