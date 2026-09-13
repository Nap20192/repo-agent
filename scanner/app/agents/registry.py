"""Every agent of the project, by name, and the class overlay that replaced the specialist agents (card 51).

AGENTS is an explicit list — adding an agent is one folder plus one line here. `overlay(item, lang, role)` returns the
instruction suffix an activation gets: the class section (taint / authz / dependency / secrets / config, picked by CWE
then kind) plus the language overlay — the knowledge the specialist agents carried, without an agent each."""

from __future__ import annotations

from pathlib import Path

from scanner.adapter.fs import LANG_EXT
from scanner.app.agents import critic, domain, knowledge, model, verify
from scanner.app.agents.base import AgentSpec, build, max_calls
from scanner.app.agents.shared import ARCHITECT_OVERLAYS, LANG_OVERLAYS, SPECIALIST_SECTIONS
from scanner.core import Finding, Hypothesis
from scanner.core.types import CWE_CLASSES

AGENTS: dict[str, AgentSpec] = {s.name: s for s in (model.SPEC, verify.SPEC, critic.SPEC, knowledge.SPEC, domain.SPEC)}
ROSTER: tuple[str, ...] = tuple(AGENTS)
CONSULTANTS = ("knowledge", "domain")  # agents other agents call as sub-agents (AgentTool), never on a graph edge


def _class(name: str) -> frozenset[str]:
    return frozenset(c for c, k in CWE_CLASSES.items() if k == name)


# class → (CWEs from the one taxonomy, kinds); most specific first: CWE, then kind, then no section
CLASSES = (
    ("taint", _class("taint"), frozenset({"entry", "sink"})),
    ("authz", _class("authz"), frozenset({"authz"})),
    ("dependency", frozenset(), frozenset({"dependency"})),
    ("secrets", _class("secret"), frozenset({"secret"})),
    ("config", _class("config"), frozenset()),
)
CRITIC_SECTIONS = {"taint": "taint_critic", "authz": "authz_critic", "dependency": "dependency_critic"}

# OWASP Top 10 (2021) → which class section covers it; A04 (insecure design) is the model stage, not an investigator.
TOP10_COVERAGE = {
    "A01": "authz", "A02": "config+secrets", "A03": "taint", "A04": "model", "A05": "config",
    "A06": "dependency", "A07": "authz", "A08": "taint(502)+dependency", "A09": "config", "A10": "taint",
}

_OVERLAY_OF = {"go": "go", "javascript": "node", "typescript": "node", "python": "python"}


def lang_of(files: list[str]) -> str:
    """Overlay key for the first file whose suffix we know: go | node | python; "" otherwise."""
    for f in files:
        lang = LANG_EXT.get(Path(f).suffix, "")
        if lang in _OVERLAY_OF:
            return _OVERLAY_OF[lang]
    return ""


def class_of(item: Hypothesis | Finding, kind: str = "") -> str:
    """The class section for an item: CWE first, then kind; "" when nothing matches (the generic prompt alone)."""
    kind = kind or getattr(item, "kind", "")
    cwe = (item.cwe or "").upper()
    return next((n for n, cwes, _ in CLASSES if cwe and cwe in cwes), None) \
        or next((n for n, _, kinds in CLASSES if kind and kind in kinds), "")


def overlay(item: Hypothesis | Finding, lang: str = "", role: str = "investigate", kind: str = "") -> tuple[str, str]:
    """(class name, instruction suffix) for one activation: the class section for the role + the language overlay."""
    cls = class_of(item, kind)
    section = SPECIALIST_SECTIONS.get(cls if role == "investigate" else CRITIC_SECTIONS.get(cls, ""), "")
    lang_text = LANG_OVERLAYS.get(_OVERLAY_OF.get(lang, lang), "")
    return cls, "\n".join(t for t in (section, lang_text) if t)


def architect_overlay(langs: set[str]) -> str:
    keys = sorted({_OVERLAY_OF[lang] for lang in langs if lang in _OVERLAY_OF})
    return "\n".join(ARCHITECT_OVERLAYS[k] for k in keys)


__all__ = [
    "AGENTS",
    "CLASSES",
    "CONSULTANTS",
    "ROSTER",
    "TOP10_COVERAGE",
    "AgentSpec",
    "architect_overlay",
    "build",
    "class_of",
    "lang_of",
    "max_calls",
    "overlay",
]
