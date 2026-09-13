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

AGENTS: dict[str, AgentSpec] = {s.name: s for s in (model.SPEC, verify.SPEC, critic.SPEC, knowledge.SPEC, domain.SPEC)}
ROSTER: tuple[str, ...] = tuple(AGENTS)
CONSULTANTS = ("knowledge", "domain")  # agents other agents call as sub-agents (AgentTool), never on a graph edge


def _cwes(*nums: int) -> frozenset[str]:
    return frozenset(f"CWE-{n}" for n in nums)


TAINT_CWES = _cwes(89, 78, 77, 88, 22, 79, 80, 918, 94, 95, 1336, 943, 611, 502, 601)
AUTHZ_CWES = _cwes(284, 285, 639, 862, 863, 840, 352, 287, 347, 915, 306, 307, 384, 613)
SECRETS_CWES = _cwes(798, 312, 321)
CONFIG_CWES = _cwes(614, 1004, 942, 16, 209, 532, 778, 327, 328, 338, 295, 319, 1357)

# class → (CWEs, kinds); most specific first: CWE, then kind, then no section
CLASSES = (
    ("taint", TAINT_CWES, frozenset({"entry", "sink"})),
    ("authz", AUTHZ_CWES, frozenset({"authz"})),
    ("dependency", frozenset(), frozenset({"dependency"})),
    ("secrets", SECRETS_CWES, frozenset({"secret"})),
    ("config", CONFIG_CWES, frozenset()),
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
