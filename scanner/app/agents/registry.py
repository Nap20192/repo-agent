"""Every agent of the project, by name, and the deterministic router (docs/plans/specialists.md).

AGENTS is an explicit list — adding an agent is one folder plus one line here. The router picks a specialist per
hypothesis/finding by CWE, then kind, then the generic fallback (verify / critic); the language flavour is an
instruction suffix by file suffix."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from google.adk.agents import LlmAgent

from scanner.adapter.fs import LANG_EXT
from scanner.adapter.tools import ToolContext
from scanner.app.agents import (
    architect,
    authz,
    authz_critic,
    config,
    confirm,
    critic,
    dependency,
    dependency_critic,
    domain_modeler,
    knowledge,
    review,
    secrets_agent,
    taint,
    taint_critic,
    threat_modeler,
    triage,
    triage_batch,
    verify,
    viability,
)
from scanner.app.agents.base import AgentSpec, build, max_calls
from scanner.app.agents.shared import ARCHITECT_OVERLAYS, LANG_OVERLAYS
from scanner.core import Finding, Hypothesis
from scanner.core.settings import Settings

AGENTS: dict[str, AgentSpec] = {s.name: s for s in (
    architect.SPEC, domain_modeler.SPEC, threat_modeler.SPEC, triage.SPEC, triage_batch.SPEC, verify.SPEC, critic.SPEC,
    review.SPEC, viability.SPEC, confirm.SPEC, knowledge.SPEC,
    taint.SPEC, authz.SPEC, dependency.SPEC, secrets_agent.SPEC, config.SPEC, taint_critic.SPEC, authz_critic.SPEC, dependency_critic.SPEC,
)}
ROSTER: tuple[str, ...] = tuple(AGENTS)

# The specialists: routed by CWE / kind. The generic fallbacks the router returns for everything else.
REGISTRY: tuple[AgentSpec, ...] = tuple(s for s in AGENTS.values() if s.role and (s.kinds or s.cwes))
BY_NAME = {s.name: s for s in REGISTRY}
FALLBACK = {"investigate": AGENTS["verify"], "critique": AGENTS["critic"]}
KNOWLEDGE_USERS = frozenset(s.name for s in REGISTRY if s.consults_knowledge)

# OWASP Top 10 (2021) → who covers it; A04 (insecure design) is the Domain/ThreatModeler path, not an investigator.
TOP10_COVERAGE = {
    "A01": "authz", "A02": "config+secrets", "A03": "taint", "A04": "domain+threat_modeler", "A05": "config",
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


def route(item: Hypothesis | Finding, lang: str = "", role: str = "investigate", kind: str = "") -> tuple[AgentSpec, str]:
    """Most specific first: CWE → kind → generic fallback. Returns (spec, language overlay suffix)."""
    lang = _OVERLAY_OF.get(lang, lang)  # the graph passes fs.LANG_EXT names (javascript/typescript → node)
    kind = kind or getattr(item, "kind", "")
    cwe = (item.cwe or "").upper()
    candidates = [s for s in REGISTRY if s.role == role]
    chosen = next((s for s in candidates if cwe and cwe in s.cwes), None) \
        or next((s for s in candidates if kind and kind in s.kinds), None) \
        or FALLBACK[role]
    return chosen, LANG_OVERLAYS.get(lang, "")


def route_name(item: Hypothesis | Finding, lang: str = "", role: str = "investigate", kind: str = "") -> tuple[str, str]:
    """Graph-facing router: (specialist name, overlay suffix); "" as the name means the generic fallback."""
    spec, suffix = route(item, lang, role, kind)
    return (spec.name if spec.name in BY_NAME else "", suffix)


def architect_overlay(langs: set[str]) -> str:
    keys = sorted({_OVERLAY_OF[lang] for lang in langs if lang in _OVERLAY_OF})
    return "\n".join(ARCHITECT_OVERLAYS[k] for k in keys)


def build_specialists(model, run, target, index=None, knowledge_factory: Callable[[], Any] | None = None,
                      settings: Settings | None = None) -> dict[str, LlmAgent]:
    """One LlmAgent per REGISTRY entry, built once per run (clones per activation happen in the graph).
    `knowledge_factory()` returns a fresh Knowledge AgentTool for each consults_knowledge specialist (own budget each)."""
    ctx = ToolContext(target, run, index=index, settings=settings or Settings())
    return {
        spec.name: build(spec, model, ctx, settings,
                         extra_tools=[knowledge_factory()] if knowledge_factory is not None and spec.consults_knowledge else None)
        for spec in REGISTRY
    }


__all__ = [
    "AGENTS",
    "BY_NAME",
    "FALLBACK",
    "KNOWLEDGE_USERS",
    "REGISTRY",
    "ROSTER",
    "TOP10_COVERAGE",
    "AgentSpec",
    "architect_overlay",
    "build",
    "build_specialists",
    "lang_of",
    "max_calls",
    "route",
    "route_name",
]
