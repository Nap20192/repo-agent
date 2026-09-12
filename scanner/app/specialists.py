"""Specialist roster + deterministic router (docs/plans/specialists.md).

One LlmAgent per specialist, built once per run; the router picks one per hypothesis/finding by CWE, then kind,
then the generic fallback (the plain Verifier/Critic). Language flavour is an instruction suffix by file suffix."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from google.adk.agents import LlmAgent

from scanner.adapter import static, tools
from scanner.app.callbacks import (
    budget_callback,
    log_tools_callback,
    tool_window_callback,
)
from scanner.app.instructions import (
    ARCHITECT_OVERLAYS,
    CRITIC_CORE,
    INVESTIGATOR_CORE,
    LANG_OVERLAYS,
    OPERATING_PRINCIPLES,
    SPECIALIST_SECTIONS,
)
from scanner.core import Finding, Hypothesis
from scanner.core.ports import Index


@dataclass(frozen=True)
class Specialist:
    name: str
    role: str  # "investigate" | "critique"
    kinds: frozenset[str]
    cwes: frozenset[str]
    tool_names: frozenset[str]
    skills: tuple[str, ...]
    max_calls: int
    description: str = ""

    @property
    def instruction(self) -> str:
        core = INVESTIGATOR_CORE if self.role == "investigate" else CRITIC_CORE
        return OPERATING_PRINCIPLES + core + "\n" + SPECIALIST_SECTIONS[self.name] + "\n"

    def tools_fn(self, run, target: Path, index: Index | None) -> list[Callable]:
        base = tools.verifier_tools(run, target, index=index) if self.role == "investigate" else tools.critic_tools(run, target, index=index)
        return tools.subset(base, set(self.tool_names))


def _cwes(*nums: int) -> frozenset[str]:
    return frozenset(f"CWE-{n}" for n in nums)


TAINT_CWES = _cwes(89, 78, 77, 88, 22, 79, 80, 918, 94, 95, 1336, 943, 611, 502, 601)
AUTHZ_CWES = _cwes(284, 285, 639, 862, 863, 840, 352, 287, 347, 915, 306, 307, 384, 613)
SECRETS_CWES = _cwes(798, 312, 321)
CONFIG_CWES = _cwes(614, 1004, 942, 16, 209, 532, 778, 327, 328, 338, 295, 319, 1357)

REGISTRY: tuple[Specialist, ...] = (
    Specialist("taint", "investigate", frozenset({"entry", "sink"}), TAINT_CWES, frozenset(tools.TAINT_TOOLS),
               ("verifier-proof", "source-aware-discovery"), 30, "source→sink tracing for injection-class flaws"),
    Specialist("authz", "investigate", frozenset({"authz"}), AUTHZ_CWES, frozenset(tools.AUTHZ_TOOLS),
               ("verifier-proof", "authz-idor", "business-logic"), 30,
               "authorization, IDOR, authentication and session (A01, A07)"),
    Specialist("dependency", "investigate", frozenset({"dependency"}), frozenset(), frozenset(tools.DEPENDENCY_TOOLS),
               ("dependency-advisory",), 15, "vulnerable dependencies: advisory + reachability (A06)"),
    Specialist("secrets", "investigate", frozenset({"secret"}), SECRETS_CWES, frozenset(tools.SECRETS_TOOLS),
               ("information-disclosure",), 10, "hardcoded / leaked credentials"),
    Specialist("config", "investigate", frozenset(), CONFIG_CWES, frozenset(tools.CONFIG_TOOLS),
               ("severity-calibration",), 12,
               "security misconfiguration, logging, crypto hygiene (A02, A05, A09)"),
    Specialist("taint_critic", "critique", frozenset({"entry", "sink"}), TAINT_CWES, frozenset(tools.TAINT_CRITIC_TOOLS),
               ("counterevidence", "severity-calibration"), 20, "disproves taint findings: dominance, reachability"),
    Specialist("authz_critic", "critique", frozenset({"authz"}), AUTHZ_CWES, frozenset(tools.AUTHZ_CRITIC_TOOLS),
               ("counterevidence", "severity-calibration"), 20, "disproves authz findings: intended business rules"),
    Specialist("dependency_critic", "critique", frozenset({"dependency"}), frozenset(), frozenset(tools.DEPENDENCY_CRITIC_TOOLS),
               ("counterevidence", "severity-calibration"), 12, "disproves dependency findings: patched, uncalled"),
)
BY_NAME = {s.name: s for s in REGISTRY}

# Generic fallbacks: the router returns these to mean "use the plain Verifier / Critic the graph already has".
FALLBACK = {
    "investigate": Specialist("verifier", "investigate", frozenset(), frozenset(), frozenset(), (), 30, "generic Investigator"),
    "critique": Specialist("critic", "critique", frozenset(), frozenset(), frozenset(), (), 20, "generic Critic"),
}

# OWASP Top 10 (2021) → who covers it; A04 (insecure design) is the Domain/ThreatModeler path, not an investigator.
TOP10_COVERAGE = {
    "A01": "authz", "A02": "config+secrets", "A03": "taint", "A04": "domain+threat_modeler", "A05": "config",
    "A06": "dependency", "A07": "authz", "A08": "taint(502)+dependency", "A09": "config", "A10": "taint",
}

_OVERLAY_OF = {"go": "go", "javascript": "node", "typescript": "node", "python": "python"}


def lang_of(files: list[str]) -> str:
    """Overlay key for the first file whose suffix we know: go | node | python; "" otherwise."""
    for f in files:
        lang = static.LANG_EXT.get(Path(f).suffix, "")
        if lang in _OVERLAY_OF:
            return _OVERLAY_OF[lang]
    return ""


def route(item: Hypothesis | Finding, lang: str = "", role: str = "investigate", kind: str = "") -> tuple[Specialist, str]:
    """Most specific first: CWE → kind → generic fallback. Returns (specialist, language overlay suffix)."""
    lang = _OVERLAY_OF.get(lang, lang)  # the graph passes static.LANG_EXT names (javascript/typescript → node)
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


ROUTER = route_name  # deprecated alias, remove after the next release


def max_calls(spec: Specialist) -> int:
    v = os.environ.get(f"SPECIALIST_{spec.name.upper()}_MAX_CALLS", "")
    return int(v) if v.isdigit() and int(v) > 0 else spec.max_calls


def architect_overlay(langs: set[str]) -> str:
    keys = sorted({_OVERLAY_OF[lang] for lang in langs if lang in _OVERLAY_OF})
    return "\n".join(ARCHITECT_OVERLAYS[k] for k in keys)


def build(model, run, target: Path, index: Index | None) -> dict[str, LlmAgent]:
    """One LlmAgent per REGISTRY entry, built once per run (clones per activation happen in the graph)."""
    target = Path(target).resolve()
    out: dict[str, Any] = {}
    for spec in REGISTRY:
        out[spec.name] = LlmAgent(
            name=spec.name, description=spec.description, model=model, instruction=spec.instruction,
            tools=spec.tools_fn(run, target, index), include_contents="none",
            before_model_callback=[budget_callback(max_calls(spec), per_branch=True), tool_window_callback()],
            before_tool_callback=log_tools_callback,
        )
    return out
