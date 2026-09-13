"""The tool registry: every tool by the name the model sees, in the order the rosters list them. An agent's roster is
a tuple of these names (scanner/app/agents/<name>/tools.py); `make(names, ctx)` builds the closures for one run."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from scanner.adapter.tools.code import grep, read_file, shell
from scanner.adapter.tools.consult import list_skills, load_skill, owasp
from scanner.adapter.tools.context import ToolContext
from scanner.adapter.tools.gates import disprove_finding, report_finding
from scanner.adapter.tools.knowledge import deps_dev, epss, ghsa, kev, nvd_cve, osv_query
from scanner.adapter.tools.lsp import callees, callers, definition, path_to_entry, references, symbols
from scanner.adapter.tools.store import list_anchors

# name → factory(ctx). Order matters: it is the order tools are listed to the model.
TOOLS: dict[str, Callable[[ToolContext], Callable]] = {
    "report_finding": report_finding.make,
    "disprove_finding": disprove_finding.make,
    "read_file": read_file.make,
    "grep": grep.make,
    "shell": shell.make,
    "lsp_symbols": symbols.make,
    "lsp_definition": definition.make,
    "lsp_references": references.make,
    "lsp_callers": callers.make,
    "lsp_callees": callees.make,
    "lsp_path_to_entry": path_to_entry.make,
    "list_anchors": list_anchors.make,
    "consult_owasp": owasp.make,
    "list_skills": list_skills.make,
    "load_skill": load_skill.make,
    # the Knowledge agent's own tools
    "osv_query": osv_query.make,
    "ghsa": ghsa.make,
    "nvd_cve": nvd_cve.make,
    "epss": epss.make,
    "kev": kev.make,
    "deps_dev": deps_dev.make,
}


def make(names: Iterable[str], ctx: ToolContext) -> list[Callable]:
    """Build the named tools for one run, in registry order; an unknown name is a build-time typo."""
    wanted = set(names)
    missing = wanted - set(TOOLS)
    if missing:
        raise KeyError(f"unknown tools: {sorted(missing)}")
    return [TOOLS[n](ctx) for n in TOOLS if n in wanted]


def subset(tools: list[Callable], names: set[str]) -> list[Callable]:
    """Pick already-built tools by function name, keeping the source order; an unknown name is a build-time typo."""
    by = {t.__name__: t for t in tools}
    missing = names - set(by)
    if missing:
        raise KeyError(f"unknown tools: {sorted(missing)}")
    return [t for t in tools if t.__name__ in names]
