"""Tool sets per role: the three assemblers (Investigator, Critic, Architect) and `subset()` for specialists.

The name sets a specialist may use live next to the roster in scanner/app/specialists.py."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from scanner.adapter import static
from scanner.adapter.dominance import make_check_dominance
from scanner.adapter.owasp import consult_owasp
from scanner.adapter.skills import list_skills, load_skill
from scanner.adapter.tools.code import code_tools
from scanner.adapter.tools.common import (
    common_tools,
    default_index,
    default_reader,
    quotes_in_target,
)
from scanner.adapter.tools.gates import disprove_finding_tool, report_finding_tool
from scanner.adapter.tools.lsp import lsp_tools
from scanner.core.ports import Index


def verifier_tools(run, target: Path, reader: Callable[[str, int], str] | None = None, index: Index | None = None) -> list[Callable]:
    """Investigator: report_finding gate, code reading, shell, symbol navigation, consultants, skills."""
    target = Path(target).resolve()
    report = report_finding_tool(run, reader or default_reader(target))
    return [report, *code_tools(target, run), *lsp_tools(target, index or default_index(target)), *common_tools(run), list_skills, load_skill]


def critic_tools(run, target: Path, in_target: Callable[[list[str]], bool] | None = None, index: Index | None = None) -> list[Callable]:
    """Critic: disprove_finding gate, dominance check, code reading, symbol navigation, consultants, skills."""
    target = Path(target).resolve()
    idx = index or default_index(target)
    disprove = disprove_finding_tool(run, in_target or (lambda qs: quotes_in_target(target, qs)))
    return [disprove, make_check_dominance(target, idx), *code_tools(target, run), *lsp_tools(target, idx), *common_tools(run), list_skills, load_skill]


def architect_tools(run, target: Path, index: Index | None = None) -> list[Callable]:
    """Architect: entry points, anchors, read_file, grep, symbol navigation, consult_owasp, skills. No shell."""
    target = Path(target).resolve()
    read_file, grep, _shell, _domain = code_tools(target, run)

    def list_entry_points() -> dict:
        """List the deterministic entry points (trust boundaries) found by the text detectors:
        route registrations and handlers, with file:line and the handler symbol."""
        return {"entry_points": [c.model_dump() for c in static.entry_points(target)]}

    list_anchors, *_ = common_tools(run)
    return [list_entry_points, list_anchors, read_file, grep, *lsp_tools(target, index or default_index(target)), consult_owasp, list_skills, load_skill]


TRIAGE_TOOLS = {"read_file", "grep", "lsp_symbols"}


def triage_tools(run, target: Path, index: Index | None = None) -> list[Callable]:
    """Triage: read-only, no verdict tool, no shell — a fast look, not an audit."""
    return subset(verifier_tools(run, target, index=index), TRIAGE_TOOLS)


def subset(tools: list[Callable], names: set[str]) -> list[Callable]:
    """Pick tools by function name, in `names` order of the source list; an unknown name is a build-time typo."""
    by = {t.__name__: t for t in tools}
    missing = names - set(by)
    if missing:
        raise KeyError(f"unknown tools: {sorted(missing)}")
    return [t for t in tools if t.__name__ in names]


# Tool names each specialist may use (scanner/app/specialists.py references these once per REGISTRY entry).
_READ = {"read_file", "grep", "lsp_symbols", "lsp_definition", "lsp_references", "lsp_callers", "lsp_callees", "lsp_path_to_entry"}
_COMMON = {"list_anchors", "list_findings", "note_add", "note_list", "consult_owasp", "load_skill", "list_skills"}
TAINT_TOOLS = {"report_finding", "shell"} | _READ | _COMMON
AUTHZ_TOOLS = TAINT_TOOLS | {"consult_domain"}
DEPENDENCY_TOOLS = {"report_finding", "consult_knowledge", "read_file", "grep", "lsp_definition", "lsp_references", "lsp_path_to_entry"} | _COMMON
SECRETS_TOOLS = {"report_finding", "read_file", "grep", "lsp_definition", "lsp_references"} | _COMMON
CONFIG_TOOLS = {"report_finding", "read_file", "grep", "lsp_definition", "lsp_references"} | _COMMON
TAINT_CRITIC_TOOLS = {"disprove_finding", "check_dominance", "shell"} | _READ | _COMMON
AUTHZ_CRITIC_TOOLS = TAINT_CRITIC_TOOLS | {"consult_domain"}
DEPENDENCY_CRITIC_TOOLS = {"disprove_finding", "consult_knowledge", "read_file", "grep", "lsp_definition", "lsp_references",
                           "lsp_path_to_entry"} | _COMMON
