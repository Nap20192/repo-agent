"""ADK function tools for the Investigator, Critic and Architect roles, as closures over the run store and target.

Layout: common (caps, confinement, shared tools), code (read/grep/shell/consult_domain), lsp (symbol navigation
over the Index port), gates (report_finding / disprove_finding), rosters (per-role assemblers + subset).
Every tool returns a dict; errors are {"status": "error", "reason": ...}, never raised into the model."""

from scanner.adapter.tools.code import code_tools
from scanner.adapter.tools.common import (
    DEF_CAP,
    FILE_CAP,
    GREP_CAP,
    OUT_CAP,
    READ_WINDOW,
    SHELL_TIMEOUT,
    SYM_CAP,
    common_tools,
    default_index,
    default_reader,
    err,
    inside,
    quotes_in_target,
    shell_quote,
)
from scanner.adapter.tools.gates import (
    disprove_finding_tool,
    gate_finding,
    report_finding_tool,
)
from scanner.adapter.tools.lsp import lsp_tools
from scanner.adapter.tools.rosters import (
    AUTHZ_CRITIC_TOOLS,
    AUTHZ_TOOLS,
    CONFIG_TOOLS,
    DEPENDENCY_CRITIC_TOOLS,
    DEPENDENCY_TOOLS,
    SECRETS_TOOLS,
    TAINT_CRITIC_TOOLS,
    TAINT_TOOLS,
    architect_tools,
    critic_tools,
    subset,
    triage_tools,
    verifier_tools,
)

# Kept for one existing importer (tests/test_lsp_callgraph.py); the public spelling `lsp_tools` is preferred.
_lsp_tools = lsp_tools

__all__ = [
    "AUTHZ_CRITIC_TOOLS",
    "AUTHZ_TOOLS",
    "CONFIG_TOOLS",
    "DEF_CAP",
    "DEPENDENCY_CRITIC_TOOLS",
    "DEPENDENCY_TOOLS",
    "FILE_CAP",
    "GREP_CAP",
    "OUT_CAP",
    "READ_WINDOW",
    "SECRETS_TOOLS",
    "SHELL_TIMEOUT",
    "SYM_CAP",
    "TAINT_CRITIC_TOOLS",
    "TAINT_TOOLS",
    "architect_tools",
    "code_tools",
    "common_tools",
    "critic_tools",
    "default_index",
    "default_reader",
    "disprove_finding_tool",
    "err",
    "gate_finding",
    "inside",
    "lsp_tools",
    "quotes_in_target",
    "report_finding_tool",
    "shell_quote",
    "subset",
    "triage_tools",
    "verifier_tools",
]
