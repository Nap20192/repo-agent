"""ADK function tools, one per file, built per run from a ToolContext through the name registry.

Layout: code/ (read_file, grep, shell), lsp/ (symbol navigation over the Index port), gates/ (report_finding,
disprove_finding), store/ (anchors, findings, notes), consult/ (owasp, knowledge, domain, skills, dominance, entry
points), knowledge/ (the Knowledge agent's databases). `registry.TOOLS` names them; `make(names, ctx)` builds them.
Every tool returns a dict; errors are {"status": "error", "reason": ...}, never raised into the model."""

from scanner.adapter.tools.common import (
    DEF_CAP,
    FILE_CAP,
    GREP_CAP,
    OUT_CAP,
    READ_WINDOW,
    SHELL_TIMEOUT,
    SYM_CAP,
    confined,
    default_index,
    default_reader,
    err,
    inside,
    quotes_in_target,
    shell_quote,
)
from scanner.adapter.tools.context import ToolContext
from scanner.adapter.tools.gates import gate_finding
from scanner.adapter.tools.registry import TOOLS, make, subset

__all__ = [
    "DEF_CAP",
    "FILE_CAP",
    "GREP_CAP",
    "OUT_CAP",
    "READ_WINDOW",
    "SHELL_TIMEOUT",
    "SYM_CAP",
    "TOOLS",
    "ToolContext",
    "confined",
    "default_index",
    "default_reader",
    "err",
    "gate_finding",
    "inside",
    "make",
    "quotes_in_target",
    "shell_quote",
    "subset",
]
