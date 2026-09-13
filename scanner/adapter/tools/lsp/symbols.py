"""lsp_symbols: the definitions declared in one file."""

from __future__ import annotations

from scanner.adapter.tools.common import SYM_CAP, err, inside
from scanner.adapter.tools.context import ToolContext


def make(ctx: ToolContext):
    def lsp_symbols(path: str) -> dict:
        """List the definitions declared in one file (name, kind, line, end_line, container) without reading its
        body. Use it to decide which symbol to open with lsp_definition instead of reading the whole file."""
        if inside(ctx.target, path) is None:
            return err(f"{path}: outside the target")
        syms = ctx.idx.symbols(path)
        return {"path": path, "symbols": [s.model_dump() for s in syms[:SYM_CAP]], "truncated": len(syms) > SYM_CAP}

    return lsp_symbols
