"""lsp_definition: only the body of a symbol's definition, numbered."""

from __future__ import annotations

from scanner.adapter.tools.common import DEF_CAP, err, inside
from scanner.adapter.tools.context import ToolContext


def make(ctx: ToolContext):
    def lsp_definition(symbol: str) -> dict:
        """Return ONLY the body of a symbol's definition as numbered lines (function/method/class), resolved by
        the language server; prefer lsp_definition over read_file — it returns only the symbol's body, so you
        quote exactly the lines that matter. Names: 'pingHandler', 'Server.login', '(*Server).login', 'pkg.Func'."""
        rng = ctx.idx.definition_range(symbol)
        if rng is None:
            return err(f"symbol {symbol!r} not found in the index — check the name with lsp_symbols or grep for it")
        file, start, end = rng
        p = inside(ctx.target, file)
        if p is None or not p.is_file():
            return err(f"{file}: not a file inside the target")
        lines = p.read_text(errors="replace").splitlines()
        start, last = max(start, 1), min(end, len(lines))
        truncated = last - start + 1 > DEF_CAP
        if truncated:
            last = start + DEF_CAP - 1
        text = "\n".join(f"{i}: {lines[i - 1]}" for i in range(start, last + 1))
        return {"symbol": symbol, "file": file, "start": start, "end": last, "truncated": truncated, "text": text}

    return lsp_definition
