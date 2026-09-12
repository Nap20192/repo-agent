"""Symbol-level code navigation tools over the Index port: bodies, references, call hierarchy, reachability."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from scanner.adapter import static
from scanner.adapter.tools.common import DEF_CAP, SYM_CAP, err, inside
from scanner.core.ports import Index


def lsp_tools(target: Path, index: Index, entries_fn: Callable[[], list[str]] | None = None) -> list[Callable]:
    """lsp_symbols / lsp_definition / lsp_references / lsp_callers / lsp_callees / lsp_path_to_entry."""
    entries_fn = entries_fn or (lambda: [c.symbol for c in static.entry_points(target) if c.symbol])

    def _confined(rows: list[tuple]) -> list[tuple]:
        return [r for r in rows if inside(target, r[0]) is not None][:50]  # never leak files outside the target

    def lsp_symbols(path: str) -> dict:
        """List the definitions declared in one file (name, kind, line, end_line, container) without reading its
        body. Use it to decide which symbol to open with lsp_definition instead of reading the whole file."""
        if inside(target, path) is None:
            return err(f"{path}: outside the target")
        syms = index.symbols(path)
        return {"path": path, "symbols": [s.model_dump() for s in syms[:SYM_CAP]], "truncated": len(syms) > SYM_CAP}

    def lsp_definition(symbol: str) -> dict:
        """Return ONLY the body of a symbol's definition as numbered lines (function/method/class), resolved by
        the language server; prefer lsp_definition over read_file — it returns only the symbol's body, so you
        quote exactly the lines that matter. Names: 'pingHandler', 'Server.login', '(*Server).login', 'pkg.Func'."""
        rng = index.definition_range(symbol)
        if rng is None:
            return err(f"symbol {symbol!r} not found in the index — check the name with lsp_symbols or grep for it")
        file, start, end = rng
        p = inside(target, file)
        if p is None or not p.is_file():
            return err(f"{file}: not a file inside the target")
        lines = p.read_text(errors="replace").splitlines()
        start, last = max(start, 1), min(end, len(lines))
        truncated = last - start + 1 > DEF_CAP
        if truncated:
            last = start + DEF_CAP - 1
        text = "\n".join(f"{i}: {lines[i - 1]}" for i in range(start, last + 1))
        return {"symbol": symbol, "file": file, "start": start, "end": last, "truncated": truncated, "text": text}

    def lsp_references(symbol: str) -> dict:
        """Every place a symbol is used or called (file, line, line text), resolved by the language server — the
        exhaustive call-site list the proof standard requires. Capped at 50; [] when the symbol is unknown."""
        refs = _confined(index.references(symbol))
        return {"symbol": symbol, "references": [{"file": f, "line": ln, "text": t} for f, ln, t in refs]}

    def lsp_callers(symbol: str) -> dict:
        """Call sites of a symbol (file, line, calling symbol) from the language server's call hierarchy — who
        invokes it. Use it to walk from a sink back towards the trust boundary; capped at 50."""
        refs = _confined(index.callers(symbol))
        return {"symbol": symbol, "callers": [{"file": f, "line": ln, "symbol": s} for f, ln, s in refs]}

    def lsp_callees(symbol: str) -> dict:
        """Symbols a function calls (callee file, definition line, callee symbol) — walk from an entry point
        down towards sinks without reading whole files; capped at 50."""
        refs = _confined(index.callees(symbol))
        return {"symbol": symbol, "callees": [{"file": f, "line": ln, "symbol": s} for f, ln, s in refs]}

    def lsp_path_to_entry(symbol: str) -> dict:
        """Shortest caller chain from an entry point (route handler / main) to the symbol, e.g.
        ["main", "pingHandler", "runCmd"]; null when no entry reaches it within 6 hops. The Investigator
        uses it for reachability claims; the Critic uses a null path as the "unreachable" disproof, after
        confirming with lsp_callers that the chain is not merely cut by dynamic dispatch."""
        entries = entries_fn()
        return {"symbol": symbol, "entries": entries[:50], "path": index.path_to_entry(symbol, entries)}

    return [lsp_symbols, lsp_definition, lsp_references, lsp_callers, lsp_callees, lsp_path_to_entry]
