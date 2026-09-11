"""Ports declared by the core: what the graph and the tools need from a code index.

`Index` is language-agnostic. Adapters live in scanner/adapter/index: one LSP-backed adapter per
language (Go, Python, TypeScript, JavaScript), a grep fallback, and a multiplexer that picks the
adapter by file extension. Symbols are addressed by fully-qualified-ish names as agents write them:
"pingHandler", "Server.login", "(*Server).login", "s.login", "pkg.Func" — adapters normalise.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict


class Symbol(BaseModel):
    """One definition: 1-based lines; `line` is the selection (name) line, `end_line` closes the body."""

    model_config = ConfigDict(extra="ignore")
    name: str
    kind: str = ""  # function | method | class | struct | variable | ...
    file: str  # relative to the target root
    line: int
    end_line: int = 0
    container: str = ""  # enclosing class/struct/receiver, if any


@runtime_checkable
class Index(Protocol):
    def find_symbol(self, fqn: str) -> tuple[str, int] | None:
        """(file, line) of the definition, or None when the symbol is not defined in the target."""

    def has_symbol(self, fqn: str) -> bool: ...

    def definition_range(self, fqn: str) -> tuple[str, int, int] | None:
        """(file, start_line, end_line) of the whole definition body, or None."""

    def references(self, fqn: str) -> list[tuple[str, int, str]]:
        """Call/use sites as (file, line, line_text); [] when unknown or unsupported."""

    def symbols(self, file: str) -> list[Symbol]:
        """Definitions declared in one file (relative path)."""

    def callers(self, fqn: str) -> list[tuple[str, int, str]]:
        """Call sites of fqn as (file, line, calling symbol name); [] when unknown."""

    def callees(self, fqn: str) -> list[tuple[str, int, str]]:
        """Symbols called inside fqn's body as (callee file, callee definition line, callee name); [] when unknown."""

    def path_to_entry(self, fqn: str, entries: list[str], max_depth: int = 6) -> list[str] | None:
        """Chain of symbol names [entry, ..., fqn] found by walking callers up to max_depth, else None."""

    def close(self) -> None:
        """Release servers/processes; idempotent."""
