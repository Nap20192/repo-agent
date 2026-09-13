"""Ports declared by the core (Cockburn's hexagon): what the graph and the tools need from the outside.

`RunStore` is the run-scoped State; `Index` is the code index, split by
consumer (ISP): `SymbolLocator` (gate, synthetic anchors), `Definitions` (bodies), `CallGraph` (reachability).

`Index` is language-agnostic. Adapters live in scanner/adapter/index: one LSP-backed adapter per
language (Go, Python, TypeScript, JavaScript), a grep fallback, and a multiplexer that picks the
adapter by file extension. Symbols are addressed by fully-qualified-ish names as agents write them:
"pingHandler", "Server.login", "(*Server).login", "s.login", "pkg.Func" — adapters normalise.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from scanner.core.types import Anchor, Dossier, Finding, Hypothesis


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
class SymbolLocator(Protocol):
    def find_symbol(self, fqn: str) -> tuple[str, int] | None:
        """(file, line) of the definition, or None when the symbol is not defined in the target."""

    def has_symbol(self, fqn: str) -> bool: ...


@runtime_checkable
class Definitions(Protocol):
    def symbols(self, file: str) -> list[Symbol]:
        """Definitions declared in one file (relative path)."""

    def definition_range(self, fqn: str) -> tuple[str, int, int] | None:
        """(file, start_line, end_line) of the whole definition body, or None."""


@runtime_checkable
class CallGraph(Protocol):
    def references(self, fqn: str) -> list[tuple[str, int, str]]:
        """Call/use sites as (file, line, line_text); [] when unknown or unsupported."""

    def callers(self, fqn: str) -> list[tuple[str, int, str]]:
        """Call sites of fqn as (file, line, calling symbol name); [] when unknown."""

    def callees(self, fqn: str) -> list[tuple[str, int, str]]:
        """Symbols called inside fqn's body as (callee file, callee definition line, callee name); [] when unknown."""

    def path_to_entry(self, fqn: str, entries: list[str], max_depth: int = 6) -> list[str] | None:
        """Chain of symbol names [entry, ..., fqn] found by walking callers up to max_depth, else None."""


@runtime_checkable
class Closeable(Protocol):
    def close(self) -> None:
        """Release servers/processes; idempotent."""


@runtime_checkable
class Degradable(Protocol):
    """An index that can give up (missing server, protocol error) — `failed` lets a fallback take over."""

    failed: bool


@runtime_checkable
class Index(SymbolLocator, Definitions, CallGraph, Closeable, Protocol):
    """The full code index: every adapter implements all of it; consumers should ask for the part they use."""


@runtime_checkable
class RunStore(Protocol):
    """Run-scoped State as the graph and the tools use it (scanner.adapter.store.Run implements it)."""

    def anchors(self) -> list[Anchor]: ...
    def anchor(self, anchor_id: str) -> Anchor | None: ...
    def save_anchors(self, anchors: list[Anchor]) -> None: ...
    def put_hypotheses(self, rnd: int, hs: list[Hypothesis]) -> None: ...
    def put_dossiers(self, rnd: int, ds: list[Dossier]) -> None: ...
    def findings(self) -> list[Finding]: ...
    def report(self, f: Finding) -> Finding: ...
    def set_status(self, finding_id: str, status: str, evidence: list[str], note: str = "") -> Finding | None: ...
    def annotate(self, finding_id: str, **fields) -> Finding | None:
        """Merge report-only annotations (review, viability, repro_status, calibration) into a finding.
        Raises ValueError for verdict fields (status, evidence, confidence, id, anchor_id): those belong to the gates."""
    def log_gate(self, anchor_id: str, reason: str) -> None: ...
    def add_note(self, text: str, ref: str = "") -> None: ...
    def notes(self) -> list[dict]: ...
    def put_artifact(self, stage: str, obj: dict) -> None: ...
    def artifact(self, stage: str) -> dict | None: ...
