"""ToolContext: everything a tool closure may need for one run — target, store run, index, readers, settings. Tool
factories take it and return the ADK function tool; defaults are lazy so tests can pass only what they use."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scanner.adapter.tools.common import default_index, default_reader, quotes_in_target
from scanner.core.ports import Index
from scanner.core.settings import Settings


@dataclass
class ToolContext:
    target: Path
    run: Any = None  # RunStore (adapter.store.Run or tests.fakes.FakeRun)
    index: Index | None = None
    reader: Callable[[str, int], str] | None = None  # (file, line) -> the code around it, for the report gate
    in_target: Callable[[list[str]], bool] | None = None  # quotes present somewhere in the target, for the disprove gate
    entries_fn: Callable[[], list[str]] | None = None  # entry-point symbols, for lsp_path_to_entry
    settings: Settings = field(default_factory=Settings)

    def __post_init__(self) -> None:
        self.target = Path(self.target).resolve()
        self.reader = self.reader or default_reader(self.target)
        self.in_target = self.in_target or (lambda qs: quotes_in_target(self.target, qs))

    @property
    def idx(self) -> Index:
        """The Index, built on first use when none was given (LSP per language, grep fallback)."""
        if self.index is None:
            self.index = default_index(self.target)
        return self.index
