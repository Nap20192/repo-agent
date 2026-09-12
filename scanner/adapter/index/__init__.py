"""Code index adapters behind scanner.core.ports.Index: LSP per language, grep fallback, multiplexer."""

from __future__ import annotations

import logging
from pathlib import Path

from scanner.adapter import fs
from scanner.adapter.index.grep import GrepIndex
from scanner.adapter.index.languages import LANGUAGES, Language
from scanner.adapter.index.lsp import LspIndex
from scanner.adapter.index.rpc import LspClient, LspError
from scanner.core.ports import Degradable, Index, Symbol

log = logging.getLogger("scanner.index")

__all__ = ["LANGUAGES", "GrepIndex", "Index", "Language", "LspClient", "LspError", "LspIndex", "MultiIndex", "build_index"]


class FallbackIndex:
    """primary (an Index that is also Degradable, e.g. LSP) until it fails, then secondary (grep) — per language."""

    def __init__(self, primary: Index | Degradable, secondary: Index):
        self.primary, self.secondary = primary, secondary

    def _pick(self, method: str, *args):
        res = getattr(self.primary, method)(*args)
        if self.primary.failed:
            return getattr(self.secondary, method)(*args)
        return res

    def find_symbol(self, fqn: str): return self._pick("find_symbol", fqn)
    def has_symbol(self, fqn: str) -> bool: return self._pick("has_symbol", fqn)
    def definition_range(self, fqn: str): return self._pick("definition_range", fqn)
    def references(self, fqn: str): return self._pick("references", fqn)
    def symbols(self, file: str): return self._pick("symbols", file)
    def callers(self, fqn: str): return self._pick("callers", fqn)
    def callees(self, fqn: str): return self._pick("callees", fqn)
    def path_to_entry(self, fqn: str, entries: list[str], max_depth: int = 6): return self._pick("path_to_entry", fqn, entries, max_depth)

    def close(self) -> None:
        self.primary.close()
        self.secondary.close()


class MultiIndex:
    """Routes by language: symbol lookups try every language index (sorted), file queries go by extension."""

    def __init__(self, target: Path, indexes: dict[str, Index], fallback: Index):
        self.target, self.indexes, self.fallback = Path(target).resolve(), dict(sorted(indexes.items())), fallback

    def _for_file(self, file: str) -> Index:
        lang = fs.LANG_EXT.get(Path(file).suffix, "")
        return self.indexes.get(lang, self.fallback)

    def _first(self, method: str, *args, empty):
        # LSP-backed languages answer first: a grep index of another language must not shadow a real definition
        order = sorted(self.indexes.items(), key=lambda kv: (isinstance(kv[1], GrepIndex), kv[0]))
        for _, ix in order:
            res = getattr(ix, method)(*args)
            if res not in (None, [], False):
                return res
            if method != "find_symbol" and args and ix.has_symbol(args[0]):
                return res  # this language owns the symbol: an empty answer is the answer (e.g. an entry point has no callers)
        return empty

    def find_symbol(self, fqn: str): return self._first("find_symbol", fqn, empty=None)
    def has_symbol(self, fqn: str) -> bool: return self.find_symbol(fqn) is not None
    def definition_range(self, fqn: str): return self._first("definition_range", fqn, empty=None)
    def references(self, fqn: str): return self._first("references", fqn, empty=[])
    def callers(self, fqn: str): return self._first("callers", fqn, empty=[])
    def callees(self, fqn: str): return self._first("callees", fqn, empty=[])
    def path_to_entry(self, fqn: str, entries: list[str], max_depth: int = 6): return self._first("path_to_entry", fqn, entries, max_depth, empty=None)
    def symbols(self, file: str) -> list[Symbol]: return self._for_file(file).symbols(file)

    def close(self) -> None:
        for ix in self.indexes.values():
            ix.close()
        self.fallback.close()


def build_index(target: Path, languages: dict[str, Language] = LANGUAGES, client_factory=LspClient) -> MultiIndex:
    """One index per detected language: LSP adapter with grep fallback; unknown languages → grep only."""
    target = Path(target).resolve()
    exts_of = {}
    for ext, lang in fs.LANG_EXT.items():
        exts_of.setdefault(lang, []).append(ext)
    indexes: dict[str, Index] = {}
    for lang in sorted(fs.detect_langs(target)):
        scoped = GrepIndex(target, tuple(exts_of.get(lang, ())))  # grep sees only this language's files
        if lang in languages:
            indexes[lang] = FallbackIndex(LspIndex(target, languages[lang], client_factory), scoped)
        else:
            indexes[lang] = scoped
    return MultiIndex(target, indexes, GrepIndex(target))
