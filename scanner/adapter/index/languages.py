"""Per-language LSP adapters: which server to run, which files it owns, how agents spell symbols."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from scanner.adapter import fs


@dataclass(frozen=True)
class Language:
    name: str
    lang_id: str  # LSP languageId
    command: tuple[str, ...]  # server argv
    extensions: tuple[str, ...]
    requires: tuple[str, ...] = ()  # binaries that must be on PATH besides command[0]
    skip_dirs: frozenset[str] = field(default_factory=lambda: frozenset({".git", "node_modules", "vendor", "venv", ".venv", "__pycache__", "dist", "build", ".targets"}))
    preflight: Callable[[Path], str | None] | None = None  # reason to refuse the server on this target (security)

    def normalize(self, fqn: str) -> list[str]:
        """Candidate lookup keys, most specific first: "(*Server).login" → ["Server.login", "login"];
        "pkg/sub.Server.login" → ["Server.login", "login"]; "s.login" → ["s.login", "login"]."""
        s = fqn.strip()
        s = re.sub(r"\(\s*\*?\s*(\w+)\s*\)", r"\1", s)  # (*Server).login → Server.login
        s = s.split("(", 1)[0]  # drop call parens/args
        s = s.rsplit("/", 1)[-1]  # drop import paths
        parts = [p for p in s.split(".") if p]
        out: list[str] = []
        if len(parts) >= 2:
            out.append(".".join(parts[-2:]))
        if parts:
            out.append(parts[-1])
        return [c for i, c in enumerate(out) if c not in out[:i]]


GO = Language("go", "go", ("gopls",), (".go",), requires=("go",))
PYTHON = Language("python", "python", ("pyright-langserver", "--stdio"), (".py",))


def ts_plugins_declared(target: Path) -> str | None:
    """tsserver `require()`s every module in tsconfig/jsconfig `compilerOptions.plugins` when a project loads —
    arbitrary JS from an untrusted target. Refuse the server (grep fallback) when any such config declares plugins."""
    for cfg in fs.files(target):
        if cfg.name.startswith(("tsconfig", "jsconfig")) and cfg.suffix == ".json":
            try:
                if '"plugins"' in cfg.read_text(errors="replace"):
                    return f"{cfg.relative_to(target)} declares TS language-service plugins (arbitrary JS on load)"
            except OSError:
                continue
    return None


TYPESCRIPT = Language("typescript", "typescript", ("typescript-language-server", "--stdio"), (".ts", ".tsx"), preflight=ts_plugins_declared)
JAVASCRIPT = Language("javascript", "javascript", ("typescript-language-server", "--stdio"), (".js", ".jsx", ".mjs"), preflight=ts_plugins_declared)

LANGUAGES: dict[str, Language] = {lang.name: lang for lang in (GO, PYTHON, TYPESCRIPT, JAVASCRIPT)}
