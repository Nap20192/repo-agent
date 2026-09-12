"""Application settings: `Settings` (scanner.core.settings) plus `.env` loading for the CLI and `adk web`."""

from __future__ import annotations

import os
from pathlib import Path

from scanner.core.settings import Settings

__all__ = ["Settings", "apply_dotenv", "load_dotenv"]


def load_dotenv(path: str | Path = ".env") -> dict[str, str]:
    """KEY=VALUE lines of a .env file (comments and blanks skipped, quotes stripped); {} when absent."""
    p = Path(path)
    if not p.is_file():
        return {}
    out: dict[str, str] = {}
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip("'\"")
    return out


def apply_dotenv(path: str | Path = ".env") -> None:
    """Merge a .env file into the process environment; variables already set win (dotenv semantics)."""
    for k, v in load_dotenv(path).items():
        os.environ.setdefault(k, v)
