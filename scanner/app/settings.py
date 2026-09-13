"""Application settings: `Settings` (scanner.core.settings) plus `.env` loading for the CLI and `adk web`."""

from __future__ import annotations

import os
import re
from pathlib import Path

from scanner.core.settings import Settings

__all__ = ["Settings", "apply_dotenv", "load_dotenv"]


def load_dotenv(path: str | Path = ".env") -> dict[str, str]:
    """KEY=VALUE lines of a .env file (comments and blanks skipped, quotes stripped); {} when absent."""
    p = Path(path)
    if not p.is_file():
        return {}
    out: dict[str, str] = {}
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = _value(v.strip())
    return out


def _value(v: str) -> str:
    """Unquote a value; an unquoted one ends at the first ` #` (inline comment, dotenv semantics)."""
    v = v.strip()
    if v[:1] in ("'", '"') and (close := v.find(v[0], 1)) > 0:
        return v[1:close]
    return "" if v.startswith("#") else re.split(r"\s+#", v, maxsplit=1)[0].strip()


def apply_dotenv(path: str | Path = ".env") -> None:
    """Merge a .env file into the process environment; variables already set win (dotenv semantics)."""
    for k, v in load_dotenv(path).items():
        os.environ.setdefault(k, v)
