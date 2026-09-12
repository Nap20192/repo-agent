"""Filesystem view of the target: which files count, how to read them safely, where the language table lives.

Every adapter that touches the target goes through here (one confinement rule, one size cap, one skip list).
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "vendor", "venv", ".venv", "__pycache__", "dist", "build", ".targets"}
LANG_EXT = {".go": "go", ".py": "python", ".js": "javascript", ".ts": "typescript", ".tsx": "typescript",
            ".jsx": "javascript", ".php": "php"}
FILE_CAP = 2 * 1024 * 1024  # never slurp a multi-GB file for a small window (read_file, dominance)
MAX_DETECT_LINE = 1000  # text detectors skip longer lines: minified bundles and adversarial input, no backtracking budget


def files(target: Path) -> Iterator[Path]:
    """Source files under target, skipping vendor/build/VCS dirs and symlinks that leave the target."""
    root_res = Path(target).resolve()
    for root, dirs, names in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not (Path(root) / d).is_symlink()]
        for f in names:
            p = Path(root) / f
            if p.is_symlink() and not p.resolve().is_relative_to(root_res):
                continue  # a symlink pointing outside the target is never read or reported
            yield p


def inside(target: Path, path: str) -> Path | None:
    """Resolved path of `path` if it stays inside the target (symlinks and '..' resolved), else None."""
    root = Path(target).resolve()
    p = (root / path).resolve()
    return p if p.is_relative_to(root) else None


def rel(target: Path, file: str) -> str:
    """Scanner-reported path → path relative to the target root ('file://' and './' stripped)."""
    file = file.removeprefix("file://").removeprefix("./")
    try:
        return str(Path(file).resolve().relative_to(Path(target).resolve())) if os.path.isabs(file) else file
    except ValueError:
        return file


def detect_langs(target: Path) -> set[str]:
    """Languages present in the target, by file extension."""
    return {LANG_EXT[p.suffix] for p in files(target) if p.suffix in LANG_EXT}


def read_lines(target: Path, file: str, line: int, window: int = 3) -> str:
    """Lines line-window..line+window of a file inside the target; FileNotFoundError when outside or missing."""
    p = inside(target, file)
    if p is None:  # symlink or '..' escaping the target
        raise FileNotFoundError(f"{file}: outside the target")
    lines = p.read_text(errors="replace").splitlines()  # raises FileNotFoundError
    lo, hi = max(1, line - window), min(len(lines), line + window)
    return "\n".join(lines[lo - 1:hi])
