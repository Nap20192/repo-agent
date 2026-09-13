"""Filesystem view of the target: which files count, how to read them safely, where the language table lives.

Every adapter that touches the target goes through here (one confinement rule, one size cap, one skip list).
"""

from __future__ import annotations

import os
import re
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


_TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "fixtures", "testdata", "mocks", "__mocks__"}
_TEST_NAMES = re.compile(r"(^test_.*|.*_test|.*\.test|.*\.spec)\.\w+$")


def source_files(target: Path) -> list[str]:
    """Production source files (known languages) as sorted relative paths — no tests, specs or fixtures
    (Shannon's plan rule: coverage is over production code). The planner's file baselines come from here."""
    root = Path(target)
    out = []
    for p in files(root):
        if p.suffix not in LANG_EXT or _TEST_NAMES.match(p.name):
            continue
        rel_p = p.relative_to(root)
        if _TEST_DIRS & set(rel_p.parts[:-1]):
            continue
        out.append(rel_p.as_posix())
    return sorted(out)


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


def imported_by(target: Path, package: str, max_files: int = 5000) -> int:
    """Source files importing `package` (require/from/import in JS/TS, import in Python, quoted module path in
    Go): the cheap reachability hint of a direct dependency finding. Counts files, capped. Ponytail: a regex,
    not the LSP — upgrade to the Index when the hint decides priorities."""
    p, py = re.escape(package), re.escape(package.replace("-", "_"))
    pat = re.compile(rf"""require\(\s*['"]{p}(?:/|['"])|(?:from|import)\s+['"]{p}(?:/|['"])"""
                     rf"""|^\s*(?:import\s+)?(?:\w+\s+)?"{p}(?:/[^"]*)?"|^\s*(?:from|import)\s+{py}\b""", re.MULTILINE)
    n = 0
    for i, f in enumerate(files(target)):
        if i >= max_files:
            break
        if f.suffix not in LANG_EXT:
            continue
        try:
            with f.open("rb") as fh:  # read at most FILE_CAP bytes; never slurp a multi-GB bundle to slice it
                text = fh.read(FILE_CAP).decode("utf-8", errors="ignore")
        except OSError:
            continue
        n += bool(pat.search(text))
    return n
