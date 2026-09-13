"""git clone on demand for scan targets named by URL. Only https://github.com/<owner>/<repo>: no other hosts or
transports (ext::, file://), no option-shaped strings, `--` before positionals, no auth prompts, a shallow clone
into `.targets/<owner>-<repo>` (kept when it already exists)."""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from pathlib import Path

log = logging.getLogger("scanner.git")

SAFE_URL = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")
TARGETS = Path(".targets")


def clone(url: str, into: Path = TARGETS) -> Path:
    """The local directory of `url`, cloned shallowly into `into` on first use. A clone lands in a temporary sibling
    and is renamed into place only when git succeeded, so a failed or interrupted clone is never reused; an existing
    entry is reused only when it is a real directory inside `into` (never a symlink planted there)."""
    m = SAFE_URL.match(url.strip())
    if not m or ".." in m.groups():
        raise ValueError(f"refusing to clone {url!r}: only https://github.com/<owner>/<repo>")
    owner, repo = m.groups()
    into = Path(into)
    dest = into / f"{owner}-{repo}"
    if dest.is_dir() and not dest.is_symlink() and dest.resolve().is_relative_to(into.resolve()):
        return dest
    if dest.exists() or dest.is_symlink():
        raise ValueError(f"refusing to reuse {dest}: not a plain directory inside {into}")
    into.mkdir(parents=True, exist_ok=True)
    tmp = into / f".{owner}-{repo}.{os.getpid()}.part"
    log.info("cloning %s → %s", url, dest)
    try:
        subprocess.run(["git", "clone", "--depth", "1", "--", m.group(0), str(tmp)], check=True, capture_output=True, text=True,
                       timeout=300, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
        tmp.rename(dest)
    finally:
        if tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)  # a failed / interrupted clone leaves nothing behind
    return dest
