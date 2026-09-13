"""git clone on demand for scan targets named by URL. Only https://github.com/<owner>/<repo>: no other hosts or
transports (ext::, file://), no option-shaped strings, `--` before positionals, no auth prompts, a shallow clone
into `.targets/<owner>-<repo>` (kept when it already exists)."""

from __future__ import annotations

import logging
import os
import re
import subprocess
from pathlib import Path

log = logging.getLogger("scanner.git")

SAFE_URL = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")
TARGETS = Path(".targets")


def clone(url: str, into: Path = TARGETS) -> Path:
    """The local directory of `url`, cloned shallowly into `into` on first use."""
    m = SAFE_URL.match(url.strip())
    if not m or ".." in m.groups():
        raise ValueError(f"refusing to clone {url!r}: only https://github.com/<owner>/<repo>")
    owner, repo = m.groups()
    dest = Path(into) / f"{owner}-{repo}"
    if dest.is_dir():
        return dest
    Path(into).mkdir(parents=True, exist_ok=True)
    log.info("cloning %s → %s", url, dest)
    subprocess.run(["git", "clone", "--depth", "1", "--", m.group(0), str(dest)], check=True, capture_output=True, text=True,
                   timeout=300, env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    return dest
