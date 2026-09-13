"""run_cmd: the one place a scanner binary is executed (host exec, no sandbox)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

# ponytail: host exec, no sandbox — do not scan untrusted repos with deps install.


def run_cmd(cmd: list[str], target: Path, timeout: int = 600) -> str:
    """stdout of `cmd` run in `target`; a missing binary raises FileNotFoundError (the scan records it as failed)."""
    if shutil.which(cmd[0]) is None:
        raise FileNotFoundError(f"{cmd[0]} not installed")
    p = subprocess.run(cmd, cwd=target, capture_output=True, text=True, timeout=timeout, check=False)
    return p.stdout
