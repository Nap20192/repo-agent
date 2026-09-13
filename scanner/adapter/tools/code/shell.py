"""shell: run a command in the target directory (host exec, capped, timed out)."""

from __future__ import annotations

import subprocess

from scanner.adapter.tools.common import OUT_CAP, SHELL_TIMEOUT, err
from scanner.adapter.tools.context import ToolContext


def run_shell(target, command: str) -> dict:
    """The shell tool's body, reused by grep and consult_domain."""
    # ponytail: host exec without sandbox; run untrusted targets in Docker before scanning.
    try:
        p = subprocess.run(command, shell=True, cwd=target, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=SHELL_TIMEOUT, check=False)
    except subprocess.TimeoutExpired:
        return err(f"timeout after {SHELL_TIMEOUT}s")
    except Exception as e:  # noqa: BLE001 — a tool never raises into the model
        return err(f"shell: {e}")
    return {"exit_code": p.returncode, "output": (p.stdout + p.stderr)[:OUT_CAP]}


def make(ctx: ToolContext):
    def shell(command: str) -> dict:
        """Run a shell command in the target directory (cat, sed -n, ls, git, go build ...). 60s timeout,
        output capped. Use it to read code you need for evidence."""
        return run_shell(ctx.target, command)

    return shell
