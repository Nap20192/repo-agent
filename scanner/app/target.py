"""The scan target named by a chat message (adk web): a local directory, or a GitHub URL cloned on demand."""

from __future__ import annotations

from pathlib import Path

from scanner.adapter import git

PREFIX = "scan target:"  # what the CLI sends as its own first message (runner.run_session)


def resolve_target(text: str, root: Path = Path(".")) -> Path:
    """`text` → an existing directory under `root` (WORKSPACE_ROOT; clones go to .targets/ under it), or
    https://github.com/<owner>/<repo> cloned there. Anything else is a ValueError with a message the user can act on.
    The web input is a shared surface, so it never reaches outside the workspace (the CLI's --target still can)."""
    root = Path(root).resolve()
    t = text.strip()
    if t.lower().startswith(PREFIX):
        t = t[len(PREFIX):].strip()
    if not t:
        raise ValueError("say which directory or GitHub repository to scan: a path under the workspace, or https://github.com/<owner>/<repo>")
    if git.SAFE_URL.match(t):
        return git.clone(t, into=root / git.TARGETS).resolve()
    p = Path(t).expanduser()
    p = (p if p.is_absolute() else root / p).resolve()
    if not p.is_relative_to(root):
        raise ValueError(f"{t!r} is outside the workspace {root} — set WORKSPACE_ROOT to scan there")
    if not p.is_dir():
        raise ValueError(f"{t!r} is neither a directory nor a https://github.com/<owner>/<repo> URL")
    return p
