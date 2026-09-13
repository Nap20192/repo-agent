"""The scan target named by a chat message (adk web): a local directory, or a GitHub URL cloned on demand."""

from __future__ import annotations

from pathlib import Path

from scanner.adapter import git

PREFIX = "scan target:"  # what the CLI sends as its own first message (runner.run_session)


def resolve_target(text: str) -> Path:
    """`text` → an existing directory: a path as given, or https://github.com/<owner>/<repo> cloned into .targets/.
    Anything else is a ValueError with a message the user can act on."""
    t = text.strip()
    if t.lower().startswith(PREFIX):
        t = t[len(PREFIX):].strip()
    if not t:
        raise ValueError("say which directory or GitHub repository to scan: a path, or https://github.com/<owner>/<repo>")
    if git.SAFE_URL.match(t):
        return git.clone(t).resolve()
    p = Path(t).expanduser()
    if not p.is_dir():
        raise ValueError(f"{t!r} is neither a directory nor a https://github.com/<owner>/<repo> URL")
    return p.resolve()
