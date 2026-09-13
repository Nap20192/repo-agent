"""grep: regex search inside the target (rg -n, grep fallback), capped."""

from __future__ import annotations

from scanner.adapter.tools.code.shell import run_shell
from scanner.adapter.tools.common import GREP_CAP, err, inside, shell_quote
from scanner.adapter.tools.context import ToolContext


def make(ctx: ToolContext):
    def grep(pattern: str, path: str = ".") -> dict:
        """Search the target for a regex (rg -n). path: file or directory inside the target."""
        if inside(ctx.target, path) is None:
            return err(f"{path}: outside the target")
        q = shell_quote
        out = run_shell(ctx.target, f"rg -n --no-heading -m 100 -e {q(pattern)} {q(path)} || grep -rn -E -m 100 -e {q(pattern)} {q(path)}")
        note = "\n… truncated: narrow the pattern or path"
        if "output" in out and len(out["output"]) > GREP_CAP:
            out["output"] = out["output"][: GREP_CAP - len(note)] + note
        return out

    return grep
