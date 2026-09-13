"""Code-reading tools confined to the target: read_file, grep, shell, and the domain consultant."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from pathlib import Path

from scanner.adapter.domain import consult as domain_consult
from scanner.adapter.tools.common import (
    FILE_CAP,
    GREP_CAP,
    OUT_CAP,
    READ_WINDOW,
    SHELL_TIMEOUT,
    err,
    inside,
    shell_quote,
)
from scanner.core.domain import DomainMap


def code_tools(target: Path, run=None) -> list[Callable]:
    """read_file / grep / shell / consult_domain; `run` (a RunStore) lets consult_domain read the domain map."""

    def read_file(path: str, start: int = 1, end: int = 0) -> dict:
        """Read lines [start, end] of a file inside the target, numbered (default window: 60 lines from start).
        Prefer lsp_definition for a symbol's body; use read_file for context around a line. Quote these lines
        as evidence."""
        p = inside(target, path)
        if p is None or not p.is_file():
            return err(f"{path}: not a file inside the target")
        if p.stat().st_size > FILE_CAP:
            return err(f"{path}: file larger than {FILE_CAP} bytes; use grep or lsp_definition")
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        if start > len(lines):
            return err(f"{path}: start {start} is past the last line ({len(lines)})")
        start = max(start, 1)
        end = min(end or start + READ_WINDOW - 1, len(lines))
        text = "\n".join(f"{i}: {lines[i - 1]}" for i in range(start, end + 1))
        return {"path": path, "start": start, "end": end, "text": text[:OUT_CAP]}

    def grep(pattern: str, path: str = ".") -> dict:
        """Search the target for a regex (rg -n). path: file or directory inside the target."""
        if inside(target, path) is None:
            return err(f"{path}: outside the target")
        q = shell_quote
        out = shell(f"rg -n --no-heading -m 100 -e {q(pattern)} {q(path)} || grep -rn -E -m 100 -e {q(pattern)} {q(path)}")
        note = "\n… truncated: narrow the pattern or path"
        if "output" in out and len(out["output"]) > GREP_CAP:
            out["output"] = out["output"][: GREP_CAP - len(note)] + note
        return out

    def shell(command: str) -> dict:
        """Run a shell command in the target directory (cat, sed -n, ls, git, go build ...). 60s timeout,
        output capped. Use it to read code you need for evidence."""
        # ponytail: host exec without sandbox; run untrusted targets in Docker before scanning.
        try:
            p = subprocess.run(command, shell=True, cwd=target, capture_output=True, text=True, timeout=SHELL_TIMEOUT, check=False)
        except subprocess.TimeoutExpired:
            return err(f"timeout after {SHELL_TIMEOUT}s")
        except Exception as e:  # noqa: BLE001 — a tool never raises into the model
            return err(f"shell: {e}")
        out = (p.stdout + p.stderr)[:OUT_CAP]
        return {"exit_code": p.returncode, "output": out}

    def consult_domain(entity: str) -> dict:
        """Ask the domain consultant whether access to an entity is a hole or a business rule. Two sources, in
        order: the run's domain map built by the DomainModeler stage (owner field, business rules with refs
        'domain:<rule id>', roles, gaps — rule statements come from the target's own docs/tests, verify them in
        code), then, when there is no map or it does not know the entity, a grep of the entity's declaration and
        the ownership/role checks near it. Cite the returned ref ('domain:<entity>' or 'domain:<rule id>') in
        evidence — required by the gate for authz/IDOR findings."""
        dm = run.artifact("domain_map") if run is not None and hasattr(run, "artifact") else None
        if dm:
            try:
                answer = domain_consult(DomainMap.model_validate(dm), entity)
            except ValueError:
                answer = {"status": "error"}
            if answer.get("status") != "error":
                return {**answer, "source": "domain_map"}
        # ponytail: grep heuristic when the DomainModeler stage produced no map (or does not know the entity).
        q = shell_quote
        name = entity.split(".")[-1]
        decl = shell(f"rg -n -e {q(rf'(type|struct|class|def|func(tion)?)\s+{re.escape(name)}\b')} . || true")["output"]
        files = sorted({ln.split(":", 1)[0] for ln in decl.splitlines() if ":" in ln})
        checks = []
        for f in files:
            checks += shell(f"rg -n -e {q(r'UserID|user_id|owner|OwnerID|current_user|==\s*\S*id')} {q(f)} || true")["output"].splitlines()
        return {
            "ref": f"domain:{entity}",
            "declaration": decl[:2000],
            "owner_checks": checks[:50],
            "note": "heuristic — decide hole vs business rule from the code",
        }

    return [read_file, grep, shell, consult_domain]
