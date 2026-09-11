#!/usr/bin/env python3
"""ECC R&D: catalog the installed ECC plugin, diff it against the last snapshot, propose candidates.

    uv run python scripts/ecc_rnd.py            # report to stdout (first run = baseline, no novelties yet)
    uv run python scripts/ecc_rnd.py --write    # also save .claude/ecc-catalog.json and append docs/rnd/<date>.md
    uv run python scripts/ecc_rnd.py --selftest

stdlib only. Reads the plugin cache read-only; never touches settings or permissions.
"""

from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = ROOT / ".claude" / "ecc-catalog.json"
RND_DIR = ROOT / "docs" / "rnd"
# what this repo is made of — a description mentioning these is a candidate worth reading
KEYWORDS = ("adk", "agent", "pipeline", "security", "sast", "python", "lsp", "eval", "tracing", "sandbox",
            "tdd", "review", "harness", "orchestrat", "hook", "cost", "loop", "vulnerab", "memory")
KINDS = {"skills": "skills/*/SKILL.md", "agents": "agents/*.md", "commands": "commands/*.md"}


def ecc_root() -> Path:
    def is_plugin(d: str) -> bool:  # the real plugin, not ~/.claude (hooks set CLAUDE_PLUGIN_ROOT to it as a fallback)
        return Path(d, "skills").is_dir() and (Path(d, "VERSION").is_file() or Path(d, ".claude-plugin/plugin.json").is_file())

    env = os.environ.get("CLAUDE_PLUGIN_ROOT", "").strip()
    if env and is_plugin(env):
        return Path(env)
    cands = glob.glob(str(Path.home() / ".claude/plugins/cache/ecc/ecc/*")) + [str(Path.home() / ".claude/plugins/marketplaces/ecc")]
    cands = [c for c in cands if is_plugin(c)]
    if not cands:
        sys.exit("ECC plugin not found under ~/.claude/plugins (set CLAUDE_PLUGIN_ROOT)")
    return Path(max(cands, key=lambda c: [int(x) if x.isdigit() else -1 for x in re.split(r"[.\-]", Path(c).name)]))  # newest version dir


def version(root: Path) -> str:
    v = root / "VERSION"
    if v.is_file():
        return v.read_text().strip()
    try:
        return json.loads((root / ".claude-plugin" / "plugin.json").read_text()).get("version", "?")
    except (OSError, ValueError):
        return root.name


def describe(path: Path) -> tuple[str, str]:
    """(name, one-line description) from YAML frontmatter, else first heading."""
    text = path.read_text(errors="replace")
    name = path.parent.name if path.name == "SKILL.md" else path.stem
    desc = ""
    if text.startswith("---"):
        fm = text.split("---", 2)[1] if text.count("---") >= 2 else ""
        if m := re.search(r"^name:\s*(.+)$", fm, re.MULTILINE):
            name = m.group(1).strip().strip("\"'")
        if m := re.search(r"^description:\s*(.*)$", fm, re.MULTILINE):
            desc = m.group(1).strip()
            if desc in (">", "|", ">-", "|-", ""):  # block scalar: indented lines that follow
                desc = " ".join(ln.strip() for ln in fm[m.end():].splitlines() if ln.startswith((" ", "\t")) and ln.strip())
    if not desc and (m := re.search(r"^#\s+(.+)$", text, re.MULTILINE)):
        desc = m.group(1).strip()
    desc = " ".join(desc.strip().strip("\"'").split())
    return name, desc[:240]


def catalog(root: Path) -> dict:
    items: dict[str, dict[str, str]] = {}
    for kind, pattern in KINDS.items():
        items[kind] = {}
        for p in sorted(root.glob(pattern)):
            n, d = describe(p)
            items[kind][n] = d
    return {"version": version(root), "root": str(root), "taken": dt.datetime.now().astimezone().isoformat(timespec="seconds"), "items": items}


def diff(old: dict | None, new: dict) -> dict:
    out = {"new": [], "removed": [], "changed": []}
    if not old:
        return out
    for kind, cur in new["items"].items():
        prev = old.get("items", {}).get(kind, {})
        out["new"] += [f"{kind[:-1]} {n}: {d}" for n, d in cur.items() if n not in prev]
        out["removed"] += [f"{kind[:-1]} {n}" for n in prev if n not in cur]
        out["changed"] += [f"{kind[:-1]} {n}: {d}" for n, d in cur.items() if n in prev and prev[n] != d]
    return out


def used_names() -> set[str]:
    """ECC names this project already references (BOARD, README, project skills, memory)."""
    text = ""
    for p in [ROOT / "BOARD.md", ROOT / "README.md", *ROOT.glob(".claude/skills/*/SKILL.md"),
              *Path.home().glob(".claude/projects/*repo-agent2*/memory/*.md")]:
        try:
            text += p.read_text(errors="replace")
        except OSError:
            pass
    return set(re.findall(r"ecc:([a-z0-9-]+)", text)) | set(re.findall(r"`/([a-z0-9-]+)`", text))


def candidates(cat: dict, used: set[str]) -> list[tuple[int, str, str, str, bool]]:
    out = []
    for kind, items in cat["items"].items():
        for n, d in items.items():
            hay = f"{n} {d}".lower()
            score = sum(1 for k in KEYWORDS if k in hay)
            if score >= 2:
                out.append((score, kind[:-1], n, d, n in used))
    return sorted(out, key=lambda t: (-t[0], t[1], t[2]))


def report(cat: dict, d: dict, cands: list) -> str:
    n = {k: len(v) for k, v in cat["items"].items()}
    lines = [f"## ECC R&D — {cat['taken'][:10]} — ECC {cat['version']}",
             f"catalog: {n['skills']} skills, {n['agents']} agents, {n['commands']} commands (`{cat['root']}`)", "",
             "### Novelties"]
    if not any(d.values()):
        lines.append("_baseline (first snapshot) or no changes since the last snapshot_" if not SNAPSHOT.exists() or d == {"new": [], "removed": [], "changed": []} else "")
    for key in ("new", "removed", "changed"):
        for x in d[key]:
            lines.append(f"- {key}: {x}")
    lines += ["", "### Candidates for repo-agent2 (keyword score ≥ 2; `used` = already referenced here)"]
    for score, kind, name, desc, used in cands[:40]:
        lines.append(f"- [{score}] {kind} **{name}**{' (used)' if used else ''} — {desc[:150]}")
    return "\n".join(lines) + "\n"


def selftest() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as t:
        p = Path(t, "SKILL.md")
        p.write_text('---\nname: foo-bar\ndescription: "Does X. Use when Y."\n---\n# Foo\n')
        assert describe(p) == ("foo-bar", "Does X. Use when Y.")
        p.write_text("---\nname: blk\ndescription: >\n  first line\n  second\n---\n")
        assert describe(p) == ("blk", "first line second")
        p.write_text("# Just Heading\nbody\n")
        assert describe(Path(t, "SKILL.md")) == (Path(t).name, "Just Heading")
    old = {"items": {"skills": {"a": "1", "b": "2"}}}
    new = {"items": {"skills": {"a": "1", "b": "changed", "c": "3"}}}
    assert diff(old, new) == {"new": ["skill c: 3"], "removed": [], "changed": ["skill b: changed"]}
    assert diff(None, new) == {"new": [], "removed": [], "changed": []}
    assert candidates({"items": {"skills": {"x": "python agent eval", "y": "cooking"}}}, {"x"})[0][:3] == (3, "skill", "x")
    print("ecc_rnd selftest ok")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--write", action="store_true", help="save the snapshot and append the report to docs/rnd/<date>.md")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        selftest()
        return 0
    cat = catalog(ecc_root())
    old = json.loads(SNAPSHOT.read_text()) if SNAPSHOT.is_file() else None
    text = report(cat, diff(old, cat), candidates(cat, used_names()))
    print(text)
    if a.write:
        SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
        SNAPSHOT.write_text(json.dumps(cat, indent=1, ensure_ascii=False))
        RND_DIR.mkdir(parents=True, exist_ok=True)
        out = RND_DIR / f"{cat['taken'][:10]}.md"
        with out.open("a") as fh:
            fh.write(("\n" if out.exists() and out.stat().st_size else "") + text)
        print(f"snapshot → {SNAPSHOT.relative_to(ROOT)}, report → {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
