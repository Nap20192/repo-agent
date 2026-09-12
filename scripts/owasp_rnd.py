#!/usr/bin/env python3
"""OWASP R&D: inventory the local OWASP corpora (WSTG, Cheat Sheets, Top 10 2021, ASVS 5.0), diff them
against the last snapshot ("Novelties") and run a gap analysis against this scanner's own maps, skills
and the CWEs it actually emits.

    uv run python scripts/owasp_rnd.py               # print the report
    uv run python scripts/owasp_rnd.py --write       # also save .claude/owasp-catalog.json, append docs/rnd/owasp-<date>.md
    OWASP_REPOS=~/tmp/repos (default) or --repos DIR — where owasp-wstg / owasp-CheatSheetSeries / owasp-Top10 / owasp-ASVS live.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = ROOT / ".claude" / "owasp-catalog.json"
EMPTY = {"wstg": {}, "wstg_docs": {}, "cheatsheets": {}, "top10": {}, "asvs": {}}

# --- inventory ---------------------------------------------------------------


def _wstg_tests(node, out: dict, category: str = "") -> None:
    if isinstance(node, dict):
        cat = node.get("id", category) if isinstance(node.get("id"), str) and "tests" in node else category
        if isinstance(node.get("id"), str) and node["id"].startswith("WSTG-") and "name" in node:
            out[node["id"]] = {"name": node.get("name", ""), "objectives": list(node.get("objectives") or []),
                               "reference": node.get("reference", ""), "category": category}
            return
        for v in node.values():
            _wstg_tests(v, out, cat)
    elif isinstance(node, list):
        for v in node:
            _wstg_tests(v, out, category)


def inventory(repos: Path) -> dict:
    """Everything we know about the corpora; missing repos simply yield empty sections."""
    repos = Path(repos).expanduser()
    inv = {k: {} for k in EMPTY}
    ck = repos / "owasp-wstg" / "checklists" / "checklist.json"
    if ck.is_file():
        _wstg_tests(json.loads(ck.read_text()), inv["wstg"])
    docs = repos / "owasp-wstg" / "document" / "4-Web_Application_Security_Testing"
    if docs.is_dir():
        inv["wstg_docs"] = {d.name: len(list(d.glob("*.md"))) for d in sorted(docs.iterdir()) if d.is_dir()}
    for p in sorted((repos / "owasp-CheatSheetSeries" / "cheatsheets").glob("*.md")):
        first = next((ln.lstrip("# ").strip() for ln in p.read_text(errors="replace").splitlines() if ln.startswith("#")), p.stem)
        inv["cheatsheets"][p.stem] = {"title": first, "size": p.stat().st_size}
    for p in sorted((repos / "owasp-Top10" / "2021" / "docs" / "en").glob("A0*.md")):
        text = p.read_text(errors="replace")
        m = re.search(r"^#\s*(A\d\d:2021)\s*[–-]\s*(.+)$", text, re.MULTILINE)
        if not m:
            continue
        tail = text.split("## List of Mapped CWEs", 1)[1] if "## List of Mapped CWEs" in text else ""
        inv["top10"][m.group(1)] = {"name": m.group(2).strip(), "cwes": re.findall(r"\[(CWE-\d+)", tail)}
    for p in sorted((repos / "owasp-ASVS" / "5.0" / "en").glob("0x*.md")):
        chapter = ""
        for ln in p.read_text(errors="replace").splitlines():
            if ln.startswith("# V"):
                chapter = ln.lstrip("# ").strip()
            elif m := re.match(r"\|\s*\*\*(\d+\.\d+\.\d+)\*\*\s*\|(.+?)\|\s*(\d)\s*\|", ln):
                inv["asvs"][m.group(1)] = {"chapter": chapter, "level": int(m.group(3)), "text": m.group(2).strip()}
    return inv


# --- our side ----------------------------------------------------------------


def ours() -> dict:
    """What this scanner maps, knows and emits: owasp.py tables, skills, and CWEs seen in State anchors."""
    sys.path.insert(0, str(ROOT))
    from scanner.adapter import (
        owasp,
        skills,
    )

    anchor_cwes: dict[str, int] = {}
    db = ROOT / ".state" / "state.db"
    if db.is_file():
        try:
            for cwe, n in sqlite3.connect(db).execute("SELECT json_extract(json,'$.cwe'), COUNT(*) FROM anchors GROUP BY 1"):
                anchor_cwes[cwe or ""] = n
        except sqlite3.Error:
            pass
    return {
        "wstg_map": {c: w for c, (w, _) in owasp._WSTG.items()},
        "cheat_map": dict(owasp._CHEAT),
        "top10_map": {c: tid for tid, (_, cwes) in owasp._TOP10.items() for c in cwes},
        "skill_cwes": set(skills._BY_CWE),
        "skill_wstg": {m.get("wstg", "") for m in getattr(skills, "META", {}).values() if m.get("wstg")},
        "skills": {n: d for n, (d, _) in skills.SKILLS.items()},
        "anchor_cwes": anchor_cwes,
    }


def gaps(inv: dict, o: dict) -> dict:
    wstg_by_cwe = o["wstg_map"]
    covered_wstg = {wstg_by_cwe[c] for c in o["skill_cwes"] if c in wstg_by_cwe} | set(o.get("skill_wstg", ()))
    # ponytail: 4-char stems ("auth" ⊂ authentication/authorization) instead of a real ASVS↔CWE map; vendor one when needed
    skill_words = {w[:4] for n, d in o["skills"].items() for w in re.findall(r"[a-z]{4,}", (n + " " + d).lower())}
    asvs_chapters = sorted({r["chapter"] for r in inv["asvs"].values() if r["chapter"]})
    return {
        "anchors_no_wstg": sorted(((c, n) for c, n in o["anchor_cwes"].items() if c and c not in wstg_by_cwe), key=lambda x: -x[1]),
        "wstg_no_skill": sorted(t for t in inv["wstg"] if t not in covered_wstg),
        "cheat_missing": sorted({s for s in o["cheat_map"].values() if inv["cheatsheets"] and s not in inv["cheatsheets"]}),
        "cheat_available": len(inv["cheatsheets"]),
        "top10_disagree": sorted((c, tid) for c, tid in o["top10_map"].items() if tid in inv["top10"] and c not in inv["top10"][tid]["cwes"]),
        "asvs_zero": [ch for ch in asvs_chapters if not ({w[:4] for w in re.findall(r"[a-z]{4,}", ch.lower())} & skill_words)],
    }


# --- novelties / report ------------------------------------------------------


def _today() -> str:
    return dt.datetime.now(tz=dt.UTC).astimezone().date().isoformat()


def diff(old: dict | None, new: dict) -> dict:
    """Novelties since the last snapshot; {} on the baseline run (no snapshot yet)."""
    out = {}
    if old is None:
        return out
    for k in ("wstg", "cheatsheets", "top10", "asvs"):
        a, b = set((old or {}).get(k, {})), set(new.get(k, {}))
        out[k] = {"new": sorted(b - a), "removed": sorted(a - b)}
    return out


def report(inv: dict, d: dict, g: dict) -> str:
    L = [f"# OWASP R&D — {_today()}", "",
         (f"Inventory: WSTG tests {len(inv['wstg'])} in {len(inv['wstg_docs'])} categories, cheat sheets {len(inv['cheatsheets'])}, "
          f"Top 10 categories {len(inv['top10'])}, ASVS requirements {len(inv['asvs'])}."), "", "## Novelties", ""]
    if not d or not any(v["new"] or v["removed"] for v in d.values()):
        L.append("_baseline snapshot or no changes since the last snapshot_")
    for k, v in d.items():
        for kind in ("new", "removed"):
            for item in v[kind]:
                L.append(f"- {k} {kind}: `{item}`")
    L += ["", "## Gaps", "", "### CWEs with anchors but no WSTG map", "", "| CWE | anchors |", "|---|---|"]
    L += [f"| {c} | {n} |" for c, n in g["anchors_no_wstg"]] or ["| — | — |"]
    L += ["", f"### WSTG tests with no skill ({len(g['wstg_no_skill'])} of {len(inv['wstg'])})", ""]
    L += [f"- `{t}` {inv['wstg'][t]['name']}" for t in g["wstg_no_skill"][:60]]
    if len(g["wstg_no_skill"]) > 60:
        L.append(f"- … {len(g['wstg_no_skill']) - 60} more")
    L += ["", f"### Cheat sheets: referenced but missing in the corpus ({g['cheat_available']} available)", ""]
    L += [f"- {s}" for s in g["cheat_missing"]] or ["- none"]
    L += ["", "### Top 10 map entries that disagree with the official CWE lists", "", "| CWE | our category |", "|---|---|"]
    L += [f"| {c} | {t} |" for c, t in g["top10_disagree"]] or ["| — | — |"]
    L += ["", "### ASVS chapters with zero skill coverage", "", "| chapter |", "|---|"]
    L += [f"| {ch} |" for ch in g["asvs_zero"]] or ["| — |"]
    return "\n".join(L) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repos", default=os.environ.get("OWASP_REPOS", "~/tmp/repos"))
    ap.add_argument("--write", action="store_true", help="save the snapshot and append the report to docs/rnd/owasp-<date>.md")
    a = ap.parse_args(argv)
    inv = inventory(Path(a.repos))
    old = json.loads(SNAPSHOT.read_text()) if SNAPSHOT.is_file() else None
    md = report(inv, diff(old, inv), gaps(inv, ours()))
    print(md)
    if a.write:
        SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
        SNAPSHOT.write_text(json.dumps(inv, ensure_ascii=False, indent=0))
        out = ROOT / "docs" / "rnd" / f"owasp-{_today()}.md"
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("a") as fh:
            fh.write(md)
        print(f"snapshot → {SNAPSHOT.relative_to(ROOT)}, report → {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
