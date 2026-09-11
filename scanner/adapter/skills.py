"""Skills: markdown playbooks per vulnerability class / analysis discipline (from Strix via git-agent3),
exposed to agents as `list_skills` / `load_skill`, plus the static CWE→skill map used to hint a Verifier."""

from __future__ import annotations

import re
from pathlib import Path

from scanner import core

_DIR = Path(__file__).resolve().parent.parent / "skills"

# ponytail: static map; add per-skill `cwes:` frontmatter if classes multiply
_BY_CWE = {
    "CWE-89": "sql-injection", "CWE-943": "nosql-injection", "CWE-78": "rce", "CWE-77": "argument-injection",
    "CWE-88": "argument-injection", "CWE-94": "rce", "CWE-95": "rce", "CWE-1336": "ssti", "CWE-79": "xss",
    "CWE-80": "xss", "CWE-918": "ssrf", "CWE-22": "path-traversal-lfi-rfi", "CWE-98": "path-traversal-lfi-rfi",
    "CWE-611": "xxe", "CWE-91": "xxe", "CWE-502": "insecure-deserialization", "CWE-601": "open-redirect",
    "CWE-352": "csrf", "CWE-915": "mass-assignment", "CWE-1321": "prototype-pollution", "CWE-362": "race-conditions",
    "CWE-434": "insecure-file-uploads", "CWE-200": "information-disclosure", "CWE-209": "information-disclosure",
    "CWE-532": "information-disclosure", "CWE-113": "header-injection", "CWE-644": "header-injection",
    "CWE-287": "authentication-jwt", "CWE-347": "authentication-jwt", "CWE-521": "weak-password-detection",
    "CWE-798": "weak-password-detection", "CWE-639": "authz-idor", "CWE-284": "authz-idor", "CWE-285": "authz-idor",
    "CWE-862": "broken-function-level-authorization", "CWE-863": "authz-idor", "CWE-840": "business-logic",
}
_BY_KIND = {"dependency": "dependency-advisory", "authz": "authz-idor", "secret": "weak-password-detection"}


def _read(path: Path) -> tuple[str, str, str]:
    text = path.read_text()
    m = re.match(r"---\n(.*?)\n---\n", text, re.DOTALL)
    fm = dict(re.findall(r"^(\w+):\s*(.*)$", m.group(1), re.MULTILINE)) if m else {}
    return fm.get("name", path.stem), fm.get("description", ""), text[m.end():].strip() if m else text


SKILLS: dict[str, tuple[str, str]] = {n: (d, b) for n, d, b in (_read(p) for p in sorted(_DIR.glob("*.md")))}


def skill_for(cwe: str = "", kind: str = "") -> str:
    """Skill name for a hypothesis: by kind first (dependency/authz/secret), then by CWE; "" if none."""
    if kind in _BY_KIND and not (kind == "authz" and cwe == "CWE-862"):
        return _BY_KIND[kind]
    if cwe in _BY_CWE:
        return _BY_CWE[cwe]
    return "authz-idor" if cwe in core.AUTHZ_CWES else ""


def list_skills(cwe: str = "", kind: str = "") -> dict:
    """List the available skills (name, description, cwes). Filter by a CWE (e.g. 'CWE-89') or a hypothesis
    kind (entry|sink|dependency|secret|authz) to get the one that applies; empty filters list all."""
    cwes: dict[str, list[str]] = {}
    for c, s in _BY_CWE.items():
        cwes.setdefault(s, []).append(c)
    want = skill_for(cwe, kind) if (cwe or kind) else ""
    return {"skills": [
        {"name": n, "description": d, "cwes": cwes.get(n, [])}
        for n, (d, _) in SKILLS.items() if not want or n == want
    ]}


def load_skill(name: str) -> dict:
    """Load a skill playbook (markdown) by name and follow it. Method skills: verifier-proof (what counts as
    proof and the report_finding gate), counterevidence (what does and does not rule a candidate out),
    severity-calibration, source-aware-discovery, authz-idor, dependency-advisory. Class skills:
    sql-injection, nosql-injection, xss, ssrf, ssti, rce, argument-injection, header-injection,
    path-traversal-lfi-rfi, xxe, insecure-deserialization, open-redirect, csrf, mass-assignment,
    prototype-pollution, race-conditions, insecure-file-uploads, information-disclosure,
    weak-password-detection, authentication-jwt, idor, broken-function-level-authorization,
    business-logic, llm-prompt-injection. Frameworks: django, fastapi, nestjs, nextjs."""
    if name not in SKILLS:
        return {"status": "error", "reason": f"unknown skill {name!r}; call list_skills"}
    d, body = SKILLS[name]
    return {"name": name, "description": d, "body": body}
