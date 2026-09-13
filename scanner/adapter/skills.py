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


def _read(path: Path) -> tuple[str, dict, str]:
    text = path.read_text(encoding="utf-8")
    m = re.match(r"---\n(.*?)\n---\n", text, re.DOTALL)
    fm = dict(re.findall(r"^(\w+):\s*(.*)$", m.group(1), re.MULTILINE)) if m else {}
    cwes = [c.strip().upper() for c in re.split(r"[,\s]+", fm.get("cwes", "").strip("[]")) if c.strip()]
    meta = {"description": fm.get("description", ""), "cwes": cwes, "wstg": fm.get("wstg", "").strip(),
            "top10": fm.get("top10", "").strip(), "role": fm.get("role", "").strip()}
    return fm.get("name", path.stem), meta, text[m.end():].strip() if m else text


META: dict[str, dict] = {}
SKILLS: dict[str, tuple[str, str]] = {}
for _n, _m, _b in (_read(p) for p in sorted(_DIR.glob("*.md"))):
    META[_n], SKILLS[_n] = _m, (_m["description"], _b)

_ANALYSIS = {"entry": "source-aware-discovery", "sink": "verifier-proof", "authz": "authz-idor",
             "dependency": "dependency-advisory", "secret": "information-disclosure"}


def skill_for(cwe: str = "", kind: str = "") -> str:
    """Skill name for a hypothesis: by kind first (dependency/authz/secret), then by CWE; "" if none."""
    if kind in _BY_KIND and not (kind == "authz" and cwe == "CWE-862"):
        return _BY_KIND[kind]
    if cwe in _BY_CWE:
        return _BY_CWE[cwe]
    return "authz-idor" if cwe in core.AUTHZ_CWES else ""


def _wstg_skill(cwe: str) -> str:
    """The WSTG verdict skill for a CWE: by owasp's CWE→WSTG map first, then by the skills' own cwes lists."""
    from scanner.adapter import owasp  # adapter → adapter

    wid = owasp.consult(cwe).get("wstg_id", "") if cwe else ""
    for n, m in META.items():
        if n.startswith("wstg-") and ((wid and m["wstg"] == wid) or cwe in m["cwes"]):
            return n
    return ""


def _control_skill(cwe: str) -> str:
    return next((n for n, m in META.items() if m["role"] == "critic" and cwe in m["cwes"]), "")


def skills_for(cwe: str = "", kind: str = "", role: str = "investigate") -> list[str]:
    """Ordered skill list for one hypothesis/finding: investigators get [WSTG verdict skill, class skill,
    analysis skill]; critics get [control skill, counterevidence]. Names only; each exists in SKILLS."""
    if role == "critique":
        out = [_control_skill(cwe), "counterevidence"]
    else:
        out = [_wstg_skill(cwe), skill_for(cwe, kind), _ANALYSIS.get(kind, "verifier-proof" if cwe else "")]
    seen: list[str] = []
    for n in out:
        if n and n in SKILLS and n not in seen:
            seen.append(n)
    return seen


def list_skills(cwe: str = "", kind: str = "", role: str = "") -> dict:
    """List the available skills (name, description, cwes, wstg, role). Filter by a CWE (e.g. 'CWE-89'), a
    hypothesis kind (entry|sink|dependency|secret|authz) and/or role ('critique' → control skills) to get the
    ones that apply; empty filters list all."""
    cwes_of: dict[str, list[str]] = {n: list(m["cwes"]) for n, m in META.items()}
    for c, s in _BY_CWE.items():
        if c not in cwes_of.setdefault(s, []):
            cwes_of[s].append(c)
    if cwe or kind or role:
        want = set(skills_for(cwe, kind, role or "investigate"))
        if cwe and not role:
            want |= {n for n, m in META.items() if cwe in m["cwes"] and m["role"] != "critic"}
    else:
        want = set(SKILLS)
    return {"skills": [
        {"name": n, "description": d, "cwes": cwes_of.get(n, []), "wstg": META[n]["wstg"], "role": META[n]["role"] or "investigate"}
        for n, (d, _) in SKILLS.items() if n in want
    ]}


def load_skill(name: str) -> dict:
    """Load a skill playbook (markdown) by name and follow it. Your payload lists the ones for this item
    (`skills`). Groups — analysis: verifier-proof, counterevidence, severity-calibration,
    source-aware-discovery, authz-idor, dependency-advisory. Class: sql-injection, nosql-injection, xss, ssrf,
    ssti, rce, argument-injection, header-injection, path-traversal-lfi-rfi, xxe, insecure-deserialization,
    open-redirect, csrf, mass-assignment, prototype-pollution, race-conditions, insecure-file-uploads,
    information-disclosure, weak-password-detection, authentication-jwt, idor,
    broken-function-level-authorization, business-logic, llm-prompt-injection. Frameworks: django, fastapi,
    nestjs, nextjs. WSTG verdict skills (Investigator): wstg-<category>-<nn>-<slug>, e.g. wstg-injt-05-sqli,
    wstg-athz-04-idor, wstg-injt-19-ssrf, wstg-sess-05-csrf, wstg-cryp-04-weak-crypto — call list_skills(cwe=…).
    Control skills (Critic): control-parameterization, control-output-encoding, control-path-traversal,
    control-csrf, control-ssrf-allowlist, control-deserialization, control-upload-validation,
    control-authz-ownership, control-redirect-allowlist, control-password-hashing, control-secrets-management,
    control-xxe."""
    if name not in SKILLS:
        return {"status": "error", "reason": f"unknown skill {name!r}; call list_skills"}
    d, body = SKILLS[name]
    return {"name": name, "description": d, "body": body}
