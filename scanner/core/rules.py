"""Pure domain rules: ids, severity, candidate selection, anchor merging, the grounding gate,
finding validation, consult requirements, secret redaction."""

from __future__ import annotations

import hashlib
import html
import re

from scanner.core.types import (
    AUTHZ_CWES,
    CONFIRMED,
    EVIDENCE_DOMAIN,
    EVIDENCE_KNOWLEDGE,
    EVIDENCE_OWASP,
    KINDS,
    SEVERITY_RANK,
    STATUSES,
    TAINT_CWES,
    Anchor,
    Candidate,
    Finding,
    Hypothesis,
)


def new_anchor_id(tool: str, rule: str, file: str, line: int) -> str:
    """Stable id for one scanner signal: same (tool, rule, file, line) across runs."""
    h = hashlib.sha1(f"{tool}|{rule}|{file}|{line}".encode()).hexdigest()  # not crypto: stable short id
    return "a_" + h[:12]

def norm_severity(s: str) -> str:
    s = (s or "").strip().lower()
    if s == "critical":
        return "critical"
    if s in ("error", "high"):
        return "high"
    if s in ("warning", "medium", "moderate"):
        return "medium"
    if s == "low":
        return "low"
    return "info"

def select_candidates(
    all_: list[Candidate], kind: str = "", cwe: str = "", severity: str = "", limit: int = 0
) -> list[Candidate]:
    """Filter + stable severity-first sort. Core of list_candidates and RoundInput."""
    out = [
        c
        for c in all_
        if (not kind or c.kind == kind)
        and (not cwe or c.cwe == cwe)
        and (not severity or c.severity == severity)
    ]
    out.sort(key=lambda c: -SEVERITY_RANK.get(c.severity, 0))
    return out[:limit] if limit > 0 else out

def merge_duplicates(anchors: list[Anchor]) -> list[Anchor]:
    """Merge signals on the same (file, line, cwe) from different rules/tools into one.

    osv and cwe-less anchors are never merged. Order = first appearance.
    """
    groups: dict[tuple[str, int, str], list[Anchor]] = {}
    order: list[tuple[str, int, str] | Anchor] = []
    for a in anchors:
        if a.tool == "osv" or not a.cwe:
            order.append(a)
            continue
        k = (a.file, a.line, a.cwe)
        if k not in groups:
            groups[k] = []
            order.append(k)
        groups[k].append(a)
    out: list[Anchor] = []
    for item in order:
        if isinstance(item, Anchor):
            out.append(item)
            continue
        g = sorted(groups[item], key=lambda a: (a.rule_id, a.tool))
        m = g[0].model_copy(deep=True)
        if len(g) > 1:
            for a in g:
                if SEVERITY_RANK.get(a.severity, 0) > SEVERITY_RANK.get(m.severity, 0):
                    m.severity = a.severity
                m.snippet = m.snippet or a.snippet
                if a.tool not in m.tools:
                    m.tools.append(a.tool)
                if a.rule_id not in m.rule_ids:
                    m.rule_ids.append(a.rule_id)
        out.append(m)
    return out

def ground_hypothesis(h: Hypothesis, has_anchor, has_symbol) -> str | None:
    """Grounding gate (dispatch). Returns None if OK, else the refusal reason."""
    if not h.claim:
        return "claim is required"
    if h.kind not in KINDS:
        return f"unknown kind {h.kind!r} — use entry|sink|dependency|secret|authz"
    if not h.anchor_id and not h.symbol:
        return "no grounding: need anchor_id (from list_candidates) or an existing symbol"
    if h.anchor_id:
        if not has_anchor(h.anchor_id):
            return f"unknown anchor_id {h.anchor_id!r} — use ids from list_candidates/list_anchors"
    elif not has_symbol(h.symbol):
        return f"symbol {h.symbol!r} not found in the index — ground on a real symbol or an anchor_id"
    if h.kind == "dependency" and h.consult != "knowledge":
        return "dependency hypotheses need consult=knowledge"
    if h.kind == "authz" and h.consult != "domain":
        return "authz hypotheses need consult=domain"
    return None

def validate_finding(f: Finding) -> str | None:
    """Anti-hallucination gate: confirmed needs an anchor and evidence."""
    if not f.title.strip():
        return "finding: title is required"
    if f.status not in STATUSES:
        return f"finding: status must be confirmed|rejected|uncertain, got {f.status!r}"
    if not 0 <= f.confidence <= 1:
        return f"finding: confidence must be in [0,1], got {f.confidence}"
    if f.status == CONFIRMED:
        if not f.anchor_id.strip():
            return "finding: confirmed requires anchor_id (no anchor — no finding)"
        if not any(e.strip() for e in f.evidence):
            return "finding: confirmed requires non-empty evidence (quote the code you read)"
    return None

def consult_required(cwe: str, tool: str = "", rule_id: str = "") -> tuple[bool, bool]:
    """(knowledge, domain): the consult a class needs before a verdict. Single source for gate and router."""
    rule, cwe = rule_id.upper(), cwe.strip().upper()
    return tool == "osv" or rule.startswith(("CVE-", "GHSA-")), cwe in AUTHZ_CWES


def required_consults(a: Anchor) -> tuple[bool, bool, str]:
    """(knowledge, domain, reason): which consult an anchor's class needs before a verdict."""
    cwe = a.cwe.strip().upper()
    knowledge, domain = consult_required(cwe, a.tool, a.rule_id)
    reasons = []
    if knowledge:
        reasons.append("dependency advisory")
    if domain:
        reasons.append(f"authz/IDOR class ({cwe})")
    elif cwe in TAINT_CWES and not knowledge:
        reasons.append(f"taint class ({cwe}): proven by code path")
    return knowledge, domain, "; ".join(reasons) or "no consult rule for this class"

_QUOTE_PREFIX = re.compile(r"^[\w./\\-]+:\d+:\s*")


def bare_quote(evidence: str) -> str:
    """Evidence line → the code text to match: a leading `path:line:` prefix (the shape agents are told to use)
    and HTML entities (some models emit `=&gt;`) are removed, whitespace trimmed."""
    return html.unescape(_QUOTE_PREFIX.sub("", evidence.strip())).strip()


_SECRET = re.compile(r"[A-Za-z0-9_\-+/=]{16,}")

def redact_secrets(text: str) -> str:
    """Mask long tokens (keys, passwords): a CWE-798 finding must never re-leak the secret it found."""
    return _SECRET.sub(lambda m: f"{m.group(0)[:4]}…[{len(m.group(0))}]", text)

def is_consult_ref(e: str) -> bool:
    return e.strip().lower().startswith((EVIDENCE_KNOWLEDGE, EVIDENCE_DOMAIN, EVIDENCE_OWASP))

def check_consulted(a: Anchor, evidence: list[str]) -> str | None:
    """Verdict on a consult-class anchor must cite 'knowledge:<id>' / 'domain:<entity>'."""
    knowledge, domain, reason = required_consults(a)
    low = [e.strip().lower() for e in evidence]
    missing = []
    if knowledge and not any(e.startswith(EVIDENCE_KNOWLEDGE) for e in low):
        missing.append("an osv_query ref (evidence knowledge:<advisory id>)")
    if domain and not any(e.startswith(EVIDENCE_DOMAIN) for e in low):
        missing.append("the ownership check you read (evidence domain:<entity>)")
    if not missing:
        return None
    return f"finding is unproven: {reason}; missing {', '.join(missing)}"
