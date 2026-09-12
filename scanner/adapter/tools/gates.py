"""The two verdict gates: report_finding (Investigator) and disprove_finding (Critic).

A finding exists only if the gate accepted it: anchor exists, coordinates agree with the anchor, the required
consult reference is cited, and a confirmed verdict quotes a line really present at the anchor."""

from __future__ import annotations

from collections.abc import Callable

from scanner import core
from scanner.adapter.tools.common import err
from scanner.core import Finding


def _mismatch(name: str, got, want) -> str | None:
    if not got or not want or got == want:  # an anchor without the value (synthetic: no CWE) cannot disagree
        return None
    return f"{name} {got!r} does not match anchor's {want!r}"


def gate_finding(run, read: Callable[[str, int], str], draft: Finding) -> str | Finding:
    """Check `draft` (the model's request, coordinates optional) against its anchor; the refusal reason or the stored Finding."""
    if not draft.anchor_id:
        return "anchor_id is required — pick one from list_anchors"
    a = run.anchor(draft.anchor_id)
    if a is None:
        return f"unknown anchor_id {draft.anchor_id!r} — use ids from list_anchors"
    bad = [m for m in (_mismatch("cwe", draft.cwe, a.cwe), _mismatch("file", draft.file, a.file), _mismatch("line", draft.line, a.line)) if m]
    if bad:
        return "; ".join(bad) + "; coordinates come from the anchor — omit them or pick the right anchor_id"
    if not a.cwe and draft.cwe:  # synthetic anchors (entrypoint/threatmodel) carry no class: the model's CWE is recorded
        a = a.model_copy(update={"cwe": draft.cwe.strip().upper()})
    f = draft.model_copy(update={"cwe": a.cwe, "file": a.file, "line": a.line, "severity": draft.severity or a.severity})
    secret = a.cwe == "CWE-798"  # never re-leak the secret: compare and store redacted
    if secret:
        f.evidence = [core.redact_secrets(e) for e in f.evidence]
    if f.status != core.UNCERTAIN and (r := core.check_consulted(a, f.evidence)):
        return r
    if f.status == core.CONFIRMED:
        try:
            code = read(a.file, a.line)
        except Exception as e:  # noqa: BLE001
            return f"cannot read {a.file}:{a.line} to verify evidence: {e}"
        if secret:
            code = core.redact_secrets(code)
        quotes = [e.strip() for e in f.evidence if e.strip() and not core.is_consult_ref(e)]
        if not any(q in code for q in quotes):
            return f"evidence does not match the code at {a.file}:{a.line} — quote the lines exactly as read"
    if r := core.validate_finding(f):
        return r
    return run.report(f)


def report_finding_tool(run, read: Callable[[str, int], str]) -> Callable:
    def report_finding(  # ten flat parameters on purpose: this signature IS the ADK tool schema the model sees

        anchor_id: str,
        title: str,
        status: str,
        evidence: list[str],
        hypothesis_id: str = "",
        severity: str = "",
        confidence: float = 0.0,
        cwe: str = "",
        file: str = "",
        line: int = 0,
    ) -> dict:
        """Record a verdict on an anchor: confirmed, rejected or uncertain. anchor_id must come from
        list_anchors. 'confirmed' is accepted only with evidence — exact quotes of the code you read
        at the anchor. Dependency (osv/CVE/GHSA) and authz/IDOR anchors also require a consult
        reference in evidence: 'knowledge:<advisory id>' or 'domain:<entity>'. Findings without a
        real anchor, evidence or required consult are refused."""
        if 1 < confidence <= 100:
            confidence /= 100  # models answer "95" or "100.0" for a [0,1] scale; the gate reads it, not refuses it
        draft = Finding(anchor_id=anchor_id, hypothesis_id=hypothesis_id, cwe=cwe, file=file, line=line, title=title,
                        severity=severity, status=status, evidence=list(evidence or []), confidence=confidence)
        result = gate_finding(run, read, draft)
        if isinstance(result, str):
            run.log_gate(anchor_id, result)
            return err(f"report_finding: {result}")
        return result.model_dump()

    return report_finding


def disprove_finding_tool(run, found: Callable[[list[str]], bool]) -> Callable:
    def disprove_finding(finding_id: str, counter_evidence: list[str], reason: str) -> dict:
        """Downgrade a confirmed finding to uncertain because you found a counter-fact: a sanitizer or
        validator that dominates the sink, a framework protection, unreachability, or a parameterized
        call. counter_evidence: exact code lines you read anywhere in the target that carry the
        counter-fact (at least one must exist in the code); reason: one sentence. Refused when the
        finding is not confirmed or the quotes are not found in the code."""
        f = next((x for x in run.findings() if x.id == finding_id), None)
        if f is None:
            return err(f"unknown finding_id {finding_id!r} — use ids from list_findings")
        if f.status != core.CONFIRMED:
            return err(f"finding {finding_id} is {f.status}, only confirmed findings can be disproved")
        quotes = [q.strip() for q in counter_evidence or [] if q.strip()]
        if not quotes or not found(quotes):
            return err("counter_evidence is not found in the code — quote the lines exactly as read")
        upd = run.set_status(f.id, core.UNCERTAIN, [f"critic: {reason}", *quotes], f"critic disproved {f.id}: {reason}")
        return upd.model_dump() if upd else err("update failed")

    return disprove_finding
