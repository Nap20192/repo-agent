"""gate_finding: the pure check behind report_finding — the refusal reason or the stored Finding."""

from __future__ import annotations

from collections.abc import Callable

from scanner import core
from scanner.core import Anchor, Finding


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
    if a.tool in core.SYNTHETIC_TOOLS and draft.file and draft.line and (draft.file, draft.line) != (a.file, a.line):
        # Discovery (Shannon): a baseline/threat hypothesis found something elsewhere. The quote check at the
        # reported location is the real gate; a passing quote mints an "investigator" anchor so every finding
        # still has exactly one anchor.
        if draft.status != core.CONFIRMED or not draft.cwe:
            return "an off-anchor report must be a confirmed finding with a cwe — rejections belong in your Dossier"
        try:
            code = read(draft.file, draft.line)
        except Exception as e:  # noqa: BLE001
            return f"cannot read {draft.file}:{draft.line} to verify evidence: {e}"
        if not any(q and q in code for q in (core.bare_quote(e) for e in draft.evidence if not core.is_consult_ref(e))):
            return f"evidence does not match the code at {draft.file}:{draft.line} — quote the lines exactly as read"
        cwe = draft.cwe.strip().upper()
        a = Anchor(id=core.new_anchor_id("investigator", cwe, draft.file, draft.line), tool="investigator", rule_id=a.id,
                   cwe=cwe, severity=draft.severity or "medium", file=draft.file, line=draft.line,
                   message=f"discovered from {a.tool} anchor {a.id}")
        run.save_anchors([a])
        draft = draft.model_copy(update={"anchor_id": a.id})
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
        quotes = [core.bare_quote(e) for e in f.evidence if e.strip() and not core.is_consult_ref(e)]
        if not any(q and q in code for q in quotes):
            return f"evidence does not match the code at {a.file}:{a.line} — quote the lines exactly as read"
    if r := core.validate_finding(f):
        return r
    return run.report(f)
