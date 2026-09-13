"""report_finding: the Investigator's verdict gate (see gates.finding.gate_finding)."""

from __future__ import annotations

from scanner.adapter.tools.common import err
from scanner.adapter.tools.context import ToolContext
from scanner.adapter.tools.gates.finding import gate_finding
from scanner.core import Finding


def make(ctx: ToolContext):
    run, read = ctx.run, ctx.reader

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
