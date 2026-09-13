"""disprove_finding: the Critic's gate — a confirmed finding becomes uncertain only with a counter-quote from the code."""

from __future__ import annotations

from scanner import core
from scanner.adapter.tools.common import err
from scanner.adapter.tools.context import ToolContext


def make(ctx: ToolContext):
    run, found = ctx.run, ctx.in_target

    def disprove_finding(finding_id: str, counter_evidence: list[str], reason: str) -> dict:
        """Downgrade a confirmed finding to uncertain because you found a counter-fact: a sanitizer or
        validator that dominates the sink, a framework protection, unreachability, or a parameterized
        call. counter_evidence: exact code lines you read anywhere in the target that carry the
        counter-fact (at least one must exist in the code); reason: one sentence. Refused when the
        finding is not confirmed or the quotes are not found in the code."""
        f = next((x for x in run.findings() if x.id == finding_id), None)
        if f is None:
            return err(f"unknown finding_id {finding_id!r} — use the id of the finding in your payload")
        if f.status != core.CONFIRMED:
            return err(f"finding {finding_id} is {f.status}, only confirmed findings can be disproved")
        quotes = [q.strip() for q in counter_evidence or [] if q.strip()]
        if not quotes or not found(quotes):
            return err("counter_evidence is not found in the code — quote the lines exactly as read")
        upd = run.set_status(f.id, core.UNCERTAIN, [f"critic: {reason}", *quotes], f"critic disproved {f.id}: {reason}")
        return upd.model_dump() if upd else err("update failed")

    return disprove_finding
