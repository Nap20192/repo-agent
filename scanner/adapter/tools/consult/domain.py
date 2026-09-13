"""domain_map: the run's domain map (the DomainModeler's artifact) — the Domain consultant's own source of truth."""

from __future__ import annotations

from scanner.adapter.domain import consult
from scanner.adapter.tools.context import ToolContext
from scanner.core.domain import DomainMap


def make(ctx: ToolContext):
    run = ctx.run

    def domain_map(question: str) -> dict:
        """Ask the run's domain map (built by the DomainModeler stage) about an entity or a rule: the entity's owner
        field, the business rules that apply to it (refs 'domain:<rule id>'), the roles and guards around it, known
        gaps. Ask with an entity name ("Order") or a rule id ("r1"). Rule statements were derived from the target's
        own docs/tests: treat them as claims to verify in code, not as verdicts. An error means there is no map (or it
        does not know the entity): fall back to grep / read_file on the declaration and the checks around it."""
        raw = run.artifact("domain_map") if run is not None and hasattr(run, "artifact") else None
        if not raw:
            return {"status": "error", "reason": "no domain map for this run (DomainModeler stage did not produce one)"}
        try:
            dm = DomainMap.model_validate(raw)
        except ValueError as e:
            return {"status": "error", "reason": f"domain map invalid: {e}"}
        return consult(dm, question)

    return domain_map
