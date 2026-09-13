"""consult_domain: the run's domain map (DomainModeler artifact) first, a grep heuristic when it has no answer."""

from __future__ import annotations

import re

from scanner.adapter.domain import consult
from scanner.adapter.tools.code.shell import run_shell
from scanner.adapter.tools.common import shell_quote
from scanner.adapter.tools.context import ToolContext
from scanner.core.domain import DomainMap


def make(ctx: ToolContext):
    run, target = ctx.run, ctx.target

    def consult_domain(entity: str) -> dict:
        """Ask the domain consultant whether access to an entity is a hole or a business rule. Two sources, in
        order: the run's domain map built by the DomainModeler stage (owner field, business rules with refs
        'domain:<rule id>', roles, gaps — rule statements come from the target's own docs/tests, verify them in
        code), then, when there is no map or it does not know the entity, a grep of the entity's declaration and
        the ownership/role checks near it. Cite the returned ref ('domain:<entity>' or 'domain:<rule id>') in
        evidence — required by the gate for authz/IDOR findings."""
        dm = run.artifact("domain_map") if run is not None and hasattr(run, "artifact") else None
        if dm:
            try:
                answer = consult(DomainMap.model_validate(dm), entity)
            except ValueError:
                answer = {"status": "error"}
            if answer.get("status") != "error":
                return {**answer, "source": "domain_map"}
        # ponytail: grep heuristic when the DomainModeler stage produced no map (or does not know the entity).
        q = shell_quote
        name = entity.split(".")[-1]
        decl = run_shell(target, f"rg -n -e {q(rf'(type|struct|class|def|func(tion)?)\s+{re.escape(name)}\b')} . || true")["output"]
        files = sorted({ln.split(":", 1)[0] for ln in decl.splitlines() if ":" in ln})
        checks = []
        for f in files:
            checks += run_shell(target, f"rg -n -e {q(r'UserID|user_id|owner|OwnerID|current_user|==\s*\S*id')} {q(f)} || true")["output"].splitlines()
        return {
            "ref": f"domain:{entity}",
            "declaration": decl[:2000],
            "owner_checks": checks[:50],
            "note": "heuristic — decide hole vs business rule from the code",
        }

    return consult_domain


def map_only(run):
    """consult_domain that answers only from the stored domain_map artifact (no grep fallback) — the eval harness
    swaps it in to grade the DomainModeler's map on its own."""

    def consult_domain(question: str) -> dict:
        """Ask the domain map about an entity or a rule: returns the entity's owner field, the business
        rules that apply to it (with refs 'domain:<rule id>'), the roles and guards around it and known gaps.
        Cite the returned ref ('domain:<entity>' or 'domain:<rule id>') in evidence — required by the gate
        for authz/IDOR findings. Ask with an entity name ("Order") or a rule id ("r1"). Rule statements were
        derived from the target's own docs/tests: treat them as claims to verify in code, not as verdicts."""
        raw = run.artifact("domain_map")
        if not raw:
            return {"status": "error", "reason": "no domain map for this run (DomainModeler stage did not produce one)"}
        try:
            dm = DomainMap.model_validate(raw)
        except ValueError as e:
            return {"status": "error", "reason": f"domain map invalid: {e}"}
        return consult(dm, question)

    return consult_domain
