"""DomainModeler agent + the consult_domain tool over the stored domain_map artifact."""

from __future__ import annotations

from collections.abc import Callable

from google.adk.agents import LlmAgent

from scanner.adapter.domain import consult
from scanner.app.callbacks import budget_callback, log_tools_callback
from scanner.app.instructions import OPERATING_PRINCIPLES
from scanner.core.domain import DomainMap

DOMAIN_MODELER_INSTRUCTION = OPERATING_PRINCIPLES + """

You are the DomainModeler. From the ArchitectureModel and the deterministic domain skeleton (JSON appended
below: entities with fields and owner-field candidates, access guards with the handlers they wrap, rule
candidates quoted from docs/tests/handlers) you produce the DomainMap every later stage cites: who owns what,
which roles reach which entry points, and the business rules the code must enforce.

Grounding gate (hard): every entity keeps the `symbol` of its struct/model (confirm with lsp_symbols or grep
when unsure); every rule carries the `symbol` that enforces it (or the handler that should) and `evidence`
file:line refs you read. A rule you cannot ground goes to `gaps` as text, never to `rules`. Fail closed:
when the owner field is ambiguous, leave it empty and note it in `gaps`.

Produce the DomainMap:
1. entities[]: {name, fields, owner_field, symbol, file, line, queries} — copy from the skeleton, fix names.
2. roles[]: {name, guards, entries} — derived from guards (login_required → "authenticated", isAdmin → "admin",
   none → "anonymous") and the entry points each role reaches.
3. rules[]: {id "r<n>", statement (one falsifiable sentence: "Order is visible only to Order.UserID"),
   entity, symbol, evidence}. Turn every rule candidate into a rule or a gap.
4. gaps[]: entities without an owner or without rules, handlers touching owned entities with no check.

Answer with the DomainMap as JSON only: {"entities":[...],"roles":[...],"rules":[...],"gaps":[...],"notes":[...]}"""


def new_domain_modeler(model, tools: list, max_calls: int = 12) -> LlmAgent:
    return LlmAgent(
        name="domain_modeler", description="turns the domain skeleton + ArchitectureModel into grounded business rules",
        model=model, instruction=DOMAIN_MODELER_INSTRUCTION, tools=tools, include_contents="none",
        before_model_callback=budget_callback(max_calls, per_branch=True), before_tool_callback=log_tools_callback,
    )


def make_consult_domain(run, index=None) -> Callable[[str], dict]:
    """Tool factory: consult_domain answers deterministically from the run's `domain_map` artifact."""

    def consult_domain(question: str) -> dict:
        """Ask the domain map about an entity or a rule: returns the entity's owner field, the business
        rules that apply to it (with refs 'domain:<rule id>'), the roles and guards around it and known gaps.
        Cite the returned ref ('domain:<entity>' or 'domain:<rule id>') in evidence — required by the gate
        for authz/IDOR findings. Ask with an entity name ("Order") or a rule id ("r1")."""
        raw = run.artifact("domain_map")
        if not raw:
            return {"status": "error", "reason": "no domain map for this run (DomainModeler stage did not produce one)"}
        try:
            dm = DomainMap.model_validate(raw)
        except ValueError as e:
            return {"status": "error", "reason": f"domain map invalid: {e}"}
        return consult(dm, question)

    return consult_domain
