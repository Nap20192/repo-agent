"""Domain model types: what the DomainModeler produces and what consult_domain answers from. Pure (no ADK, no I/O)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore")


class Entity(_Model):
    """A business object: a struct/model/table with its fields and the field that names its owner."""

    name: str
    fields: list[str] = Field(default_factory=list)
    owner_field: str = ""  # user_id / owner / tenant_id … — empty when no ownership candidate was seen
    symbol: str = ""  # grounding symbol (struct/class name) when it exists in the index
    file: str = ""
    line: int = 0
    queries: list[str] = Field(default_factory=list)  # sqlc query names / DAO functions touching it


class Guard(_Model):
    """An access-control construct: middleware, decorator, role check — and the handler it wraps."""

    name: str
    file: str
    line: int
    wraps: str = ""


class Role(_Model):
    name: str
    guards: list[str] = Field(default_factory=list)
    entries: list[str] = Field(default_factory=list)  # entry-point symbols this role reaches


class Rule(_Model):
    """A falsifiable business rule grounded on a symbol: "Order is visible only to Order.UserID"."""

    id: str
    statement: str
    entity: str = ""
    symbol: str = ""  # the symbol that enforces (or should enforce) the rule
    evidence: list[str] = Field(default_factory=list)  # file:line refs the modeler read


class RuleCandidate(_Model):
    text: str
    file: str
    line: int


class Skeleton(_Model):
    """Deterministic pre-pass for the DomainModeler: what the code says before any LLM interpretation."""

    entities: list[Entity] = Field(default_factory=list)
    guards: list[Guard] = Field(default_factory=list)
    rule_candidates: list[RuleCandidate] = Field(default_factory=list)


class DomainMap(_Model):
    entities: list[Entity] = Field(default_factory=list)
    roles: list[Role] = Field(default_factory=list)
    rules: list[Rule] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)  # assertions the modeler could not ground on a symbol
    notes: list[str] = Field(default_factory=list)
