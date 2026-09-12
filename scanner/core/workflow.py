"""Payloads between the Workflow graph's nodes (card 43, docs/plans/workflow-migration.md §3–4).

Only what a later node must read outside its predecessor's output lives here; findings, anchors, hypotheses,
dossiers and grounded artifacts stay in the RunStore. `ScanSkeleton` (not `Skeleton`: that name is the
DomainModeler's pre-pass in scanner.core.domain) is what the modelling stages receive."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from scanner.core.types import Candidate, Hypothesis


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore")


class ScanSkeleton(_Model):
    target: str = ""
    entry_points: list[Candidate] = Field(default_factory=list)
    anchors: list[dict] = Field(default_factory=list)  # trimmed anchor view: id, tool, cwe, file, line, message[:120]


class QueueState(_Model):
    queue: list[Hypothesis] = Field(default_factory=list)
    done: list[str] = Field(default_factory=list)  # `key(h)` strings; a set is not JSON-native


class InvestigateResult(_Model):
    rounds: int = 0
    stop: str = ""  # "" | "round limit" | "budget"


class Report(_Model):
    rounds: int = 0
    stop_reason: str = ""
    timings: dict[str, float] = Field(default_factory=dict)


class WorkflowState(BaseModel):
    """`state_schema` of the Workflow: typed keys the nodes share, plus tool/consultant scratch keys."""

    model_config = ConfigDict(extra="allow")
    round: int = 0  # core.STATE_ROUND
    queue_len: int = 0
    stop_reason: str = ""  # core.STATE_STOP_REASON
    budget_exhausted: bool = False  # core.STATE_BUDGET_EXHAUSTED
    grounding_dropped: int = 0
