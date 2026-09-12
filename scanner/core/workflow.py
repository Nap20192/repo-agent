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
