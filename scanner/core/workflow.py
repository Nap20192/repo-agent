"""Payloads between the graph's nodes. Only what a later node must read outside its predecessor's output lives here;
findings, anchors, hypotheses, dossiers and the model artifacts stay in the RunStore."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from scanner.core.types import Anchor, Candidate, Hypothesis


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore")


class ScanSkeleton(_Model):
    target: str = ""
    entry_points: list[Candidate] = Field(default_factory=list)


class DirectResult(_Model):
    """`direct_findings` → the anchors the model may still investigate + the finding ids reported without it."""
    remaining: list[Anchor] = Field(default_factory=list)
    reported: list[str] = Field(default_factory=list)


class QueueState(_Model):
    queue: list[Hypothesis] = Field(default_factory=list)
    done: list[str] = Field(default_factory=list)  # `key(h)` strings; a set is not JSON-native


class ResearchResult(_Model):
    rounds: int = 0
    stop: str = ""  # "" | "round limit" | "budget" | "verify round N failed: ..."
    findings: int = 0


class ExportResult(_Model):
    rounds: int = 0
    stop_reason: str = ""
    timings: dict[str, float] = Field(default_factory=dict)
    coverage: Literal["complete", "reduced"] = "complete"
    reductions: list[str] = Field(default_factory=list)  # why coverage is reduced (failed stages)
