"""Payloads between the Workflow graph's nodes (card 43, docs/plans/workflow-migration.md §3–4; card 45, docs/plans/shannon-graph.md §3).

Only what a later node must read outside its predecessor's output lives here; findings, anchors, hypotheses,
dossiers and grounded artifacts stay in the RunStore. `ScanSkeleton` (not `Skeleton`: that name is the
DomainModeler's pre-pass in scanner.core.domain) is what the modelling stages receive."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from scanner.core.types import Anchor, Candidate, Hypothesis


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


# --- card 45: Shannon-graph payloads (docs/plans/shannon-graph.md §3) --------------------------------------------

class DirectResult(_Model):
    """`direct_findings` → the anchors the model may still investigate + the finding ids reported without it."""
    remaining: list[Anchor] = Field(default_factory=list)
    reported: list[str] = Field(default_factory=list)


class ReconMap(_Model):
    """Deterministic pre-recon (Shannon pre-recon-code): sources, sinks by class, auth guards, config files."""
    sources: list[Candidate] = Field(default_factory=list)
    sinks: dict[str, list[str]] = Field(default_factory=dict)  # "CWE-89" → ["db.js:10", …]
    auth: list[str] = Field(default_factory=list)  # guard/middleware symbols
    config_files: list[str] = Field(default_factory=list)


class PlanState(QueueState):
    """The queue plus the file batches the triage sweep classifies."""
    batches: list[list[str]] = Field(default_factory=list)


class TriageClassification(_Model):
    file: str = ""
    flagged: bool = False
    classes: list[str] = Field(default_factory=list)
    why: str = ""


class TriageBatch(_Model):
    classifications: list[TriageClassification] = Field(default_factory=list)


class TriageCoverage(_Model):
    """Artifact of `fold_triage`: how much of the plan the sweep actually classified (Capella computeTriageCoverage)."""
    considered: int = 0
    classified: int = 0
    missing: list[str] = Field(default_factory=list)
    flagged: list[str] = Field(default_factory=list)


class ResearchResult(InvestigateResult):
    findings: int = 0


RuleOutcome = Literal["PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE"]
ReviewStatus = Literal["VALID", "FALSE_POSITIVE", "PROVISIONALLY_VALID", "NEEDS_RESEARCH"]
ViabilityStatus = Literal["VIABLE", "CONDITIONAL_VIABLE", "NON_VIABLE", "SAMPLE_OR_TEST"]
ReproStatus = Literal["statically_confirmed", "not_attempted"]


class RuleEval(_Model):
    outcome: RuleOutcome = "UNKNOWN"
    reason: str = ""


class ReviewVerdict(_Model):
    """Review node output. The status is an ANNOTATION: the stored verdict changes only through the gates
    (FALSE_POSITIVE must come with a disprove_finding call, else it is NEEDS_RESEARCH)."""
    finding_id: str = ""
    status: ReviewStatus = "NEEDS_RESEARCH"
    reasoning: str = ""
    repro_hints: list[str] = Field(default_factory=list)
    checklist: dict[str, RuleEval] = Field(default_factory=dict)


class Viability(_Model):
    finding_id: str = ""
    viability: ViabilityStatus = "CONDITIONAL_VIABLE"
    reasoning: str = ""


class Confirmation(_Model):
    finding_id: str = ""
    repro_status: ReproStatus = "not_attempted"
    repro_hints: list[str] = Field(default_factory=list)


class ExportResult(Report):
    coverage: Literal["complete", "reduced"] = "complete"
    reductions: list[str] = Field(default_factory=list)  # why coverage is reduced (triage missing files, failed stages)
