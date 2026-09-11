"""Domain types (pydantic, tolerant of extra fields) and constants. No ADK, no I/O.

Ported from git-agent3 internal/core; v2 artifacts (Threat, ArchitectureModel, ThreatModel) live here too."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

CONFIRMED, REJECTED, UNCERTAIN = "confirmed", "rejected", "uncertain"

STATUSES = (CONFIRMED, REJECTED, UNCERTAIN)

KINDS = ("entry", "sink", "dependency", "secret", "authz")

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

EVIDENCE_KNOWLEDGE = "knowledge:"

EVIDENCE_DOMAIN = "domain:"

EVIDENCE_OWASP = "owasp:"  # methodology citation: exempt from the quote check, never required

AUTHZ_CWES = {"CWE-284", "CWE-285", "CWE-639", "CWE-862", "CWE-863"}

TAINT_CWES = {"CWE-89", "CWE-78", "CWE-22", "CWE-79", "CWE-918"}

STATE_ROUND = "round"

STATE_BUDGET_EXHAUSTED = "budget_exhausted"

STATE_STOP_REASON = "stop_reason"

class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore")

class Anchor(_Model):
    id: str
    tool: str  # gosec | semgrep | osv | gitleaks
    rule_id: str = ""
    cwe: str = ""
    severity: str = "info"
    file: str
    line: int
    message: str = ""
    snippet: str = ""
    tools: list[str] = Field(default_factory=list)
    rule_ids: list[str] = Field(default_factory=list)

class Candidate(_Model):
    kind: str  # entry | sink | external
    file: str = ""
    line: int = 0
    route: list[str] = Field(default_factory=list)
    symbol: str = ""
    anchor_id: str = ""
    cwe: str = ""
    severity: str = ""

class Hypothesis(_Model):
    id: str = ""  # "h<round>-<n>"
    kind: str = ""  # entry|sink|dependency|secret|authz
    cwe: str = ""
    claim: str = ""
    anchor_id: str = ""
    symbol: str = ""
    route: list[str] = Field(default_factory=list)
    reads: list[str] = Field(default_factory=list)
    consult: str = ""  # knowledge|domain|""
    priority: int = 0

class Dossier(_Model):
    hypothesis_id: str = ""
    verdict: str = UNCERTAIN
    finding_id: str = ""
    evidence: list[str] = Field(default_factory=list)
    notes: str = ""
    new_hypotheses: list[Hypothesis] = Field(default_factory=list)
    error: str = ""

class Finding(_Model):
    id: str = ""
    anchor_id: str = ""
    hypothesis_id: str = ""
    cwe: str = ""
    file: str = ""
    line: int = 0
    title: str = ""
    severity: str = ""
    status: str = UNCERTAIN
    evidence: list[str] = Field(default_factory=list)
    confidence: float = 0.0

class Threat(_Model):
    """One modeled threat (ThreatModeler output). Grounding: an anchor match by (file, cwe) or a symbol."""
    id: str = ""
    cwe: str = ""
    claim: str = ""
    symbol: str = ""
    file: str = ""
    line: int = 0
    wstg_id: str = ""
    priority: int = 50
    reads: list[str] = Field(default_factory=list)

class Entity(_Model):
    name: str
    files: list[str] = Field(default_factory=list)
    role: str = ""
    grounding_symbol: str = ""
    criticality: str = "STANDARD"  # CRITICAL|STANDARD|LOW

class VulnClass(_Model):
    cwe: str
    wstg_id: str = ""
    why: str = ""

class ArchitectureModel(_Model):
    entities: list[Entity] = Field(default_factory=list)
    trust_boundaries: list[str] = Field(default_factory=list)  # "entity: symbol — what crosses"
    vuln_classes: list[VulnClass] = Field(default_factory=list)
    deployment_signals: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

class ThreatModel(_Model):
    threats: list[Threat] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)  # design concerns without a symbol: notes, never threats
    intent: str = "production"  # production | sample (fail-closed: sample only if every check holds)

    @field_validator("intent", mode="before")
    @classmethod
    def _norm_intent(cls, v: object) -> str:  # tolerate the model's spelling; anything not clearly sample is production
        return "sample" if str(v).strip().lower().startswith("sample") else "production"
