"""Domain types (pydantic, tolerant of extra fields) and constants. No ADK, no I/O.

Ported from git-agent3 internal/core; the modelling artifacts (Threat, ArchitectureModel, ThreatModel) live here too."""

from __future__ import annotations

from typing import Literal

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

# --- vocabularies (PEP 586). Applied as field types only where the program, not the model, sets the value:
# LLM-supplied fields (Finding.status/severity, Dossier.verdict, Hypothesis.kind) stay `str` so the gates can
# answer the model with a reason instead of a ValidationError — the gate messages are part of the contract.
Status = Literal["confirmed", "rejected", "uncertain"]
Kind = Literal["entry", "sink", "dependency", "secret", "authz"]
CandidateKind = Literal["entry", "sink", "external"]
Severity = Literal["critical", "high", "medium", "low", "info"]
Tool = Literal["gosec", "semgrep", "osv", "gitleaks", "threatmodel", "entrypoint", "investigator"]
SYNTHETIC_TOOLS = ("threatmodel", "entrypoint")  # anchors minted from a stage, not a scanner: they only say "start here"
Intent = Literal["production", "sample"]

# One CWE taxonomy (ADR 0006): cwe → class family. The class overlay (agents.registry.CLASSES) and the consult gate derive from it;
# AUTHZ_CWES/TAINT_CWES above stay as the gate's historical subsets (CWE-352 routes to authz but needs no domain: ref).
def _cwes(*ns: int) -> frozenset[str]:
    return frozenset(f"CWE-{n}" for n in ns)


CWE_CLASSES: dict[str, str] = {
    **dict.fromkeys(_cwes(89, 78, 77, 88, 22, 79, 80, 918, 94, 95, 1336, 943, 611, 502, 601), "taint"),
    **dict.fromkeys(_cwes(284, 285, 639, 862, 863, 840, 352, 287, 347, 915, 306, 307, 384, 613), "authz"),
    **dict.fromkeys(_cwes(798, 312, 321), "secret"),
    **dict.fromkeys(_cwes(614, 1004, 942, 16, 209, 532, 778, 327, 328, 338, 295, 319, 1357), "config"),
}

class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore")

class Anchor(_Model):
    id: str
    tool: Tool
    rule_id: str = ""
    cwe: str = ""  # "" for synthetic anchors (entrypoint) — the model's CWE is recorded at report time
    severity: Severity = "info"
    file: str
    line: int
    message: str = ""
    snippet: str = ""
    tools: list[str] = Field(default_factory=list)
    rule_ids: list[str] = Field(default_factory=list)

class Candidate(_Model):
    kind: CandidateKind
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
    wstg_id: str = ""  # OWASP WSTG test the claim maps to (from the anchor's CWE or the threat)
    asvs_id: str = ""  # ASVS 5.0 requirement id

class Dossier(_Model):
    hypothesis_id: str = ""
    verdict: str = UNCERTAIN
    finding_id: str = ""
    evidence: list[str] = Field(default_factory=list)
    notes: str = ""
    new_hypotheses: list[Hypothesis] = Field(default_factory=list)
    error: str = ""
    specialist: str = ""  # which specialist agent investigated (routing; "" = generic verifier)

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
    remediation: str = ""  # one line, filled from the CWE by the store when empty
    remediation_url: str = ""  # OWASP Cheat Sheet
    wstg_id: str = ""
    asvs_id: str = ""  # ASVS 5.0 requirement id (from the hypothesis / CWE map)
    top10: str = ""  # OWASP Top 10 2025 category
    source: Literal["llm", "direct"] = "llm"  # direct: a scanner result reported without an LLM verdict (card 42)
    # card 45 annotations (report-only, written through RunStore.annotate; the verdict stays with the gates)
    review: dict = Field(default_factory=dict)  # ReviewVerdict dump: status, checklist, repro_hints
    viability: str = ""  # VIABLE | CONDITIONAL_VIABLE | NON_VIABLE | SAMPLE_OR_TEST
    repro_status: str = ""  # statically_confirmed | not_attempted
    calibration: dict = Field(default_factory=dict)  # filled by the calibrate node; exporters compute it when empty

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
    intent: Intent = "production"  # fail-closed: sample only if every check holds; normalised before validation

    @field_validator("intent", mode="before")
    @classmethod
    def _norm_intent(cls, v: object) -> str:  # tolerate the model's spelling; anything not clearly sample is production
        return "sample" if str(v).strip().lower().startswith("sample") else "production"
