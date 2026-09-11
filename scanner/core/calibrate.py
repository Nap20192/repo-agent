"""Calibrate stage, report-only: a 1..10 hazard score per finding. Never changes status, severity or export.

Adapted from the Shannon/Mantis calibrate prompt + calibration-rules catalogue (Apache-2.0), reduced to the
deterministic web/Go subset a static-only engine can decide from (cwe, status, confidence, file, intent,
exposure). Hazard = (Impact + Likelihood) × Multiplier, capped at 10; caps: most restrictive wins.

Impact by CWE class (1..5):
  5  RCE-class: CWE-78, CWE-77, CWE-94, CWE-95, CWE-502
  4  core-control bypass / systemic data: CWE-89, CWE-918, CWE-611, CWE-22, CWE-287, CWE-306,
     CWE-284, CWE-285, CWE-639, CWE-862, CWE-863, CWE-798
  3  CWE-79, CWE-352, CWE-327, CWE-328, CWE-338, CWE-90, CWE-943
  2  default (CWE-601 and unknown classes)
  1  hygiene: CWE-676, CWE-614, CWE-1004, CWE-16
  a finding whose own severity is low/info is capped at 2.
Likelihood (1..5): static engine → 3 ("trivial to automate") capped by static_confirmation; confidence < 0.5 → 2;
  status uncertain → 1.
Multiplier: exposure (exposed 1.0 / internal 0.8 / privileged 0.5) × 0.8 static_confirmation
  × 0.7 user_interaction (CWE-352, CWE-79, CWE-601) × 0.4 intent sample.
Caps: third_party_reachability (dependency advisory, no proven path) → LOW 2.0; unreachable_inputs/vague
  (status not confirmed) → LOW 2.0; hygiene impact 1 → LOW 2.0; static_confirmation → HIGH 7.9;
  internal_nested (multiplier < 1) → HIGH 7.9; strict_xss (CWE-79) → MEDIUM 5.9.
"""

from __future__ import annotations

from scanner.core.types import CONFIRMED, Finding

_IMPACT = {
    **dict.fromkeys(["CWE-78", "CWE-77", "CWE-94", "CWE-95", "CWE-502"], 5),
    **dict.fromkeys(["CWE-89", "CWE-918", "CWE-611", "CWE-22", "CWE-287", "CWE-306", "CWE-284", "CWE-285",
                     "CWE-639", "CWE-862", "CWE-863", "CWE-798"], 4),
    **dict.fromkeys(["CWE-79", "CWE-352", "CWE-327", "CWE-328", "CWE-338", "CWE-90", "CWE-943"], 3),
    **dict.fromkeys(["CWE-676", "CWE-614", "CWE-1004", "CWE-16"], 1),
}
_EXPOSURE = {"exposed": 1.0, "internal": 0.8, "privileged": 0.5}
_USER_INTERACTION = {"CWE-352", "CWE-79", "CWE-601"}
_MANIFESTS = {"go.mod", "go.sum", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt",
              "poetry.lock", "Pipfile.lock", "composer.lock", "Cargo.lock", "Gemfile.lock", "pom.xml"}
LOW, MEDIUM, HIGH = 2.0, 5.9, 7.9


def priority(score: float) -> str:
    return "CRITICAL" if score >= 8 else "HIGH" if score >= 6 else "MEDIUM" if score >= 3 else "LOW"


def calibrate(finding: Finding, intent: str = "production", exposure: str = "internal") -> dict:
    """Report-only hazard score for one finding. Pure; see the module docstring for the tables."""
    cwe = finding.cwe.upper()
    impact = _IMPACT.get(cwe, 2)
    if finding.severity in ("low", "info"):
        impact = min(impact, 2)
    likelihood = 1 if finding.status != CONFIRMED else 2 if finding.confidence < 0.5 else 3
    rules = ["static_confirmation"]  # no sandbox: never empirically reproduced → likelihood ≤ 3, ×0.8, not CRITICAL
    mult = _EXPOSURE.get(exposure.lower(), 0.8) * 0.8
    if cwe in _USER_INTERACTION:
        mult *= 0.7
        rules.append("user_interaction")
    if intent == "sample":
        mult *= 0.4
        rules.append("sample_or_test")
    score = min(10.0, (impact + likelihood) * mult)

    cap = 10.0
    if finding.file.rsplit("/", 1)[-1] in _MANIFESTS:  # dependency advisory without a proven reachable path
        cap, rules = min(cap, LOW), [*rules, "third_party_reachability"]
    if finding.status != CONFIRMED:
        cap, rules = min(cap, LOW), [*rules, "unreachable_inputs"]
    if impact == 1:
        cap, rules = min(cap, LOW), [*rules, "hygiene_only"]
    if cwe == "CWE-79":
        cap, rules = min(cap, MEDIUM), [*rules, "strict_xss"]
    if mult < 0.8:  # exposure below "exposed" (the ×0.8 static factor alone leaves 0.8)
        cap, rules = min(cap, HIGH), [*rules, "internal_nested"]
    cap = min(cap, HIGH)  # static_confirmation: never CRITICAL
    score = round(min(score, cap), 1)
    return {"score": score, "impact": impact, "likelihood": likelihood, "multiplier": round(mult, 3),
            "priority": priority(score), "rules_applied": rules}
