"""Deterministic ADK-eval metrics for the per-agent web apps (card 46): the discipline every agent must keep, graded
from what the agent actually did (tool calls, tool responses, final text) — no judge model, no golden trajectory.

Wired through `web/<name>/test_config.json` (`custom_metrics.<name>.code_config.name = "eval.adk_metrics.<fn>"`) and
run with `adk eval web/<name> web/<name>/<name>.evalset.json` (the config next to the evalset is picked up).
Each metric scores one invocation in [0, 1] and passes only at 1.0. The seeded cases (web/<app>/<app>.evalset.json) name
anchors of samples/02-vulnshop: run them with BUGFINDER_TARGET unset (or pointing there) — on another target the agent
finds no anchor and never reaches the gate, which `gate_attempted` reports as a failure instead of a free pass."""

from __future__ import annotations

import json

from google.adk.evaluation.eval_case import Invocation
from google.adk.evaluation.eval_metrics import EvalMetric, EvalStatus
from google.adk.evaluation.evaluator import EvaluationResult, PerInvocationResult
from pydantic import BaseModel, ValidationError

from scanner.core import ArchitectureModel, ThreatModel
from scanner.core.domain import DomainMap
from scanner.core.workflow import Confirmation, ReviewVerdict, TriageBatch, Viability

VERDICT_TOOLS = {"report_finding", "disprove_finding"}
READ_TOOLS = {"read_file", "lsp_definition", "grep", "lsp_references", "lsp_callers", "lsp_callees"}
VERDICT_WORDS = ("confirmed", "false_positive", "non_viable", "valid")


def _result(scores: list[float], actual: list[Invocation]) -> EvaluationResult:
    per = [PerInvocationResult(actual_invocation=inv, score=sc, eval_status=EvalStatus.PASSED if sc >= 1.0 else EvalStatus.FAILED)
           for inv, sc in zip(actual, scores, strict=True)]
    overall = sum(scores) / len(scores) if scores else 0.0
    return EvaluationResult(overall_score=overall, per_invocation_results=per,
                            overall_eval_status=EvalStatus.PASSED if overall >= 1.0 else EvalStatus.FAILED)


def _calls(inv: Invocation) -> list[str]:
    return [fc.name or "" for fc in (inv.intermediate_data.tool_uses if inv.intermediate_data else [])]


def _gate_ok(inv: Invocation) -> bool:
    """Did any verdict tool answer without {"status": "error"}?"""
    for fr in inv.intermediate_data.tool_responses if inv.intermediate_data else []:
        if fr.name in VERDICT_TOOLS and isinstance(fr.response, dict) and fr.response.get("status") != "error":
            return True
    return False


def _final_text(inv: Invocation) -> str:
    return "".join(p.text or "" for p in (inv.final_response.parts if inv.final_response and inv.final_response.parts else []))


def read_before_report(metric: EvalMetric, actual: list[Invocation], expected=None, scenario=None) -> EvaluationResult:
    """Evidence discipline: every report_finding / disprove_finding call comes after at least one code read
    (read_file, lsp_definition, grep, …) in the same activation. No verdict call at all scores 1 (nothing to judge)."""
    scores = []
    for inv in actual:
        seen_read, ok, n = False, 0, 0
        for name in _calls(inv):
            if name in READ_TOOLS:
                seen_read = True
            elif name in VERDICT_TOOLS:
                n += 1
                ok += seen_read
        scores.append(ok / n if n else 1.0)
    return _result(scores, actual)


def verdict_via_gate(metric: EvalMetric, actual: list[Invocation], expected=None, scenario=None) -> EvaluationResult:
    """Capella rule: a verdict exists only through the gate. A final answer that claims confirmed / false_positive /
    non_viable / valid while no verdict tool call was accepted scores 0; an honest "uncertain" without a call scores 1."""
    scores = []
    for inv in actual:
        claims = any(w in _final_text(inv).lower() for w in VERDICT_WORDS)
        scores.append(1.0 if (not claims or _gate_ok(inv)) else 0.0)
    return _result(scores, actual)


def gate_attempted(metric: EvalMetric, actual: list[Invocation], expected=None, scenario=None) -> EvaluationResult:
    """The activation reached a verdict tool at all (report_finding / disprove_finding, accepted or refused). Guards the
    two metrics above from passing vacuously when the target has no such anchor (wrong BUGFINDER_TARGET)."""
    return _result([1.0 if any(c in VERDICT_TOOLS for c in _calls(inv)) else 0.0 for inv in actual], actual)


def _schema_metric(model: type[BaseModel]):
    def metric(metric_: EvalMetric, actual: list[Invocation], expected=None, scenario=None) -> EvaluationResult:
        scores = []
        for inv in actual:
            text = _final_text(inv).strip()
            text = text[text.find("{"):text.rfind("}") + 1] if "{" in text else text
            try:
                model.model_validate(json.loads(text))
                scores.append(1.0)
            except (ValueError, ValidationError):
                scores.append(0.0)
        return _result(scores, actual)
    metric.__name__ = f"schema_{model.__name__}"
    metric.__doc__ = f"Document stage contract: the final answer is JSON that validates as {model.__name__}."
    return metric


# document stages (output_schema agents): the final answer must be the stage's document
schema_architecture_model = _schema_metric(ArchitectureModel)
schema_domain_map = _schema_metric(DomainMap)
schema_threat_model = _schema_metric(ThreatModel)
schema_triage_batch = _schema_metric(TriageBatch)
schema_review_verdict = _schema_metric(ReviewVerdict)
schema_viability = _schema_metric(Viability)
schema_confirmation = _schema_metric(Confirmation)
