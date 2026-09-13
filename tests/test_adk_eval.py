"""ADK eval for the per-agent web apps (card 46): every app ships a seeded evalset (the graph's own payloads) and a
test_config.json whose criteria are deterministic code graders from eval/adk_metrics.py."""

import json
from pathlib import Path

from google.adk.evaluation.eval_case import IntermediateData, Invocation
from google.adk.evaluation.eval_config import EvalConfig
from google.adk.evaluation.eval_metrics import EvalMetric, EvalStatus
from google.adk.evaluation.eval_set import EvalSet
from google.adk.evaluation.metric_evaluator_registry import DEFAULT_METRIC_EVALUATOR_REGISTRY, register_custom_metrics_from_config
from google.genai import types

from eval import adk_metrics as m
from scanner.app import runner
from scanner.core import Finding, Hypothesis

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"
APPS = sorted(p.name for p in WEB.iterdir() if p.is_dir() and p.name != "fullscan" and (p / "agent.py").is_file())
METRIC = EvalMetric(metric_name="x", threshold=1.0)


def _inv(text: str = "", calls: list[str] = (), responses: dict[str, dict] | None = None) -> Invocation:
    return Invocation(
        user_content=types.Content(role="user", parts=[types.Part(text="go")]),
        final_response=types.Content(role="model", parts=[types.Part(text=text)]),
        intermediate_data=IntermediateData(
            tool_uses=[types.FunctionCall(name=c, args={}) for c in calls],
            tool_responses=[types.FunctionResponse(name=n, response=r) for n, r in (responses or {}).items()]),
    )


# --- the files ------------------------------------------------------------------------------------------

def test_every_app_has_a_valid_evalset_and_config():
    assert len(APPS) == 5
    for app in APPS:
        es = EvalSet.model_validate_json((WEB / app / f"{app}.evalset.json").read_text(encoding="utf-8"))
        assert es.eval_set_id == app and es.eval_cases, app
        for case in es.eval_cases:
            assert case.session_input.app_name == app and case.conversation[0].user_content.parts[0].text
        cfg = EvalConfig.model_validate(json.loads((WEB / app / "test_config.json").read_text(encoding="utf-8")))
        assert set(cfg.criteria) == set(cfg.custom_metrics or {}), app  # every criterion is one of our code graders
        for name, custom in (cfg.custom_metrics or {}).items():
            assert custom.code_config.name == f"eval.adk_metrics.{name}" and callable(getattr(m, name))
        register_custom_metrics_from_config(cfg, DEFAULT_METRIC_EVALUATOR_REGISTRY.fork())  # ADK resolves them by import


def test_seed_payloads_are_the_graphs_own_shapes():
    """Investigators get a Hypothesis (+ skill hints), critics/reviewers a {finding, anchor} pair — as route_and_verify
    and route_and_critique build them; the anchor ids are the ones gosec mints on samples/02-vulnshop."""
    sqli = None
    for app in APPS:
        es = EvalSet.model_validate_json((WEB / app / f"{app}.evalset.json").read_text(encoding="utf-8"))
        text = es.eval_cases[0].conversation[0].user_content.parts[0].text
        if app in ("knowledge", "domain", "model"):
            continue
        payload = json.loads(text)
        if app == "verify":
            h = Hypothesis.model_validate(payload)
            assert payload["skill"] and payload["specialist"] == ""
            sqli = sqli or h.anchor_id
        elif app == "critic":
            f = Finding.model_validate(payload["finding"])
            assert payload["anchor"]["id"] == f.anchor_id and payload["skills"]
    assert sqli == "a_f62a1e0787ee"  # new_anchor_id("gosec", "G202", "main.go", 22)


def test_app_names_match_the_roster():
    assert set(APPS) == set(runner.ROSTER)


# --- the graders ----------------------------------------------------------------------------------------

def test_read_before_report_requires_a_read_before_every_verdict_call():
    good = _inv(calls=["read_file", "report_finding"])
    bad = _inv(calls=["report_finding", "read_file", "disprove_finding"])
    none = _inv(calls=["grep"])
    r = m.read_before_report(METRIC, [good, bad, none])
    assert [p.score for p in r.per_invocation_results] == [1.0, 0.5, 1.0]
    assert [p.eval_status for p in r.per_invocation_results] == [EvalStatus.PASSED, EvalStatus.FAILED, EvalStatus.PASSED]
    assert r.overall_eval_status == EvalStatus.FAILED


def test_verdict_via_gate_rejects_verdicts_the_gate_never_accepted():
    prose = _inv(text='{"status": "confirmed", "notes": "SQLi"}', calls=["read_file"])
    refused = _inv(text="confirmed", calls=["read_file", "report_finding"], responses={"report_finding": {"status": "error", "reason": "unmatched quote"}})
    gated = _inv(text="confirmed", calls=["read_file", "report_finding"], responses={"report_finding": {"status": "ok", "id": "f_1"}})
    honest = _inv(text="uncertain: could not trace the hop from the handler to the sink")
    r = m.verdict_via_gate(METRIC, [prose, refused, gated, honest])
    assert [p.score for p in r.per_invocation_results] == [0.0, 0.0, 1.0, 1.0]


def test_gate_attempted_fails_an_activation_that_never_reached_the_gate():
    """Wrong BUGFINDER_TARGET: no anchor, no verdict call — the other two graders would pass vacuously."""
    r = m.gate_attempted(METRIC, [_inv(calls=["read_file", "grep"]), _inv(calls=["read_file", "report_finding"])])
    assert [p.score for p in r.per_invocation_results] == [0.0, 1.0] and r.overall_eval_status == EvalStatus.FAILED


def test_investigator_and_critic_configs_guard_against_vacuous_passes():
    for app in APPS:
        cfg = json.loads((WEB / app / "test_config.json").read_text(encoding="utf-8"))
        if "verdict_via_gate" in cfg["criteria"] and "read_before_report" in cfg["criteria"]:
            assert cfg["criteria"]["gate_attempted"] == 1.0, app
