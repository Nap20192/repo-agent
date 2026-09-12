"""End-to-end through the real runner (Store, pre-pass, ADK session, SARIF/summary, CLI exit code) with
fake agents in place of the LLM graph: `build_agent` is monkeypatched, everything else is real."""

import asyncio
import json
import shutil
import sqlite3
from pathlib import Path

import pytest
from google.adk.sessions.sqlite_session_service import SqliteSessionService

from scanner import core, main
from scanner.adapter.store import Run, Store
from scanner.app import runner
from scanner.app.pipeline_v2 import PipelineV2
from tests.fakes import FakeStage, FakeVerifier

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "02-vulnshop"
pytestmark = pytest.mark.skipif(shutil.which("gosec") is None, reason="gosec not installed")


def _fake_v1(run, target, entries, model, index=None, settings=None):
    """Stages off: the queue is the real pre-pass anchors; the fake verifier confirms CWE-89 and rejects the rest."""
    return PipelineV2(verifier=FakeVerifier(name="verify", store=run), store=run, target=str(target),
                      has_anchor=lambda i: run.anchor(i) is not None, has_symbol=lambda s: False, entry_points_fn=list,
                      max_parallel=1, max_hyps=8, max_rounds=1)


def _fake_v2(run, target, entries, model, index=None, settings=None):
    arch = FakeStage(name="architect", store=run, reply={"entities": [{"name": "shop"}], "vuln_classes": [{"cwe": "CWE-89"}]})
    tm = FakeStage(name="threat_modeler", store=run, reply={"intent": "production", "threats": [
        {"cwe": "CWE-639", "claim": "ghost", "symbol": "nowhere", "priority": 80}]})
    return PipelineV2(architect=arch, threat_modeler=tm, verifier=FakeVerifier(name="verify", store=run), store=run, target=str(target),
                      has_anchor=lambda i: run.anchor(i) is not None, has_symbol=lambda s: False, entry_points_fn=list,
                      max_parallel=1, max_hyps=2, max_rounds=1)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # no project .env, .runs lands here
    monkeypatch.setenv("GOOGLE_API_KEY", "dummy")  # model_from_env needs a key; the fake graph never calls it
    monkeypatch.setenv("STATE_PATH", str(tmp_path / "state.db"))
    monkeypatch.setenv("SESSIONS_PATH", str(tmp_path / "sessions.db"))
    monkeypatch.setenv("SKIP_DEPS", "1")
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    return tmp_path


def test_full_end_to_end(env, monkeypatch):
    monkeypatch.setattr(runner, "build_agent", _fake_v1)
    s = runner.scan_full(SAMPLE, runs_dir=env / "runs")

    # pre-pass: real gosec anchors in the real store
    db = sqlite3.connect(env / "state.db")
    anchors = [json.loads(j) for (j,) in db.execute("SELECT json FROM anchors WHERE run=1")]
    assert {a["cwe"] for a in anchors} >= {"CWE-89", "CWE-78"}
    assert db.execute("SELECT status, reason FROM runs WHERE id=1").fetchone() == ("done", "round limit")

    # verdicts from the fake verifier, exported
    assert s["run_id"] == 1 and s["confirmed"] == 1 and s["rejected"] >= 1 and s["stop_reason"] == "round limit"
    summary = json.loads(Path(s["summary_path"]).read_text())
    assert summary["confirmed"] == 1 and {f["cwe"] for f in summary["findings"]} >= {"CWE-89", "CWE-78"}
    sarif = json.loads(Path(s["sarif_path"]).read_text())
    assert [r["ruleId"] for r in sarif["runs"][0]["results"]] == ["CWE-89"]

    # the ADK session is where `adk web` reads it: user "user", id run-<id>-<target>
    svc = SqliteSessionService(str(env / "sessions.db"))
    sess = asyncio.run(svc.get_session(app_name="fullscan", user_id="user", session_id="run-1-02-vulnshop"))
    assert sess is not None and len(sess.events) > 3 and sess.state[core.STATE_STOP_REASON] == "round limit" and sess.state[core.STATE_ROUND] == 1


def test_cli_exit_code(env, monkeypatch):
    monkeypatch.setattr(runner, "build_agent", _fake_v1)
    assert main.main(["full", "--target", str(SAMPLE)]) == 2  # confirmed findings → 2
    assert (env / ".runs").is_dir()


def test_full_v2_persists_artifacts(env, monkeypatch):
    monkeypatch.setattr(runner, "build_agent", _fake_v2)
    s = runner.scan_full(SAMPLE, runs_dir=env / "runs")
    assert s["intent"] == "production" and s["confirmed"] == 1 and s["stop_reason"] == "round limit"
    run = Run(Store(str(env / "state.db")).db, 1, str(SAMPLE))
    assert run.artifact("architecture_model")["vuln_classes"] == [{"cwe": "CWE-89"}]
    assert run.artifact("threat_model")["intent"] == "production"
    assert any("ungrounded" in n["text"] for n in run.notes())  # the ghost threat was gated, not silently lost
