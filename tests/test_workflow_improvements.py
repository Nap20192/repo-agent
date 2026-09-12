"""Card 20: parallel pre-pass, JSON retry nudge, stage timings, stage timeout."""

import asyncio
import json
import time
from typing import ClassVar

from google.adk.agents import BaseAgent

from scanner import core
from scanner.adapter import static
from scanner.adapter.store import Store
from scanner.app.pipeline_v2 import PipelineV2
from scanner.core import Anchor
from tests.fakes import (
    A1,
    FakeRun,
    FakeStage,
    FakeVerifier,
    _run,
    _text_event,
    notes_of,
)


# --- 1. parallel pre-pass ---------------------------------------------------------------
def test_run_jobs_parallel_ordered_and_failures_recorded(tmp_path):
    def job(tool):
        def fn(target):
            time.sleep(0.2)
            if tool == "bad":
                raise RuntimeError("boom")
            return [Anchor(id=tool, tool=tool, cwe="CWE-1", file="f", line=len(tool))]  # distinct lines: no merge
        return fn

    jobs = [(t, job(t)) for t in ("a", "bb", "bad", "ccc")]
    t0 = time.monotonic()
    res = static._run_jobs(tmp_path, jobs)
    assert time.monotonic() - t0 < 0.6  # 4 × 0.2 s sequentially would be ≥ 0.8
    assert [a.tool for a in res.anchors] == ["a", "bb", "ccc"] and res.ran == ["a", "bb", "ccc"]
    assert "RuntimeError: boom" in res.failed["bad"]


# --- fakes ----------------------------------------------------------------------------------
class FlakyStage(BaseAgent):
    """Prose on the first activation, JSON on the retry. Clone-safe via the shared store's notes."""
    instruction: str = ""
    store: object = None
    reply: dict | None = None
    model_config: ClassVar[dict] = {"arbitrary_types_allowed": True}

    async def _run_async_impl(self, ctx):
        first = not any(t == f"flaky:{self.name.removesuffix('_retry')}" for t, _ in notes_of(self.store))
        if first:
            self.store.add_note(f"flaky:{self.name}", "")
            yield _text_event(self.name, ctx, "Sure! Here is my analysis in prose, no braces at all.")
            return
        assert "not valid JSON" in self.instruction  # the nudge reached the retry activation
        yield _text_event(self.name, ctx, json.dumps(self.reply))


class FlakyVerifier(FakeVerifier):
    async def _run_async_impl(self, ctx):
        h = json.loads(self.instruction.split("(JSON):\n", 1)[1])
        if "not valid JSON" not in self.instruction:
            self.store.report(core.Finding(anchor_id=h["anchor_id"], hypothesis_id=h["id"], cwe=h["cwe"], file="main.go",
                                           title="t", status=core.CONFIRMED, evidence=["db.Query(x)"]))
            yield _text_event(self.name, ctx, "I confirmed it, see report_finding.")
            return
        yield _text_event(self.name, ctx, json.dumps({"hypothesis_id": h["id"], "verdict": "confirmed", "notes": "n2", "new_hypotheses": []}))


class SlowStage(BaseAgent):
    instruction: str = ""
    model_config: ClassVar[dict] = {"arbitrary_types_allowed": True}

    async def _run_async_impl(self, ctx):
        await asyncio.sleep(1.0)
        yield _text_event(self.name, ctx, json.dumps({"entities": []}))


def _v2(run, **kw):
    return PipelineV2(verifier=kw.pop("verifier", FakeVerifier(name="verify", store=run)), store=run, target="/t",
                      has_anchor=lambda i: run.anchor(i) is not None, has_symbol=lambda s: False,
                      entry_points_fn=list, max_parallel=1, **kw)


# --- 2. JSON retry nudge -------------------------------------------------------------------
def test_stage_retries_once_when_reply_is_not_json():
    run = FakeRun()
    arch = FlakyStage(name="architect", store=run, reply={"entities": [{"name": "x"}]})
    state = _run(_v2(run, architect=arch, max_rounds=1))
    assert run.artifact("architecture_model") == {"entities": [{"name": "x"}]}
    assert state["json_retries"] == 1


def test_verify_retries_once_for_missing_dossier_json():
    run = FakeRun()
    state = _run(_v2(run, verifier=FlakyVerifier(name="verify", store=run), max_rounds=1, max_hyps=1))
    d = run.doss[0][0]
    assert d.verdict == core.CONFIRMED and d.notes == "n2" and not d.error
    assert state["json_retries"] == 1


# --- 3. stage timings ----------------------------------------------------------------------
def test_timings_artifact_and_summary(tmp_path):
    store = Store(str(tmp_path / "s.db"))
    run = store.start_run("/t")
    run.save_anchors([A1])
    arch = FakeStage(name="architect", store=run, reply={"entities": []})
    tm = FakeStage(name="threat_modeler", store=run, reply={"intent": "production", "threats": []})
    _run(_v2(run, architect=arch, threat_modeler=tm, max_rounds=1))
    t = run.artifact("timings")
    assert set(t) >= {"architecture_model", "threat_model", "verify_0"} and all(v >= 0 for v in t.values())
    summary = json.loads(run.write_summary(tmp_path).read_text())
    assert summary["timings"] == t
    store.close()


# --- 5. stage timeout ----------------------------------------------------------------------
def test_slow_stage_is_cancelled_and_pipeline_goes_on(monkeypatch):
    monkeypatch.setenv("STAGE_TIMEOUT", "0.2")
    run = FakeRun()
    t0 = time.monotonic()
    state = _run(_v2(run, architect=SlowStage(name="architect"), max_rounds=1))
    assert time.monotonic() - t0 < 0.9
    assert run.artifact("architecture_model") is None
    assert any("stage architecture_model failed" in t for t, _ in notes_of(run))
    assert state[core.STATE_STOP_REASON] == "round limit"  # the queue was still investigated
