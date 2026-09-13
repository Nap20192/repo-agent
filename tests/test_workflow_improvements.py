"""Card 20: parallel pre-pass, stage timings, stage timeout (on the Workflow graph)."""

import asyncio
import json
import time

from google.adk.workflow import FunctionNode

from scanner import core
from scanner.adapter import scanners
from scanner.adapter.store import Store
from scanner.core import Anchor
from tests.fakes import A1, FakeRun, _run, _workflow, fake_stage_node, notes_of


def test_run_jobs_parallel_ordered_and_failures_recorded(tmp_path):
    def job(tool):
        def fn(target):
            time.sleep(0.2)
            if tool == "bad":
                raise RuntimeError("boom")
            return [Anchor(id=tool, tool="semgrep", rule_id=tool, cwe="CWE-1", file="f", line=len(tool))]  # distinct lines: no merge
        return fn

    jobs = [(t, job(t)) for t in ("a", "bb", "bad", "ccc")]  # job names are free; Anchor.tool is a Literal
    t0 = time.monotonic()
    res = scanners.run_jobs(tmp_path, jobs)
    assert time.monotonic() - t0 < 0.6  # 4 × 0.2 s sequentially would be ≥ 0.8
    assert [a.rule_id for a in res.anchors] == ["a", "bb", "ccc"] and res.ran == ["a", "bb", "ccc"]
    assert "RuntimeError: boom" in res.failed["bad"]


def test_timings_artifact_and_summary(tmp_path):
    store = Store(str(tmp_path / "s.db"))
    run = store.start_run("/t")
    run.save_anchors([A1])
    stage = fake_stage_node(run, "model", {"architecture_model": {"entities": []}, "threat_model": {"intent": "production", "threats": []}})
    _run(_workflow(run, model=stage, max_rounds=1, max_parallel=1))
    t = run.artifact("timings")
    assert set(t) >= {"model", "verify_0"} and all(v >= 0 for v in t.values())
    summary = json.loads(run.write_summary(tmp_path).read_text())
    assert summary["timings"] == t
    store.close()


def test_slow_stage_is_cancelled_and_pipeline_goes_on():
    async def slow(ctx, node_input):
        await asyncio.sleep(1.0)
        return {"entities": []}

    run = FakeRun()
    t0 = time.monotonic()
    state = _run(_workflow(run, model=FunctionNode(func=slow, name="model", rerun_on_resume=True), max_rounds=1, stage_timeout=0.2))
    assert time.monotonic() - t0 < 0.9
    assert run.artifact("architecture_model") is None
    assert any("stage model failed" in t for t, _ in notes_of(run))
    assert state[core.STATE_STOP_REASON] == "round limit"  # the queue was still investigated
