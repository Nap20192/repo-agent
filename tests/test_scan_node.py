"""Card 48: web/fullscan's root node — the target named in the message → prepare → the graph nested → finish_run."""

from pathlib import Path
from types import SimpleNamespace

from google.adk.workflow import FunctionNode

from scanner.app import runner
from tests.fakes import _run_node


def _fake_graph(seen: dict):
    async def scan(ctx, node_input):
        seen["ran"] = True
        ctx.state["stop_reason"] = ""
        return {"anchors": 1}
    return FunctionNode(func=scan, name="scan", rerun_on_resume=True)


def test_root_node_scans_the_target_named_in_the_message(tmp_path, monkeypatch):
    seen: dict = {}
    (tmp_path / "main.go").write_text("package main\n")

    def fake_prepare(target):
        seen["target"] = target
        return "store", SimpleNamespace(id=7, finish=lambda *a: seen.setdefault("failed", a)), _fake_graph(seen)

    def fake_finish(store, run, agent, state, runs_dir):
        seen["finish"] = (store, run.id, state.get("stop_reason"))
        return {"confirmed": 0, "stop_reason": ""}

    monkeypatch.setattr(runner, "prepare", fake_prepare)
    monkeypatch.setattr(runner, "finish_run", fake_finish)
    outs = _run_node(runner.target_node(), message=str(tmp_path))
    assert seen["target"] == tmp_path.resolve() and seen["ran"] and seen["finish"][:2] == ("store", 7) and "failed" not in seen
    assert outs[-1]["confirmed"] == 0 and outs[-1]["target"] == str(tmp_path.resolve())


def test_root_node_answers_with_an_error_instead_of_scanning(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "prepare", lambda target: (_ for _ in ()).throw(AssertionError("must not prepare")))
    assert "error" in _run_node(runner.target_node(), message="what is this?")[-1]
    assert "error" in _run_node(runner.target_node(), message="")[-1]


def test_finish_run_closes_the_run_and_writes_the_reports(tmp_path):
    from scanner.adapter.store import Store

    store = Store(str(tmp_path / "s.db"))
    run = store.start_run(str(tmp_path))
    summary = runner.finish_run(store, run, object(), {"stop_reason": "budget"}, runs_dir=tmp_path / "runs")
    assert summary["stop_reason"] == "budget" and Path(summary["sarif_path"]).is_file() and Path(summary["summary_path"]).is_file()


def test_root_node_reports_a_failed_graph_as_an_answer(tmp_path, monkeypatch):
    seen: dict = {}

    async def boom(ctx, node_input):
        raise RuntimeError("verify round 0 failed: no key")

    run = SimpleNamespace(id=9, finish=lambda status, why: seen.update(status=status, why=why))
    monkeypatch.setattr(runner, "prepare", lambda target: (SimpleNamespace(close=lambda: seen.update(closed=True)), run,
                                                         FunctionNode(func=boom, name="scan", rerun_on_resume=True)))
    out = _run_node(runner.target_node(), message=str(tmp_path))[-1]
    assert "verify round 0 failed" in out["error"] and out["run"] == 9
    assert seen == {"status": "failed", "why": out["error"], "closed": True} or seen["status"] == "failed"
