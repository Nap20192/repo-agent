"""wiring / build_agents for the small graph: every agent from the registry, flags → None, consultants as sub-agents."""

from pathlib import Path

from scanner.app import runner
from scanner.app.graph.workflow import ScanWorkflow
from tests.fakes import FakeRun


def _target(tmp_path: Path) -> Path:
    (tmp_path / "go.mod").write_text("module t\n\ngo 1.22\n")
    (tmp_path / "main.go").write_text("package main\nfunc main() {}\n")
    return tmp_path


def test_wiring_has_every_agent_and_the_consultants(tmp_path, monkeypatch):
    monkeypatch.delenv("THREAT_MODEL", raising=False)
    monkeypatch.delenv("CRITIC", raising=False)
    kw = runner.wiring(FakeRun(), _target(tmp_path), [], "gemini-flash-lite-latest")
    try:
        assert kw["model"].name == "model" and "Go" in kw["model"].instruction  # stack overlay appended for a Go target
        assert {"knowledge", "domain"} <= {getattr(t, "name", "") for t in kw["verifier"].tools}
        assert {"knowledge", "domain"} <= {getattr(t, "name", "") for t in kw["critic"].tools}
        names = {getattr(t, "__name__", "") for t in kw["model"].tools}
        assert "report_finding" not in names and "shell" not in names and "read_file" in names
    finally:
        kw["index"].close()


def test_flags_turn_agents_into_none(tmp_path, monkeypatch):
    monkeypatch.setenv("THREAT_MODEL", "0")
    monkeypatch.setenv("CRITIC", "0")
    kw = runner.wiring(FakeRun(), _target(tmp_path), [], "gemini-flash-lite-latest")
    kw["index"].close()
    assert kw["model"] is None and kw["critic"] is None and kw["verifier"] is not None


def test_build_agent_returns_the_workflow_with_its_index(tmp_path, monkeypatch):
    wf = runner.build_agent(FakeRun(), _target(tmp_path), [], "gemini-flash-lite-latest")
    try:
        assert isinstance(wf, ScanWorkflow) and wf.name == "scan" and wf.index is not None
    finally:
        wf.index.close()


def test_new_agent_overlay_is_appended():
    from scanner.app.agents import new_agent
    a = new_agent("model", "d", "i", [], 5, model="gemini-flash-lite-latest", overlay="GO OVERLAY")
    assert a.instruction.endswith("GO OVERLAY")


def test_session_service_survives_a_concurrent_writer(tmp_path):
    """adk web can post into the CLI run's session while the scan runs (run-23: a 'hello' from the UI made the
    CLI's session object stale and killed the run). Our service re-syncs the timestamp and retries once."""
    import asyncio

    from google.adk.events import Event
    from google.adk.sessions.sqlite_session_service import SqliteSessionService
    from google.genai import types

    from scanner.app.runner import ScanSessionService

    path = str(tmp_path / "s.db")
    ours, other = ScanSessionService(path), SqliteSessionService(path)

    async def go():
        s = await ours.create_session(app_name="a", user_id="u", session_id="x")
        foreign = await other.get_session(app_name="a", user_id="u", session_id="x")
        await other.append_event(foreign, Event(author="user", content=types.Content(role="user", parts=[types.Part(text="hello")])))
        await ours.append_event(s, Event(author="scan", content=types.Content(role="model", parts=[types.Part(text="ok")])))
        back = await ours.get_session(app_name="a", user_id="u", session_id="x")
        return [e.author for e in back.events]
    assert asyncio.run(go()) == ["user", "scan"]
