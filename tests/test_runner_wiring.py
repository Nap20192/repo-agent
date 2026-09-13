"""build_agent wires the specialist registry, router, overlays, DomainModeler and the Knowledge AgentTool into the
Workflow; `wiring` is the inspectable kwargs dict behind it."""

from pathlib import Path

from scanner.app import runner
from scanner.app.agents.registry import REGISTRY, route_name
from scanner.app.pipeline import ScanWorkflow
from tests.fakes import FakeRun


def _target(tmp_path: Path) -> Path:
    (tmp_path / "go.mod").write_text("module t\n\ngo 1.22\n")
    (tmp_path / "main.go").write_text("package main\nfunc main() {}\n")
    return tmp_path


def test_wiring_has_specialists_router_overlay_and_knowledge(tmp_path, monkeypatch):
    monkeypatch.delenv("SPECIALISTS", raising=False)
    kw = runner.wiring(FakeRun(), _target(tmp_path), [], "gemini-flash-lite-latest")
    try:
        assert set(kw["specialists"]) == {s.name for s in REGISTRY} and kw["router"] is route_name
        assert kw["domain_modeler"] is not None and kw["architect"] is not None
        assert "Go" in kw["architect"].instruction  # stack overlay appended for a Go target
        names = {getattr(t, "name", getattr(t, "__name__", "")) for t in kw["specialists"]["dependency"].tools}
        assert "knowledge" in names and "shell" not in names
        assert "knowledge" in {getattr(t, "name", "") for t in kw["specialists"]["dependency_critic"].tools}
    finally:
        kw["index"].close()


def test_specialists_can_be_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECIALISTS", "0")
    kw = runner.wiring(FakeRun(), _target(tmp_path), [], "gemini-flash-lite-latest")
    kw["index"].close()
    assert kw["specialists"] == {} and kw["router"] is route_name  # router with no registry → generic fallback


def test_build_agent_returns_the_workflow_with_its_index(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECIALISTS", "0")
    wf = runner.build_agent(FakeRun(), _target(tmp_path), [], "gemini-flash-lite-latest")
    try:
        assert isinstance(wf, ScanWorkflow) and wf.name == "scan" and wf.index is not None
    finally:
        wf.index.close()


def test_new_architect_overlay_is_appended():
    from scanner.app.agents import new_agent
    a = new_agent("architect", "d", "i", [], 5, model="gemini-flash-lite-latest", overlay="GO OVERLAY")
    assert a.instruction.endswith("GO OVERLAY")


def test_wiring_has_a_triage_agent_with_read_only_tools(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECIALISTS", "0")
    kw = runner.wiring(FakeRun(), _target(tmp_path), [], "gemini-flash-lite-latest")
    names = {getattr(t, "__name__", getattr(t, "name", "")) for t in kw["triage"].tools}
    assert kw["triage"].name == "triage_batch" and names == {"read_file", "grep", "lsp_symbols"}
    monkeypatch.setenv("TRIAGE", "0")
    assert runner.wiring(FakeRun(), _target(tmp_path), [], "gemini-flash-lite-latest")["triage"] is None


def test_threat_modeler_gets_read_file_and_grep(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECIALISTS", "0")
    kw = runner.wiring(FakeRun(), _target(tmp_path), [], "gemini-flash-lite-latest")
    names = {getattr(t, "__name__", "") for t in kw["threat_modeler"].tools}
    assert names == {"consult_owasp", "read_file", "grep"}


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


def test_wiring_has_the_verdict_ladder_agents_recon_and_knobs(tmp_path, monkeypatch):
    """Card 45: review / viability critic / confirm agents with their rosters, the recon closure, the triage
    batch agent, and the knobs the graph needs; switches turn agents into None without changing the graph shape."""
    monkeypatch.setenv("SPECIALISTS", "0")
    kw = runner.wiring(FakeRun(), _target(tmp_path), [], "gemini-flash-lite-latest")
    assert kw["review"].name == "review" and kw["confirm"].name == "confirm" and kw["critic"].name == "viability"
    assert kw["triage"].name == "triage_batch"
    assert {getattr(t, "__name__", "") for t in kw["confirm"].tools} >= {"report_finding", "read_file", "grep"}
    assert callable(kw["recon_fn"]) and set(kw["recon_fn"]()) == {"sources", "sinks", "auth", "config_files"}
    assert kw["triage_batch"] == 10 and kw["triage_parallel"] == 4 and kw["knowledge_cfg"] is None
    monkeypatch.setenv("CRITIC", "0")
    monkeypatch.setenv("RECON", "0")
    kw = runner.wiring(FakeRun(), _target(tmp_path), [], "gemini-flash-lite-latest")
    assert kw["review"] is None and kw["critic"] is None and kw["confirm"] is None and kw["recon_fn"] is None
