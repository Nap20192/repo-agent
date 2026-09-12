"""build_agent wires the specialist registry, router, overlays, DomainModeler and the Knowledge AgentTool."""

from pathlib import Path

from scanner.app import runner
from scanner.app.specialists import REGISTRY, route_name
from tests.fakes import FakeRun


def _target(tmp_path: Path) -> Path:
    (tmp_path / "go.mod").write_text("module t\n\ngo 1.22\n")
    (tmp_path / "main.go").write_text("package main\nfunc main() {}\n")
    return tmp_path


def test_build_agent_wires_specialists(tmp_path, monkeypatch):
    monkeypatch.delenv("SPECIALISTS", raising=False)
    agent = runner.build_agent(FakeRun(), _target(tmp_path), [], "gemini-flash-lite-latest")
    try:
        assert set(agent.specialists) == {s.name for s in REGISTRY} and agent.router is route_name
        assert agent.domain_modeler is not None and agent.architect is not None
        assert "Go" in agent.architect.instruction  # stack overlay appended for a Go target
        names = {getattr(t, "name", getattr(t, "__name__", "")) for t in agent.specialists["dependency"].tools}
        assert "knowledge" in names and "shell" not in names
        assert "knowledge" in {getattr(t, "name", "") for t in agent.specialists["dependency_critic"].tools}
    finally:
        agent.index.close() if getattr(agent, "index", None) else None


def test_specialists_can_be_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECIALISTS", "0")
    agent = runner.build_agent(FakeRun(), _target(tmp_path), [], "gemini-flash-lite-latest")
    assert agent.specialists == {} and agent.router is route_name  # router with no registry → generic fallback


def test_pipeline_switch_selects_v2_or_v3(tmp_path, monkeypatch):
    """PIPELINE=v3 wires the Workflow graph with the same knobs; the default stays the v2 BaseAgent (card 43 step 6)."""
    from scanner.app.pipeline_v2 import PipelineV2
    from scanner.app.pipeline_v3 import ScanWorkflow
    from scanner.core.settings import Settings

    assert Settings.from_env({}).pipeline == "v2" and Settings.from_env({"PIPELINE": "v3"}).pipeline == "v3"
    monkeypatch.setenv("SPECIALISTS", "0")
    v2 = runner.build_agent(FakeRun(), _target(tmp_path), [], "gemini-flash-lite-latest")
    assert isinstance(v2, PipelineV2)
    monkeypatch.setenv("PIPELINE", "v3")
    v3 = runner.build_agent(FakeRun(), _target(tmp_path), [], "gemini-flash-lite-latest")
    try:
        assert isinstance(v3, ScanWorkflow) and v3.name == "scan_v3" and v3.index is not None
    finally:
        v3.index.close()
