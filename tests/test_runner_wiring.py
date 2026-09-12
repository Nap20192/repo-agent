"""build_agent wires the specialist registry, router, overlays, DomainModeler and the Knowledge AgentTool."""

from pathlib import Path

from scanner.app import runner
from scanner.app.specialists import REGISTRY, ROUTER
from tests.test_graph import FakeRun


def _target(tmp_path: Path) -> Path:
    (tmp_path / "go.mod").write_text("module t\n\ngo 1.22\n")
    (tmp_path / "main.go").write_text("package main\nfunc main() {}\n")
    return tmp_path


def test_build_agent_wires_specialists(tmp_path, monkeypatch):
    monkeypatch.delenv("SPECIALISTS", raising=False)
    agent = runner.build_agent(FakeRun(), _target(tmp_path), [], "gemini-flash-lite-latest")
    try:
        assert set(agent.specialists) == {s.name for s in REGISTRY} and agent.router is ROUTER
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
    assert agent.specialists == {} and agent.router is ROUTER  # router with no registry → generic fallback
