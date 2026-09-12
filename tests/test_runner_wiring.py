"""build_agent wires the specialist registry, router, overlays, DomainModeler and the Knowledge AgentTool into the
Workflow; `wiring` is the inspectable kwargs dict behind it."""

from pathlib import Path

from scanner.app import runner
from scanner.app.pipeline import ScanWorkflow
from scanner.app.specialists import REGISTRY, route_name
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
    from scanner.app.agents import new_architect
    a = new_architect("gemini-flash-lite-latest", [], 5, overlay="GO OVERLAY")
    assert a.instruction.endswith("GO OVERLAY")


def test_wiring_has_a_triage_agent_with_read_only_tools(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECIALISTS", "0")
    kw = runner.wiring(FakeRun(), _target(tmp_path), [], "gemini-flash-lite-latest")
    names = {getattr(t, "__name__", getattr(t, "name", "")) for t in kw["triage"].tools}
    assert kw["triage"].name == "triage" and names == {"read_file", "grep", "lsp_symbols"}
    monkeypatch.setenv("TRIAGE", "0")
    assert runner.wiring(FakeRun(), _target(tmp_path), [], "gemini-flash-lite-latest")["triage"] is None


def test_threat_modeler_gets_read_file_and_grep(tmp_path, monkeypatch):
    monkeypatch.setenv("SPECIALISTS", "0")
    kw = runner.wiring(FakeRun(), _target(tmp_path), [], "gemini-flash-lite-latest")
    names = {getattr(t, "__name__", "") for t in kw["threat_modeler"].tools}
    assert names == {"consult_owasp", "read_file", "grep"}
