"""web/<name>/: one `adk create` app per agent of the project next to `fullscan` (card 46). Each folder's lazy
`root_agent` asks `scanner.app.runner.standalone(name, BUGFINDER_TARGET)` for the agent wired like in a full run."""

import importlib
import sys
from pathlib import Path

import pytest
from google.adk.agents import LlmAgent

from scanner.adapter.scanners import ScanResult
from scanner.app import runner
from tests.fakes import A1, FakeRun

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"
FOLDER_OF: dict[str, str] = {}  # web folder per agent when it differs from the name (none today)


def _target(tmp_path: Path) -> Path:
    (tmp_path / "go.mod").write_text("module t\n\ngo 1.22\n")
    (tmp_path / "main.go").write_text("package main\nfunc main() {}\n")
    return tmp_path


# --- the roster -------------------------------------------------------------------------------------------

def test_roster_is_the_five_agents():
    assert set(runner.ROSTER) == {"model", "verify", "critic"}


def test_one_web_app_per_roster_name_next_to_fullscan():
    apps = {p.name for p in WEB.iterdir() if p.is_dir() and (p / "agent.py").is_file()}
    assert apps == {FOLDER_OF.get(n, n) for n in runner.ROSTER} | {"fullscan"}
    for app in apps - {"fullscan"}:
        assert (WEB / app / "__init__.py").read_text(encoding="utf-8").startswith("from . import agent")
        assert not (WEB / app / ".env").exists(), f"web/{app}/.env would override the root .env under adk web"


def test_web_apps_do_not_shadow_stdlib():
    for p in WEB.iterdir():
        assert p.name not in sys.stdlib_module_names, f"web/{p.name} would shadow the stdlib module"


# --- standalone -------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["verify", "critic", "model"])
def test_standalone_builds_the_named_agent_with_its_run_tools(name, tmp_path, monkeypatch):
    monkeypatch.setenv("STATE_PATH", str(tmp_path / "state.db"))
    monkeypatch.setenv("CRITIC", "0")
    monkeypatch.setattr(runner, "model_from_env", lambda s: "gemini-flash-lite-latest")
    monkeypatch.setattr(runner, "_shared", {})
    monkeypatch.setattr(runner.scanners, "scan", lambda *a, **k: ScanResult(anchors=[A1], ran=["gosec"]))
    store, run, agent = runner.standalone(name, _target(tmp_path))
    try:
        assert isinstance(agent, LlmAgent) and agent.name == name
        tools = {getattr(t, "__name__", getattr(t, "name", "")) for t in agent.tools}
        if name == "model":
            assert "read_file" in tools and not ({"report_finding", "disprove_finding", "shell"} & tools)  # a document stage
        elif name == "critic":
            assert {"read_file", "disprove_finding", "osv_query"} <= tools and "report_finding" not in tools
        else:
            assert {"read_file", "report_finding", "osv_query"} <= tools  # investigators report only through the gate
        assert run.target == str(tmp_path.resolve()) and [a.id for a in run.anchors()] == [A1.id]  # pre-pass ran once
        assert run.artifact("scan") == {"anchors": 1, "ran": ["gosec"], "failed": {}}
        assert runner.standalone("verify", tmp_path)[1] is run  # every app of the process shares the run
    finally:
        store.close()


def test_standalone_rejects_unknown_names_and_missing_targets(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "_shared", {})
    with pytest.raises(KeyError):
        runner.standalone("nobody", _target(tmp_path))
    with pytest.raises(FileNotFoundError):
        runner.standalone("verify", tmp_path / "missing")


def test_standalone_names_cover_the_roster(tmp_path, monkeypatch):
    """Every ROSTER name resolves to an agent of that name out of one `wiring` (no roster member is None)."""
    kw = runner.wiring(FakeRun(), _target(tmp_path), [], "gemini-flash-lite-latest")
    try:
        built = {a.name for a in kw.values() if isinstance(a, LlmAgent)}
        assert built == set(runner.ROSTER)
    finally:
        kw["index"].close()


# --- the apps' lazy root_agent -----------------------------------------------------------------------------

def _load(monkeypatch, app: str, target_env: str | None):
    monkeypatch.syspath_prepend(str(WEB))
    sys.modules.pop(f"{app}.agent", None)
    sys.modules.pop(app, None)
    mod = importlib.import_module(f"{app}.agent")
    seen: dict = {}

    def fake_standalone(name, target):
        seen["name"], seen["target"] = name, target
        return "store", "run", "agent"

    monkeypatch.setattr("scanner.app.runner.standalone", fake_standalone)
    monkeypatch.setattr("scanner.app.runner.load_env", lambda: None)
    if target_env is None:
        monkeypatch.delenv("BUGFINDER_TARGET", raising=False)
    else:
        monkeypatch.setenv("BUGFINDER_TARGET", target_env)
    assert mod.root_agent == "agent"
    return seen


def test_app_root_agent_is_lazy_and_names_its_agent(monkeypatch):
    assert _load(monkeypatch, "verify", None) == {"name": "verify", "target": ROOT / "samples/02-vulnshop"}


def test_app_target_from_env(monkeypatch, tmp_path):
    assert _load(monkeypatch, "critic", str(tmp_path))["target"] == tmp_path  # absolute: as is
    assert _load(monkeypatch, "critic", "ewq/bakery")["target"] == ROOT / "ewq/bakery"  # relative: from the repo root
