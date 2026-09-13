"""web/fullscan/agent.py: the lazy `root_agent` picks its target from BUGFINDER_TARGET, empty meaning the default."""

import importlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load(monkeypatch, target_env: str | None):
    monkeypatch.syspath_prepend(str(ROOT / "web"))
    sys.modules.pop("fullscan.agent", None)
    mod = importlib.import_module("fullscan.agent")
    seen: dict = {}

    def fake_prepare(target):
        seen["target"] = target
        return "store", "run", "agent"

    monkeypatch.setattr("scanner.app.runner.prepare", fake_prepare)
    monkeypatch.setattr("scanner.app.runner.load_env", lambda: None)
    if target_env is None:
        monkeypatch.delenv("BUGFINDER_TARGET", raising=False)
    else:
        monkeypatch.setenv("BUGFINDER_TARGET", target_env)
    assert mod.root_agent == "agent"
    return seen["target"]


def test_empty_target_means_default(monkeypatch):
    assert _load(monkeypatch, "") == Path("samples/02-vulnshop")
    assert _load(monkeypatch, None) == Path("samples/02-vulnshop")


def test_target_from_env(monkeypatch, tmp_path):
    assert _load(monkeypatch, str(tmp_path)) == tmp_path
