"""web/fullscan/agent.py: the root node scans the target named in the message; importing has no side effects."""

import importlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_root_agent_is_the_target_node(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "web"))
    sys.modules.pop("fullscan.agent", None)
    monkeypatch.setattr("scanner.app.runner.load_env", lambda: None)
    mod = importlib.import_module("fullscan.agent")
    assert mod.root_agent.name == "fullscan"
