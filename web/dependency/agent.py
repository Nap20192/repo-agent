"""`adk web web`: the `dependency` agent alone, wired like in a full run (scanner.app.runner.standalone) — chat with it,
build eval sets from the sessions. Target for its tools: BUGFINDER_TARGET (default samples/02-vulnshop). Built once,
lazily, when the ADK loader first reads `root_agent` (PEP 562) — importing this module has no side effects. State
lands in .state/state.db. Scaffolded with `adk create web/dependency` (card 46).
"""

import os
from pathlib import Path

NAME = "dependency"
_built: dict = {}


def __getattr__(attr: str):
    if attr != "root_agent":
        raise AttributeError(attr)
    if "root_agent" not in _built:
        from scanner.app.runner import load_env, standalone

        load_env()
        target = Path(os.environ.get("BUGFINDER_TARGET") or "samples/02-vulnshop")
        if not target.is_absolute():
            target = Path(__file__).resolve().parents[2] / target  # relative to the repo root, whatever the cwd (adk eval runs elsewhere)
        _built["store"], _built["run"], _built["root_agent"] = standalone(NAME, target)
    return _built["root_agent"]
