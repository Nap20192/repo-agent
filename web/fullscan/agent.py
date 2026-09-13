"""`adk web web --port 8080`: the same graph as `scan full`, driven from the ADK dev UI.

Target comes from BUGFINDER_TARGET (default samples/02-vulnshop). The pre-pass runs once, lazily, when the
ADK loader first reads `root_agent` (PEP 562 module __getattr__) — importing this module has no side effects.
State lands in .state/state.db; SARIF is not exported in web mode.
"""

import os
from pathlib import Path

_built: dict = {}


def __getattr__(name: str):
    if name != "root_agent":
        raise AttributeError(name)
    if "root_agent" not in _built:
        from scanner.app.runner import load_env, prepare

        load_env()
        _built["store"], _built["run"], _built["root_agent"] = prepare(Path(os.environ.get("BUGFINDER_TARGET") or "samples/02-vulnshop"))
    return _built["root_agent"]
