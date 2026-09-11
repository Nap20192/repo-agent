"""`adk web web --port 8080`: the same graph as `scan full`, driven from the ADK dev UI.

Target comes from BUGFINDER_TARGET (default samples/02-vulnshop); the pre-pass runs once at import,
like git-agent3's `scan web`. State lands in .state/state.db; SARIF is not exported in web mode.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # adk web puts only the agents dir on sys.path

from scanner.app.runner import load_env, prepare

load_env()
_store, run, root_agent = prepare(Path(os.environ.get("BUGFINDER_TARGET", "samples/02-vulnshop")))
