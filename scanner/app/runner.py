"""Runner: env/model, wiring of the graph for one run (`build_agent`), the pre-pass (`prepare`) and the
ADK run in a persistent session (`scan_full`). The CLI (scanner/main.py) and `adk web` (web/) both use this."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path

from google.adk.apps import App
from google.adk.runners import Runner
from google.adk.sessions.sqlite_session_service import SqliteSessionService
from google.genai import types

from scanner import core
from scanner.adapter import static
from scanner.adapter.index import build_index
from scanner.adapter.owasp import consult_owasp
from scanner.adapter.store import Store
from scanner.adapter.tools import (
    architect_tools,
    critic_tools,
    verifier_tools,
)
from scanner.app.agents import (
    new_architect,
    new_critic,
    new_threat_modeler,
    new_verifier,
)
from scanner.app.domain import new_domain_modeler
from scanner.app.knowledge_agent import make_consult_knowledge
from scanner.app.observe import compaction_config, setup_tracing
from scanner.app.pipeline_v2 import PipelineV2
from scanner.app.specialists import ROUTER, architect_overlay
from scanner.app.specialists import build as build_specialists
from scanner.core import Candidate
from scanner.core.ports import Index

log = logging.getLogger("scanner.runner")

APP_NAME = "fullscan"  # = the agent folder under web/, so CLI sessions show in the same app of the ADK UI
SESSION_USER = "user"  # the ADK dev UI lists this user's sessions


def load_env(path: str = ".env") -> None:
    p = Path(path)
    if not p.is_file():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip("'\""))

def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, "") or default)
    except ValueError:
        return default

def model_from_env():
    if os.environ.get("GOOGLE_API_KEY"):
        return os.environ.get("LLM_MODEL") or "gemini-flash-lite-latest"  # cheapest Gemini by default
    if os.environ.get("LLM_API_KEY"):
        from google.adk.models.lite_llm import LiteLlm

        base = os.environ.get("LLM_BASE_URL", "").rstrip("/")
        if base and not base.endswith("/v1"):
            base += "/v1"
        return LiteLlm(
            model=f"openai/{os.environ.get('LLM_MODEL') or 'gpt-4.1'}",
            api_base=base or None,
            api_key=os.environ["LLM_API_KEY"],
        )
    raise SystemExit("no model: set GOOGLE_API_KEY or LLM_API_KEY (+LLM_BASE_URL)")


def sessions_path() -> str:
    return os.environ.get("SESSIONS_PATH") or ".state/sessions.db"


async def run_session(agent, target: str, run_id: int) -> dict:
    """Run the graph in a persistent ADK session (the file `adk web` reads) so the run shows in the UI."""
    svc = SqliteSessionService(sessions_path())
    sid = f"run-{run_id}-{Path(target).name}"
    app = App(name=APP_NAME, root_agent=agent, events_compaction_config=compaction_config(model_from_env()))
    runner = Runner(app=app, session_service=svc)
    await svc.create_session(app_name=APP_NAME, user_id=SESSION_USER, session_id=sid)
    log.info("session %s (user %s): adk web → /dev-ui/?app=%s", sid, SESSION_USER, APP_NAME)
    msg = types.Content(role="user", parts=[types.Part(text=f"scan target: {target}")])
    async for _ in runner.run_async(user_id=SESSION_USER, session_id=sid, new_message=msg):
        pass
    s = await svc.get_session(app_name=APP_NAME, user_id=SESSION_USER, session_id=sid)
    return dict(s.state) if s else {}


def build_agent(run, target: Path, entries: list[Candidate], model, index: Index | None = None):
    """Wire the staged graph for one run: Architect → ThreatModeler → Reconciler → Investigator ⇄ queue → Critic."""
    index = index or build_index(target)  # LSP per language (gopls/pyright/tsserver), grep fallback
    has_symbol = index.has_symbol
    tm = os.environ.get("THREAT_MODEL") != "0"
    langs = static.detect_langs(target)
    specialists = {} if os.environ.get("SPECIALISTS") == "0" else build_specialists(model, run, target, index)
    for name in ("dependency", "dependency_critic"):  # the Knowledge consultant answers open questions as an AgentTool
        if name in specialists:  # one instance each: the AgentTool's budget counter must not be shared
            specialists[name].tools.append(make_consult_knowledge(model, _env_int("KNOWLEDGE_MAX_MODEL_CALLS", 10)))
    return PipelineV2(
        architect=new_architect(model, architect_tools(run, target, index=index), _env_int("ARCHITECT_MAX_MODEL_CALLS", 40),
                                overlay=architect_overlay(langs)) if tm else None,
        domain_modeler=new_domain_modeler(model, architect_tools(run, target, index=index), _env_int("DOMAIN_MODELER_MAX_MODEL_CALLS", 12))
        if tm and os.environ.get("DOMAIN_MODEL") != "0" else None,
        threat_modeler=new_threat_modeler(model, [consult_owasp], _env_int("THREAT_MODELER_MAX_MODEL_CALLS", 6)) if tm else None,
        specialists=specialists,
        router=ROUTER,
        verifier=new_verifier(model, verifier_tools(run, target, index=index), _env_int("VERIFIER_MAX_MODEL_CALLS", 30)),
        critic=None if os.environ.get("CRITIC") == "0" else
        new_critic(model, critic_tools(run, target, index=index), _env_int("CRITIC_MAX_MODEL_CALLS", 20)),
        store=run,
        target=str(target),
        has_anchor=lambda i: run.anchor(i) is not None,
        has_symbol=has_symbol,
        locate=index.find_symbol,
        entry_points_fn=lambda: entries,
        max_rounds=_env_int("BUGFINDER_MAX_ROUNDS", 4),
        max_hyps=_env_int("BUGFINDER_MAX_HYPS", 8),
        max_parallel=_env_int("BUGFINDER_MAX_PARALLEL", 3),
    )


def prepare(target: Path, deps: bool = False):
    """Store → run → pre-pass (scanners → anchors) → entry points → wired graph. Returns (store, run, agent)."""
    setup_tracing()
    target = target.resolve()
    if not target.is_dir():
        raise FileNotFoundError(f"target {target} is not a directory")
    store = Store(os.environ.get("STATE_PATH") or ".state/state.db")
    run = store.start_run(str(target))
    try:
        res = static.scan(target, skip_deps=not deps and os.environ.get("SKIP_DEPS") == "1")
        for tool, why in res.failed.items():
            log.warning("static: %s failed: %s", tool, why)
        run.save_anchors(res.anchors)
        by_tool = {t: sum(a.tool == t for a in res.anchors) for t in res.ran}
        log.info("pre-pass: %d anchors — %s%s", len(res.anchors),
                 ", ".join(f"{t} {n}" for t, n in by_tool.items()),
                 f"; failed: {', '.join(res.failed)}" if res.failed else "")
        index = build_index(target)
        agent = build_agent(run, target, static.entry_points(target), model_from_env(), index)
    except Exception as e:
        run.finish("failed", str(e))
        store.close()
        raise
    agent.index = index  # closed by scan_full (the web agent lives as long as the server)
    return store, run, agent

def scan_full(target: Path, deps: bool = False, runs_dir: Path = Path(".runs")) -> dict:
    """One full run. Returns the summary dict (+ 'stop_reason', 'summary_path', 'sarif_path')."""
    store, run, agent = prepare(target, deps)
    try:
        state = asyncio.run(run_session(agent, run.target, run.id))
    except Exception as e:
        run.finish("failed", str(e))
        store.close()
        raise
    finally:
        idx = getattr(agent, "index", None)
        if idx is not None:
            idx.close()  # LSP servers die with the run
    stop = state.get(core.STATE_STOP_REASON) or ("budget" if state.get(core.STATE_BUDGET_EXHAUSTED) else "")
    run.finish("done", stop)
    out = runs_dir / str(int(time.time()))
    out.mkdir(parents=True, exist_ok=True)
    sarif = run.write_report(out)
    summary_path = run.write_summary(out)
    summary = json.loads(summary_path.read_text())
    summary.update(stop_reason=stop, sarif_path=str(sarif), summary_path=str(summary_path))
    store.close()
    if stop:
        log.warning("run stopped early: %s", stop)
    return summary
