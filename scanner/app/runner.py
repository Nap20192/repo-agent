"""Runner: env/model, wiring of the graph for one run (`build_agent`), the pre-pass (`prepare`) and the
ADK run in a persistent session (`scan_full`). The CLI (scanner/main.py) and `adk web` (web/) both use this."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path

from google.adk.apps import App
from google.adk.runners import Runner
from google.adk.sessions.sqlite_session_service import SqliteSessionService
from google.genai import types

from scanner import core
from scanner.adapter import entrypoints, fs, static
from scanner.adapter.index import build_index
from scanner.adapter.knowledge import KnowledgeConfig
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
from scanner.app.settings import Settings, apply_dotenv
from scanner.app.specialists import architect_overlay, route_name
from scanner.app.specialists import build as build_specialists
from scanner.core import Candidate
from scanner.core.ports import Index

log = logging.getLogger("scanner.runner")

APP_NAME = "fullscan"  # = the agent folder under web/, so CLI sessions show in the same app of the ADK UI
SESSION_USER = "user"  # the ADK dev UI lists this user's sessions


def load_env(path: str = ".env") -> None:
    """Compat wrapper: merge `.env` into the process environment (see scanner.app.settings.apply_dotenv)."""
    apply_dotenv(path)


def model_from_env(settings: Settings | None = None):
    """The model to run: a Gemini model name with GOOGLE_API_KEY, else an OpenAI-compatible LiteLlm endpoint."""
    s = settings or Settings.from_env()
    if s.google_api_key:
        return s.llm_model or "gemini-flash-lite-latest"  # cheapest Gemini by default
    if s.llm_api_key:
        from google.adk.models.lite_llm import LiteLlm

        base = s.llm_base_url.rstrip("/")
        if base and not base.endswith("/v1"):
            base += "/v1"
        return LiteLlm(model=f"openai/{s.llm_model or 'gpt-4.1'}", api_base=base or None, api_key=s.llm_api_key)
    raise SystemExit("no model: set GOOGLE_API_KEY or LLM_API_KEY (+LLM_BASE_URL)")


async def run_session(agent, target: str, run_id: int, settings: Settings | None = None) -> dict:
    """Run the graph in a persistent ADK session (the file `adk web` reads) so the run shows in the UI."""
    s = settings or Settings.from_env()
    svc = SqliteSessionService(s.sessions_path)
    sid = f"run-{run_id}-{Path(target).name}"
    app = App(name=APP_NAME, root_agent=agent, events_compaction_config=compaction_config(model_from_env(s), s))
    runner = Runner(app=app, session_service=svc)
    await svc.create_session(app_name=APP_NAME, user_id=SESSION_USER, session_id=sid)
    log.info("session %s (user %s): adk web → /dev-ui/?app=%s", sid, SESSION_USER, APP_NAME)
    msg = types.Content(role="user", parts=[types.Part(text=f"scan target: {target}")])
    async for _ in runner.run_async(user_id=SESSION_USER, session_id=sid, new_message=msg):
        pass
    s = await svc.get_session(app_name=APP_NAME, user_id=SESSION_USER, session_id=sid)
    return dict(s.state) if s else {}


def build_agent(run, target: Path, entries: list[Candidate], model, index: Index | None = None,
                settings: Settings | None = None):
    """Wire the staged graph for one run: Architect → ThreatModeler → Reconciler → Investigator ⇄ queue → Critic."""
    s = settings or Settings.from_env()
    index = index or build_index(target, max_files=s.index_max_files, max_bytes=s.index_max_bytes)  # LSP per language, grep fallback
    has_symbol = index.has_symbol
    langs = fs.detect_langs(target)
    specialists = build_specialists(model, run, target, index) if s.specialists else {}
    for name in ("dependency", "dependency_critic"):  # the Knowledge consultant answers open questions as an AgentTool
        if name in specialists:  # one instance each: the AgentTool's budget counter must not be shared
            specialists[name].tools.append(make_consult_knowledge(model, s.knowledge_max_calls))
    return PipelineV2(
        architect=new_architect(model, architect_tools(run, target, index=index), s.architect_max_calls,
                                overlay=architect_overlay(langs)) if s.threat_model else None,
        domain_modeler=new_domain_modeler(model, architect_tools(run, target, index=index), s.domain_modeler_max_calls)
        if s.threat_model and s.domain_model else None,
        threat_modeler=new_threat_modeler(model, [consult_owasp], s.threat_modeler_max_calls) if s.threat_model else None,
        specialists=specialists,
        router=route_name,
        verifier=new_verifier(model, verifier_tools(run, target, index=index), s.verifier_max_calls),
        critic=new_critic(model, critic_tools(run, target, index=index), s.critic_max_calls) if s.critic else None,
        store=run,
        target=str(target),
        has_anchor=lambda i: run.anchor(i) is not None,
        has_symbol=has_symbol,
        locate=index.find_symbol,
        entry_points_fn=lambda: entries,
        max_rounds=s.max_rounds,
        max_hyps=s.max_hyps,
        max_parallel=s.max_parallel,
        json_retry=s.json_retry,
        stage_timeout=s.stage_timeout,
    )


def prepare(target: Path, deps: bool = False, settings: Settings | None = None):
    """Store → run → pre-pass (scanners → anchors) → entry points → wired graph. Returns (store, run, agent)."""
    s = settings or Settings.from_env()
    setup_tracing(s)
    target = target.resolve()
    if not target.is_dir():
        raise FileNotFoundError(f"target {target} is not a directory")
    store = Store(s.state_path)
    run = store.start_run(str(target))
    try:
        run.knowledge = KnowledgeConfig.from_settings(s)  # calibration reads EPSS/KEV through the run's config
        res = static.scan(target, skip_deps=not deps and s.skip_deps, knowledge_cfg=run.knowledge)
        for tool, why in res.failed.items():
            log.warning("static: %s failed: %s", tool, why)
        run.save_anchors(res.anchors)
        by_tool = {t: sum(a.tool == t for a in res.anchors) for t in res.ran}
        log.info("pre-pass: %d anchors — %s%s", len(res.anchors),
                 ", ".join(f"{t} {n}" for t, n in by_tool.items()),
                 f"; failed: {', '.join(res.failed)}" if res.failed else "")
        index = build_index(target, max_files=s.index_max_files, max_bytes=s.index_max_bytes)
        agent = build_agent(run, target, entrypoints.entry_points(target), model_from_env(s), index, s)
    except Exception as e:
        run.finish("failed", str(e))
        store.close()
        raise
    agent.index = index  # closed by scan_full (the web agent lives as long as the server)
    return store, run, agent

def scan_full(target: Path, deps: bool = False, runs_dir: Path = Path(".runs"), settings: Settings | None = None) -> dict:
    """One full run. Returns the summary dict (+ 'stop_reason', 'summary_path', 'sarif_path')."""
    s = settings or Settings.from_env()  # the only env read of a run; everything below receives values
    store, run, agent = prepare(target, deps, s)
    try:
        state = asyncio.run(run_session(agent, run.target, run.id, s))
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
