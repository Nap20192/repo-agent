"""Runner: env/model, wiring of the graph for one run (`build_agent`), the pre-pass (`prepare`) and the
ADK run in a persistent session (`scan_full`). The CLI (scanner/main.py) and `adk web` (web/) both use this."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import subprocess
import time
from pathlib import Path

from google.adk.agents import LlmAgent
from google.adk.apps import App
from google.adk.errors._stale_session_error import StaleSessionError
from google.adk.runners import Runner
from google.adk.sessions.sqlite_session_service import SqliteSessionService
from google.adk.tools.agent_tool import AgentTool
from google.adk.workflow import FunctionNode
from google.genai import types

from scanner import core
from scanner.adapter import entrypoints, fs, scanners
from scanner.adapter.index import build_index
from scanner.adapter.knowledge import KnowledgeConfig
from scanner.adapter.store import Store
from scanner.adapter.tools import ToolContext
from scanner.app.agents import build
from scanner.app.agents.registry import AGENTS, ROSTER, architect_overlay
from scanner.app.graph.helpers import why
from scanner.app.graph.workflow import build_workflow
from scanner.app.observe import setup_tracing
from scanner.app.settings import Settings, apply_dotenv
from scanner.app.target import resolve_target
from scanner.core import Candidate
from scanner.core.ports import Index

log = logging.getLogger("scanner.runner")

APP_NAME = "fullscan"  # = the agent folder under web/, so CLI sessions show in the same app of the ADK UI
SESSION_USER = "user"  # the ADK dev UI lists this user's sessions

__all__ = ["ROSTER", "build_agent", "finish_run", "prepare", "scan_full", "standalone", "target_node", "wiring"]  # ROSTER: every agent name (web/<name>)


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


class ScanSessionService(SqliteSessionService):
    """SqliteSessionService that tolerates one concurrent writer: `adk web` lets a person post into the session
    of a running CLI scan, which bumps `update_time` and makes the CLI's session object stale (ADK then refuses
    every later append). We re-sync the timestamp from storage and retry once; the foreign event stays."""

    async def append_event(self, session, event):
        try:
            return await super().append_event(session=session, event=event)
        except StaleSessionError:
            fresh = await self.get_session(app_name=session.app_name, user_id=session.user_id, session_id=session.id)
            if fresh is None:
                raise
            log.warning("session %s was updated elsewhere (adk web?) — re-synced, continuing", session.id)
            session.last_update_time = fresh.last_update_time
            return await super().append_event(session=session, event=event)


async def run_session(agent, target: str, run_id: int, settings: Settings | None = None) -> dict:
    """Run the graph in a persistent ADK session (the file `adk web` reads) so the run shows in the UI."""
    s = settings or Settings.from_env()
    svc = ScanSessionService(s.sessions_path)
    sid = f"run-{run_id}-{Path(target).name}"
    app = App(name=APP_NAME, root_agent=agent)
    runner = Runner(app=app, session_service=svc)
    await svc.create_session(app_name=APP_NAME, user_id=SESSION_USER, session_id=sid)
    log.info("session %s (user %s): adk web → /dev-ui/?app=%s", sid, SESSION_USER, APP_NAME)
    msg = types.Content(role="user", parts=[types.Part(text=f"scan target: {target}")])
    async for _ in runner.run_async(user_id=SESSION_USER, session_id=sid, new_message=msg):
        pass
    s = await svc.get_session(app_name=APP_NAME, user_id=SESSION_USER, session_id=sid)
    return dict(s.state) if s else {}


def build_agents(model, run, target: Path, index: Index, s: Settings) -> dict[str, LlmAgent | None]:
    """Every agent of the registry for one run, by name — None when its Settings flag is off (the graph keeps the
    node as a no-op of the same name). One fresh consultant AgentTool (knowledge / domain) per agent that consults it
    (own budget each); the Model agent gets the stack overlay of the target's languages."""
    ctx = ToolContext(target, run, index=index, settings=s)
    overlay = architect_overlay(fs.detect_langs(target))
    out: dict[str, LlmAgent | None] = {}
    for spec in AGENTS.values():
        if spec.flag and not getattr(s, spec.flag):
            out[spec.name] = None
            continue
        extra = [AgentTool(build(AGENTS[c], model, ctx, s)) for c in spec.consults] or None
        out[spec.name] = build(spec, model, ctx, s, overlay=overlay if spec.name == "model" else "", extra_tools=extra)
    return out


def wiring(run, target: Path, entries: list[Candidate], model, index: Index | None = None,
           settings: Settings | None = None, deps: bool = False) -> dict:
    """Everything the graph needs for one run, by keyword: the agents, the store, the index-backed callables, the knobs."""
    s = settings or Settings.from_env()
    index = index or build_index(target, max_files=s.index_max_files, max_bytes=s.index_max_bytes)  # LSP per language, grep fallback
    agents = build_agents(model, run, target, index, s)
    return {
        "index": index,
        "scan_fn": lambda: scanners.scan(target, skip_deps=not deps and s.skip_deps, knowledge_cfg=run.knowledge),
        "model": agents["model"],
        "verifier": agents["verify"],
        "critic": agents["critic"],
        "knowledge_cfg": getattr(run, "knowledge", None),
        "store": run,
        "target": str(target),
        "has_anchor": lambda i: run.anchor(i) is not None,
        "has_symbol": index.has_symbol,
        "locate": index.find_symbol,
        "entry_points_fn": lambda: entries,
        "max_rounds": s.max_rounds,
        "max_hyps": s.max_hyps,
        "max_parallel": s.max_parallel,
        "stage_timeout": s.stage_timeout,
    }


def build_agent(run, target: Path, entries: list[Candidate], model, index: Index | None = None,
                settings: Settings | None = None, deps: bool = False):
    """The ADK Workflow for one run: the static Shannon graph (docs/adr/0008), scanners included as its first node."""
    return build_workflow(**wiring(run, target, entries, model, index, settings, deps=deps))


def prepare(target: Path, deps: bool = False, settings: Settings | None = None):
    """Store → run → index → entry points → wired graph (the scanners run inside it). Returns (store, run, agent)."""
    s = settings or Settings.from_env()
    setup_tracing(s)
    target = target.resolve()
    if not target.is_dir():
        raise FileNotFoundError(f"target {target} is not a directory")
    store = Store(s.state_path)
    run = store.start_run(str(target))
    try:
        run.knowledge = KnowledgeConfig.from_settings(s)  # calibration reads EPSS/KEV through the run's config
        index = build_index(target, max_files=s.index_max_files, max_bytes=s.index_max_bytes)
        agent = build_agent(run, target, entrypoints.entry_points(target), model_from_env(s), index, s, deps=deps)
    except Exception as e:
        run.finish("failed", str(e))
        store.close()
        raise
    agent.index = index  # closed by scan_full (the web agent lives as long as the server)
    return store, run, agent

_shared: dict[tuple[str, str], tuple] = {}  # ponytail: one wired run per (state_path, target) per process, for adk web


def standalone(name: str, target: Path, settings: Settings | None = None):
    """One ROSTER agent alone, for `adk web web` (web/<name>/agent.py): the real tools against `target`, every stage
    switch forced on so no roster member comes back None. All apps of one `adk web` process share one run per
    target (one Store run, one Index, one pre-pass so investigators find anchors and critics find the findings the
    investigators reported). Returns (store, run, agent) like `prepare`; the store lives as long as the process."""
    if name not in ROSTER:
        raise KeyError(f"{name!r} is not a roster agent: {', '.join(ROSTER)}")
    s = dataclasses.replace(settings or Settings.from_env(), threat_model=True, critic=True)
    target = target.resolve()
    if not target.is_dir():
        raise FileNotFoundError(f"target {target} is not a directory")
    key = (s.state_path, str(target))
    if key not in _shared:
        _shared[key] = _shared_run(target, s)
    store, run, agents = _shared[key]
    return store, run, agents[name]


def _shared_run(target: Path, s: Settings) -> tuple:
    """Store run + index + pre-pass + every ROSTER agent for `target`, built once per process."""
    store = Store(s.state_path)
    run = store.start_run(str(target))
    try:
        run.knowledge = KnowledgeConfig.from_settings(s)
        index = build_index(target, max_files=s.index_max_files, max_bytes=s.index_max_bytes)
        model = model_from_env(s)
        res = scanners.scan(target, skip_deps=s.skip_deps, knowledge_cfg=run.knowledge)  # the graph's `scan` node, once
        run.save_anchors(res.anchors)
        run.put_artifact("scan", {"anchors": len(res.anchors), "ran": res.ran, "failed": res.failed})
        agents = build_agents(model, run, target, index, s)
    except Exception as e:
        run.finish("failed", str(e))
        store.close()
        raise
    return store, run, agents


def finish_run(store, run, agent, state, runs_dir: Path = Path(".runs")) -> dict:
    """Close a run after its graph ran: LSP index down, run status + stop reason, SARIF + summary under runs_dir/<ts>.
    Returns the summary dict (+ 'stop_reason', 'summary_path', 'sarif_path')."""
    idx = getattr(agent, "index", None)
    if idx is not None:
        idx.close()  # LSP servers die with the run
    stop = state.get(core.STATE_STOP_REASON) or ("budget" if state.get(core.STATE_BUDGET_EXHAUSTED) else "")
    run.finish("done", stop)
    out = runs_dir / str(int(time.time()))
    out.mkdir(parents=True, exist_ok=True)
    sarif = run.write_report(out)
    summary_path = run.write_summary(out)
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary.update(stop_reason=stop, sarif_path=str(sarif), summary_path=str(summary_path))
    store.close()
    if stop:
        log.warning("run stopped early: %s", stop)
    return summary


def scan_full(target: Path, deps: bool = False, runs_dir: Path = Path(".runs"), settings: Settings | None = None) -> dict:
    """One full run. Returns the summary dict (+ 'stop_reason', 'summary_path', 'sarif_path')."""
    s = settings or Settings.from_env()  # the only env read of a run; everything below receives values
    store, run, agent = prepare(target, deps, s)
    try:
        state = asyncio.run(run_session(agent, run.target, run.id, s))
    except Exception as e:
        idx = getattr(agent, "index", None)
        if idx is not None:
            idx.close()
        run.finish("failed", str(e))
        store.close()
        raise
    return finish_run(store, run, agent, state, runs_dir)


def target_node(runs_dir: Path = Path(".runs")) -> FunctionNode:
    """`adk web`'s root (web/fullscan): the message names the target — a directory or https://github.com/<owner>/<repo>
    (cloned into .targets/) — the graph is prepared for it and run nested, then the run is closed like `scan full`
    (SARIF + summary). A message that names nothing scannable answers with an error and starts nothing."""
    async def fullscan(ctx, node_input) -> dict:
        s = Settings.from_env()  # once per message: the workspace root, the flags, the model
        text = "".join(p.text or "" for p in (ctx.user_content.parts or [])) if ctx.user_content else ""
        try:
            target = await asyncio.to_thread(resolve_target, text, Path(s.workspace_root))  # a clone may take a while: keep the loop free
        except (ValueError, subprocess.SubprocessError, OSError) as e:  # bad input, git timeout/failure, no git binary
            log.warning("fullscan: %s", e)
            return {"error": core.redact_secrets(str(e))}
        store, run, agent = await asyncio.to_thread(prepare, target, settings=s)  # index build + entry points: off the loop
        try:
            await ctx.run_node(agent, None, run_id=f"run-{run.id}")
        except Exception as e:  # noqa: BLE001 — the UI gets the reason as the answer, not a traceback; the run is marked failed
            idx = getattr(agent, "index", None)
            if idx is not None:
                idx.close()
            reason = why(e)  # ADK wraps the node's exception; keep the original message
            run.finish("failed", reason)
            store.close()
            log.warning("run %s failed: %s", run.id, reason)
            return {"error": core.redact_secrets(reason), "target": str(target), "run": run.id}  # a chat answer: redacted like a finding
        return {**finish_run(store, run, agent, ctx.state, runs_dir), "target": str(target)}
    return FunctionNode(func=fullscan, name=APP_NAME, rerun_on_resume=True)
