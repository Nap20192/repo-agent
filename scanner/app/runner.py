"""Runner: env/model, wiring of the graph for one run (`build_agent`), the pre-pass (`prepare`) and the
ADK run in a persistent session (`scan_full`). The CLI (scanner/main.py) and `adk web` (web/) both use this."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import time
from pathlib import Path

from google.adk.agents import LlmAgent
from google.adk.apps import App
from google.adk.errors._stale_session_error import StaleSessionError
from google.adk.runners import Runner
from google.adk.sessions.sqlite_session_service import SqliteSessionService
from google.genai import types

from scanner import core
from scanner.adapter import entrypoints, fs, static
from scanner.adapter import recon as recon_adapter
from scanner.adapter.index import build_index
from scanner.adapter.knowledge import KnowledgeConfig
from scanner.adapter.store import Store
from scanner.adapter.tools import (
    architect_tools,
    confirm_tools,
    critic_tools,
    review_tools,
    subset,
    triage_tools,
    verifier_tools,
    viability_tools,
)
from scanner.app.agents import (
    new_architect,
    new_confirm,
    new_critic,
    new_review,
    new_threat_modeler,
    new_triage,
    new_triage_batch,
    new_verifier,
    new_viability,
)
from scanner.app.domain import new_domain_modeler
from scanner.app.knowledge_agent import make_consult_knowledge, new_knowledge_agent
from scanner.app.observe import compaction_config, setup_tracing
from scanner.app.pipeline import build_workflow
from scanner.app.settings import Settings, apply_dotenv
from scanner.app.specialists import REGISTRY, architect_overlay, route_name
from scanner.app.specialists import build as build_specialists
from scanner.core import Candidate
from scanner.core.ports import Index

log = logging.getLogger("scanner.runner")

APP_NAME = "fullscan"  # = the agent folder under web/, so CLI sessions show in the same app of the ADK UI
SESSION_USER = "user"  # the ADK dev UI lists this user's sessions

# Agents `wiring` does not build (the graph uses their batch / viability siblings): `standalone` builds them itself.
EXTRA_AGENTS = ("triage", "critic", "knowledge")
# Every LlmAgent of the project by its `.name`: one `adk create` app each under web/ (card 46).
ROSTER = ("architect", "domain_modeler", "threat_modeler", "triage_batch", "verify", "review", "viability", "confirm",
          *EXTRA_AGENTS, *(spec.name for spec in REGISTRY))


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
    app = App(name=APP_NAME, root_agent=agent, events_compaction_config=compaction_config(model_from_env(s), s))
    runner = Runner(app=app, session_service=svc)
    await svc.create_session(app_name=APP_NAME, user_id=SESSION_USER, session_id=sid)
    log.info("session %s (user %s): adk web → /dev-ui/?app=%s", sid, SESSION_USER, APP_NAME)
    msg = types.Content(role="user", parts=[types.Part(text=f"scan target: {target}")])
    async for _ in runner.run_async(user_id=SESSION_USER, session_id=sid, new_message=msg):
        pass
    s = await svc.get_session(app_name=APP_NAME, user_id=SESSION_USER, session_id=sid)
    return dict(s.state) if s else {}


def wiring(run, target: Path, entries: list[Candidate], model, index: Index | None = None,
           settings: Settings | None = None, deps: bool = False) -> dict:
    """Everything the graph needs for one run, by keyword: agents (Architect → DomainModeler → ThreatModeler,
    Investigator + specialists, Critic), the store, the index-backed callables and the budgets."""
    s = settings or Settings.from_env()
    index = index or build_index(target, max_files=s.index_max_files, max_bytes=s.index_max_bytes)  # LSP per language, grep fallback
    has_symbol = index.has_symbol
    langs = fs.detect_langs(target)
    specialists = build_specialists(  # the Knowledge consultant is injected at construction (one AgentTool per user)
        model, run, target, index, knowledge_factory=lambda: make_consult_knowledge(model, s.knowledge_max_calls),
    ) if s.specialists else {}
    return {
        "index": index,
        "scan_fn": lambda: static.scan(target, skip_deps=not deps and s.skip_deps, knowledge_cfg=run.knowledge),
        "architect": new_architect(model, architect_tools(run, target, index=index), s.architect_max_calls,
                                overlay=architect_overlay(langs)) if s.threat_model else None,
        "domain_modeler": new_domain_modeler(model, architect_tools(run, target, index=index), s.domain_modeler_max_calls)
        if s.threat_model and s.domain_model else None,
        "threat_modeler": new_threat_modeler(model, subset(architect_tools(run, target, index=index), {"consult_owasp", "read_file", "grep"}),
                                             s.threat_modeler_max_calls) if s.threat_model else None,
        "specialists": specialists,
        "router": route_name,
        "verifier": new_verifier(model, verifier_tools(run, target, index=index), s.verifier_max_calls),
        # the verdict ladder (Shannon review → critic → confirm); CRITIC=0 turns all three off, the nodes stay
        "review": new_review(model, review_tools(run, target, index=index), s.review_max_calls) if s.critic else None,
        "critic": new_viability(model, viability_tools(run, target, index=index), s.viability_max_calls) if s.critic else None,
        "confirm": new_confirm(model, confirm_tools(run, target, index=index), s.confirm_max_calls) if s.critic else None,
        "triage": new_triage_batch(model, triage_tools(run, target, index=index), s.triage_max_calls) if s.triage else None,
        "recon_fn": (lambda: recon_adapter.recon(target, entries, langs, index)) if s.recon else None,
        "knowledge_cfg": getattr(run, "knowledge", None),
        "triage_batch": s.triage_batch,
        "triage_parallel": s.triage_parallel,
        "store": run,
        "target": str(target),
        "has_anchor": lambda i: run.anchor(i) is not None,
        "has_symbol": has_symbol,
        "locate": index.find_symbol,
        "entry_points_fn": lambda: entries,
        "source_files_fn": lambda: fs.source_files(target),  # planner: file baselines for what nobody reads
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
    s = dataclasses.replace(settings or Settings.from_env(), specialists=True, threat_model=True, domain_model=True,
                            critic=True, triage=True)
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
        w = wiring(run, target, entrypoints.entry_points(target), model, index, s)
        res = w["scan_fn"]()  # the graph's `scan` node, once: anchors are what the investigators and gates work on
        run.save_anchors(res.anchors)
        run.put_artifact("scan", {"anchors": len(res.anchors), "ran": res.ran, "failed": res.failed})
        agents = {a.name: a for a in w.values() if isinstance(a, LlmAgent)} | dict(w["specialists"])
        agents["triage"] = new_triage(model, triage_tools(run, target, index=index), s.triage_max_calls)
        agents["critic"] = new_critic(model, critic_tools(run, target, index=index), s.critic_max_calls)
        agents["knowledge"] = new_knowledge_agent(model, s.knowledge_max_calls)
    except Exception as e:
        run.finish("failed", str(e))
        store.close()
        raise
    return store, run, agents


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
