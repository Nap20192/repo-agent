"""Test doubles shared by the suite (one place, per ADR-0005): an in-memory RunStore, node-shaped doubles for
every stage, a fake LSP client, and helpers to run the Workflow under the real ADK Runner."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from google.adk.agents import BaseAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from scanner import core
from scanner.core import Anchor, Finding

A1 = Anchor(id="a_1", tool="gosec", rule_id="G201", cwe="CWE-89", severity="high", file="main.go", line=22)
A2 = Anchor(id="a_2", tool="gosec", rule_id="G204", cwe="CWE-78", severity="high", file="main.go", line=30)
SQL = Anchor(id="a_sql", tool="gosec", rule_id="G202", cwe="CWE-89", severity="high", file="main.go", line=3)
IDOR = Anchor(id="a_idor", tool="semgrep", rule_id="idor", cwe="CWE-639", severity="medium", file="main.go", line=5)


class FakeRun:
    """In-memory RunStore. `dedup=True` mirrors Store.report (same anchor → the existing finding)."""

    def __init__(self, anchors: list[Anchor] | None = None, dedup: bool = False):
        self._anchors = list(anchors) if anchors is not None else [A1, A2]
        self.dedup = dedup
        self.hyps: dict[int, list] = {}
        self.doss: dict[int, list] = {}
        self._findings: list[Finding] = []
        self.gate: list[tuple[str, str]] = []
        self._notes: list[dict] = []
        self._art: dict[str, dict] = {}

    def anchors(self): return list(self._anchors)
    def anchor(self, anchor_id): return next((a for a in self._anchors if a.id == anchor_id), None)
    def save_anchors(self, xs):  # INSERT OR REPLACE by id, like Store.Run
        by_id = {a.id: a for a in self._anchors}
        by_id.update({a.id: a for a in xs})
        self._anchors = list(by_id.values())
    def put_hypotheses(self, rnd, hs): self.hyps[rnd] = hs
    def put_dossiers(self, rnd, ds): self.doss[rnd] = ds
    def findings(self): return list(self._findings)

    def report(self, f):
        if self.dedup:
            for old in self._findings:
                if old.anchor_id == f.anchor_id:
                    return old
        f = f.model_copy(update={"id": f"f_{len(self._findings) + 1}"})
        self._findings.append(f)
        return f

    def set_status(self, fid, status, evidence, note=""):
        for i, f in enumerate(self._findings):
            if f.id == fid:
                self._findings[i] = f.model_copy(update={"status": status, "evidence": [*f.evidence, *evidence]})
                return self._findings[i]
        return None

    ANNOTATIONS = ("review", "viability", "repro_status", "calibration")

    def annotate(self, fid, **fields):  # mirrors Store.Run.annotate (card 45)
        if set(fields) - set(self.ANNOTATIONS):
            raise ValueError("not annotations")
        for i, f in enumerate(self._findings):
            if f.id == fid:
                merged = {k: ({**getattr(f, k), **v} if isinstance(v, dict) else v) for k, v in fields.items()}
                self._findings[i] = f.model_copy(update=merged)
                return self._findings[i]
        return None

    def log_gate(self, anchor_id, reason): self.gate.append((anchor_id, reason))
    def add_note(self, text, ref=""): self._notes.append({"time": "t", "text": text, "ref": ref})
    def notes(self): return list(self._notes)
    def put_artifact(self, stage, obj): self._art[stage] = obj
    def artifact(self, stage): return self._art.get(stage)


def notes_of(run) -> list[tuple[str, str]]:
    """(text, ref) pairs of a run's notes — the shape most assertions want."""
    return [(n["text"], n["ref"]) for n in run.notes()]


def _run(agent):
    """Run a Workflow (or any node / agent) under the real ADK Runner with an in-memory session; return the final
    session state."""
    async def go():
        svc = InMemorySessionService()
        r = Runner(app_name="t", session_service=svc, **({"agent": agent} if isinstance(agent, BaseAgent) else {"node": agent}))
        await svc.create_session(app_name="t", user_id="u", session_id="s")
        async for _ in r.run_async(user_id="u", session_id="s",
                                   new_message=types.Content(role="user", parts=[types.Part(text="go")])):
            pass
        return dict((await svc.get_session(app_name="t", user_id="u", session_id="s")).state)
    return asyncio.run(go())


# --- LSP ------------------------------------------------------------------------------------------------
GO_SRC = """package main

type Server struct{}

func (s *Server) login() {
	x := 1
}

func pingHandler() {
	s := &Server{}
	s.login()
}
"""


def _sym(name, kind, line, end, sel_char=5, children=()):
    return {"name": name, "kind": kind, "range": {"start": {"line": line, "character": 0}, "end": {"line": end, "character": 1}},
            "selectionRange": {"start": {"line": line, "character": sel_char}, "end": {"line": line, "character": sel_char + len(name)}},
            "children": list(children)}


class FakeClient:
    """Answers documentSymbol/references from canned data; records calls."""

    def __init__(self, cmd, root, lang_id, timeout=30):
        self.root, self.calls = Path(root), []

    def start(self): self.calls.append("start")
    def initialize(self): self.calls.append("initialize"); return {}
    def did_open(self, path): self.calls.append(("open", Path(path).name))
    def close(self): self.calls.append("close")

    def document_symbols(self, path):
        if Path(path).name != "main.go":
            return []
        return [_sym("Server", 23, 2, 2), _sym("(*Server).login", 6, 4, 6, sel_char=17), _sym("pingHandler", 12, 8, 11)]

    def definition(self, path, line0, char0): return []

    def references(self, path, line0, char0, include_declaration=False):
        if line0 == 4:  # login → called from pingHandler
            return [{"uri": (self.root / "main.go").as_uri(), "range": {"start": {"line": 10, "character": 3}, "end": {"line": 10, "character": 8}}}]
        return []


class BrokenClient(FakeClient):
    def initialize(self): raise RuntimeError("server exploded")


def _run_node(node, node_input=None) -> list:
    """Run one Workflow node under the real ADK Runner (card 43); returns the outputs of the node's events.
    With a `node_input` the node runs as a dynamic child of a driver node (the way the graph calls it):
    a root node only ever receives the user turn."""
    from google.adk.workflow import FunctionNode

    if node_input is not None:
        inner, payload = node, node_input

        async def driver(ctx, node_input):
            return await ctx.run_node(inner, payload, run_id="t")
        node = FunctionNode(func=driver, name="driver", rerun_on_resume=True)

    async def go():
        svc = InMemorySessionService()
        r = Runner(app_name="t", node=node, session_service=svc)
        await svc.create_session(app_name="t", user_id="u", session_id="s")
        outs = []
        msg = types.Content(role="user", parts=[types.Part(text="go")])
        async for ev in r.run_async(user_id="u", session_id="s", new_message=msg):
            if ev.output is not None:
                outs.append(ev.output)
        return outs
    return asyncio.run(go())


# --- node-shaped doubles for the Workflow (the payload arrives as node_input) ----

def fake_stage_node(store, name: str, reply):
    """Architect / DomainModeler / ThreatModeler stand-in: records the payload it received, returns a canned reply."""
    from google.adk.workflow import FunctionNode

    async def stage(ctx, node_input: dict):
        store.add_note("seen:" + json.dumps(node_input), name)
        return reply
    return FunctionNode(func=stage, name=name, rerun_on_resume=True)


def fake_verifier_node(store, name: str = "verify", budget: bool = False, global_flag: bool = False,
                       fail_prefix: str = ""):
    """Verifier double: confirms CWE-89, rejects the rest, proposes one duplicate and one ungrounded
    hypothesis; `fail_prefix` raises for hypothesis ids starting with it (e.g. "h1" = every round-1 item)."""
    from google.adk.workflow import FunctionNode

    async def verify(ctx, node_input: dict):
        h = node_input
        if fail_prefix and h["id"].startswith(fail_prefix):
            raise RuntimeError("boom")
        if global_flag:
            ctx.state[core.STATE_BUDGET_EXHAUSTED] = True
            return None
        if budget:
            ctx.state[f"{core.STATE_BUDGET_EXHAUSTED}:{name}"] = True
            return None
        status = core.CONFIRMED if h["cwe"] == "CWE-89" else core.REJECTED
        store.report(Finding(anchor_id=h["anchor_id"], hypothesis_id=h["id"], cwe=h["cwe"], file="main.go",
                             title="t", status=status, evidence=["db.Query(x)"]))
        new = [{"kind": "sink", "cwe": "CWE-89", "claim": "dup of a_1", "anchor_id": "a_1"},
               {"kind": "sink", "claim": "ungrounded", "symbol": "nope"}]
        return {"hypothesis_id": h["id"], "verdict": status, "notes": "n", "new_hypotheses": new}
    return FunctionNode(func=verify, name=name, rerun_on_resume=True)


def fake_critic_node(store, name: str = "critic", fail: bool = False):
    from google.adk.workflow import FunctionNode

    async def critic(ctx, node_input: dict):
        if fail:
            raise RuntimeError("boom")
        f = node_input["finding"]
        assert f["status"] == core.CONFIRMED
        store.add_note("critic:" + name)
        store.set_status(f["id"], core.UNCERTAIN, ["critic: parameterized after all"])
        return {"finding_id": f["id"], "disproved": True}
    return FunctionNode(func=critic, name=name, rerun_on_resume=True)


def _workflow(run, **kw):
    """The Workflow with the node doubles and a FakeRun."""
    from scanner.app.graph.workflow import build_workflow

    return build_workflow(
        store=run, target="/t", verifier=kw.pop("verifier", fake_verifier_node(run)),
        has_anchor=lambda i: run.anchor(i) is not None, has_symbol=kw.pop("has_symbol", lambda s: False),
        entry_points_fn=kw.pop("entry_points_fn", list), **kw,
    )


# --- card 45 doubles for the static Shannon graph (route maps, output_schema stages, parallel workers) ----------

def fake_route_node(name: str, route: str):
    """A route FunctionNode that always emits `route`, passing its input through as the output."""
    from google.adk.events import Event
    from google.adk.workflow import FunctionNode

    def pick(node_input):
        return Event(route=route, output=node_input)
    return FunctionNode(func=pick, name=name)


def fake_schema_stage_node(store, name: str, schema, payload):
    """An output_schema stage stand-in: validates `payload` against `schema` (raises at construction on a
    mismatch, like an LlmAgent's final output would fail validation), records what it received, returns the dict."""
    from google.adk.workflow import FunctionNode

    out = schema.model_validate(payload).model_dump()

    async def stage(ctx, node_input):
        store.add_note("seen:" + json.dumps(node_input, default=str), name)
        return out
    return FunctionNode(func=stage, name=name, rerun_on_resume=True)


def fake_parallel_node(name: str, fn, max_parallel_workers: int | None = None):
    """A @node(parallel_worker=True) over a pure per-item function: list in, list out in input order."""
    from google.adk.workflow import node

    async def one(ctx, node_input):
        return fn(node_input)
    return node(one, parallel_worker=True, max_parallel_workers=max_parallel_workers, rerun_on_resume=True, name=name)
