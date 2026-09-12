"""Test doubles shared by the suite (one place, per ADR-0005): an in-memory RunStore, fake ADK agents for
every node, a fake LSP client, and helpers to run a graph under the real ADK Runner."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, ClassVar

from google.adk.agents import BaseAgent
from google.adk.events import Event, EventActions
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from scanner import core
from scanner.app.pipeline_v2 import PipelineV2
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
    def save_anchors(self, xs): self._anchors = self._anchors + list(xs)
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

    def log_gate(self, anchor_id, reason): self.gate.append((anchor_id, reason))
    def add_note(self, text, ref=""): self._notes.append({"time": "t", "text": text, "ref": ref})
    def notes(self): return list(self._notes)
    def put_artifact(self, stage, obj): self._art[stage] = obj
    def artifact(self, stage): return self._art.get(stage)


def notes_of(run) -> list[tuple[str, str]]:
    """(text, ref) pairs of a run's notes — the shape most assertions want."""
    return [(n["text"], n["ref"]) for n in run.notes()]


def _text_event(name, ctx, text):
    return Event(author=name, invocation_id=ctx.invocation_id, branch=ctx.branch,
                 content=types.Content(role="model", parts=[types.Part(text=text)]))


class FakeVerifier(BaseAgent):
    """Confirms CWE-89, rejects the rest, proposes one duplicate and one ungrounded hypothesis."""
    instruction: str = ""
    store: object = None
    budget: bool = False
    global_flag: bool = False
    model_config: ClassVar[dict] = {"arbitrary_types_allowed": True}

    async def _run_async_impl(self, ctx):
        h = json.loads(self.instruction.split("(JSON):\n", 1)[1])
        if self.global_flag:
            yield Event(author=self.name, invocation_id=ctx.invocation_id, branch=ctx.branch,
                        actions=EventActions(state_delta={core.STATE_BUDGET_EXHAUSTED: True}))
            return
        if self.budget:  # this verifier's own model-call budget tripped before any report_finding
            yield Event(author=self.name, invocation_id=ctx.invocation_id, branch=ctx.branch,
                        actions=EventActions(state_delta={f"{core.STATE_BUDGET_EXHAUSTED}:{ctx.branch}": True}))
            return
        status = core.CONFIRMED if h["cwe"] == "CWE-89" else core.REJECTED
        self.store.report(Finding(anchor_id=h["anchor_id"], hypothesis_id=h["id"], cwe=h["cwe"], file="main.go",
                                  title="t", status=status, evidence=["db.Query(x)"]))
        new = [{"kind": "sink", "cwe": "CWE-89", "claim": "dup of a_1", "anchor_id": "a_1"},
               {"kind": "sink", "claim": "ungrounded", "symbol": "nope"}]
        yield _text_event(self.name, ctx, json.dumps({"hypothesis_id": h["id"], "verdict": "confirmed",
                                                      "notes": "n", "new_hypotheses": new}))


class FakeCritic(BaseAgent):
    instruction: str = ""
    store: object = None
    model_config: ClassVar[dict] = {"arbitrary_types_allowed": True}

    async def _run_async_impl(self, ctx):
        f = json.loads(self.instruction.split("(JSON):\n", 1)[1])["finding"]
        assert f["status"] == core.CONFIRMED
        self.store.set_status(f["id"], core.UNCERTAIN, ["critic: parameterized after all"])
        yield _text_event(self.name, ctx, json.dumps({"finding_id": f["id"], "disproved": True}))


class FakeStage(BaseAgent):
    """Architect / DomainModeler / ThreatModeler stand-in: echoes a canned JSON, records the payload it received."""
    instruction: str = ""
    reply: dict | None = None
    store: object = None
    model_config: ClassVar[dict] = {"arbitrary_types_allowed": True}

    async def _run_async_impl(self, ctx):
        self.store.add_note("seen:" + self.instruction.split("(JSON):\n", 1)[1], self.name)  # clone-safe record
        yield _text_event(self.name, ctx, json.dumps(self.reply))


class Node(PipelineV2):
    """Runs one node in isolation: `body(self, ctx)` is an async generator over that node's method."""

    body: Any = None

    async def _run_async_impl(self, ctx):
        async for ev in self.body(self, ctx):
            yield ev


def _scan(run, **kw):
    return PipelineV2(
        verifier=kw.pop("verifier", FakeVerifier(name="verify", store=run)), store=run, target="/t",
        has_anchor=lambda i: run.anchor(i) is not None, has_symbol=lambda s: False, entry_points_fn=list, **kw,
    )


def _run(agent):
    """Run an agent under the real ADK Runner with an in-memory session; return the final session state."""
    async def go():
        svc = InMemorySessionService()
        r = Runner(app_name="t", agent=agent, session_service=svc)
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
