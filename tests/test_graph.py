"""PipelineV2 with fake (non-LLM) stage/verifier/critic agents and an in-memory Run."""

import asyncio
import json
from typing import ClassVar

import pytest
from google.adk.agents import BaseAgent
from google.adk.events import Event, EventActions
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from scanner import core
from scanner.app.graph import dossier_from_store, parse_json
from scanner.app.pipeline_v2 import PipelineV2
from scanner.core import Anchor, Candidate, Finding, Hypothesis

A1 = Anchor(id="a_1", tool="gosec", rule_id="G201", cwe="CWE-89", severity="high", file="main.go", line=22)
A2 = Anchor(id="a_2", tool="gosec", rule_id="G204", cwe="CWE-78", severity="high", file="main.go", line=30)


class FakeRun:
    def __init__(self):
        self.hyps, self.doss, self._findings, self.gate, self._notes = {}, {}, [], [], []
        self._anchors, self._art = [A1, A2], {}

    def add_note(self, text, ref=""): self._notes.append((text, ref))
    def notes(self): return self._notes

    def anchors(self): return list(self._anchors)
    def save_anchors(self, xs): self._anchors = self._anchors + list(xs)
    def put_artifact(self, stage, obj): self._art[stage] = obj
    def artifact(self, stage): return self._art.get(stage)
    def anchor(self, id): return next((a for a in self.anchors() if a.id == id), None)
    def put_hypotheses(self, r, hs): self.hyps[r] = hs
    def set_status(self, fid, status, evidence, note=""):
        for i, f in enumerate(self._findings):
            if f.id == fid:
                self._findings[i] = f.model_copy(update={"status": status, "evidence": [*f.evidence, *evidence]})
                return self._findings[i]
    def put_dossiers(self, r, ds): self.doss[r] = ds
    def findings(self): return list(self._findings)

    def report(self, f):
        f.id = f"f_{len(self._findings) + 1}"
        self._findings.append(f)
        return f


def _text_event(name, ctx, text):
    return Event(author=name, invocation_id=ctx.invocation_id, branch=ctx.branch,
                 content=types.Content(role="model", parts=[types.Part(text=text)]))




class FakeVerifier(BaseAgent):
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
    """Architect or ThreatModeler stand-in: echoes a canned JSON, records the payload it received."""
    instruction: str = ""
    reply: dict | None = None
    store: object = None
    model_config: ClassVar[dict] = {"arbitrary_types_allowed": True}

    async def _run_async_impl(self, ctx):
        self.store.add_note("seen:" + self.instruction.split("(JSON):\n", 1)[1], self.name)  # clone-safe record
        yield _text_event(self.name, ctx, json.dumps(self.reply))


def _scan(run, **kw):
    return PipelineV2(
        verifier=kw.pop("verifier", FakeVerifier(name="verify", store=run)), store=run, target="/t",
        has_anchor=lambda i: run.anchor(i) is not None, has_symbol=lambda s: False, entry_points_fn=list, **kw,
    )


def _run(agent):
    async def go():
        svc = InMemorySessionService()
        r = Runner(app_name="t", agent=agent, session_service=svc)
        await svc.create_session(app_name="t", user_id="u", session_id="s")
        async for _ in r.run_async(user_id="u", session_id="s",
                                   new_message=types.Content(role="user", parts=[types.Part(text="go")])):
            pass
        return dict((await svc.get_session(app_name="t", user_id="u", session_id="s")).state)
    return asyncio.run(go())


def test_round_limit_stops_with_queue_left():
    run = FakeRun()
    state = _run(_scan(run, max_rounds=1, max_hyps=1))
    assert [h.id for h in run.hyps[0]] == ["h0-1"] and 1 not in run.hyps
    assert state[core.STATE_STOP_REASON] == "round limit"


def test_verify_failure_round0_raises_later_finishes():
    class Boom(FakeVerifier):
        async def _run_async_impl(self, ctx):
            raise RuntimeError("boom")
            yield

    with pytest.raises(RuntimeError):
        _run(_scan(FakeRun(), verifier=Boom(name="verify")))


def test_verifier_budget_marks_dossier_but_run_goes_on():
    run = FakeRun()
    state = _run(_scan(run, verifier=FakeVerifier(name="verify", store=run, budget=True)))
    assert [d.error for d in run.doss[0]] == ["budget", "budget"]
    assert state[core.STATE_STOP_REASON] == "" and core.STATE_BUDGET_EXHAUSTED not in state  # queue drained normally


def test_global_budget_flag_finishes_run():
    """A stop_run budget (global flag) finishes the run, even at round 0."""
    from google.adk.models.llm_request import LlmRequest

    from scanner.app.callbacks import BUDGET_LAST_CALL, budget_callback

    class Ctx:
        branch = "b"
        state: ClassVar[dict] = {}

    cb, req = budget_callback(2, stop_run=True), LlmRequest()
    assert cb(Ctx, req) is None and not req.contents
    assert cb(Ctx, req) is None and req.contents[-1].parts[0].text == BUDGET_LAST_CALL and req.config.tools is None
    assert cb(Ctx, req) is not None and Ctx.state[core.STATE_BUDGET_EXHAUSTED] is True and Ctx.state["budget_exhausted:b"] is True
    run = FakeRun()
    state = _run(_scan(run, verifier=FakeVerifier(name="verify", store=run, budget=True, global_flag=True)))
    assert state[core.STATE_STOP_REASON] == "budget" and 1 not in run.hyps


def test_critic_downgrades_confirmed():
    run = FakeRun()
    state = _run(_scan(run, critic=FakeCritic(name="critic", store=run)))
    assert state[core.STATE_STOP_REASON] == ""
    assert {f.id: f.status for f in run.findings()} == {"f_1": core.UNCERTAIN, "f_2": core.REJECTED}
    assert run.doss[0][0].verdict == core.CONFIRMED  # dossier keeps the Verifier's verdict; the store has the Critic's


def test_v2_queue_drains_without_lead():
    run = FakeRun()
    agent = PipelineV2(verifier=FakeVerifier(name="verify", store=run), store=run, target="/t",
                       has_anchor=lambda i: run.anchor(i) is not None, has_symbol=lambda s: False, max_parallel=1)
    state = _run(agent)
    assert [h.id for h in run.hyps[0]] == ["h0-1", "h0-2"]  # both anchors, severity order
    assert {d.hypothesis_id: d.verdict for d in run.doss[0]} == {"h0-1": core.CONFIRMED, "h0-2": core.REJECTED}
    # new_hypotheses: the a_1 duplicate is done, the ungrounded one is gated out → queue empty after round 1
    assert 1 in run.hyps and run.hyps[1] == [] and 1 not in run.doss
    assert state[core.STATE_STOP_REASON] == "" and state[core.STATE_ROUND] == 2
    assert any("ungrounded" in t for t, _ in run.notes())


def test_v2_stages_mint_anchor_for_grounded_threat():
    run = FakeRun()
    arch = FakeStage(name="architect", store=run, reply={"entities": [{"name": "orders", "grounding_symbol": "getOrder"}], "vuln_classes": [{"cwe": "CWE-639"}]})
    tm = FakeStage(name="threat_modeler", store=run, reply={"intent": "production", "notes": ["no symbol: skipped"], "threats": [
        {"cwe": "CWE-639", "claim": "getOrder returns any user's order", "symbol": "getOrder", "priority": 80},
        {"cwe": "CWE-79", "claim": "ghost", "symbol": "nowhere", "priority": 30}]})
    agent = PipelineV2(architect=arch, threat_modeler=tm, verifier=FakeVerifier(name="verify", store=run), store=run, target="/t",
                       has_anchor=lambda i: run.anchor(i) is not None, has_symbol=lambda s: s == "listOrders",
                       locate=lambda s: ("orders.go", 31) if s == "getOrder" else None,
                       entry_points_fn=lambda: [Candidate(kind="entry", symbol="listOrders", file="list.go", line=10)], max_parallel=1)
    state = _run(agent)
    # plan-stage coverage: the entry point no threat/anchor examines becomes a low-priority baseline hypothesis
    baseline = [h for h in run.hyps[0] if h.kind == "entry"]
    assert len(baseline) == 1 and baseline[0].symbol == "listOrders"
    seen = {ref: json.loads(t[5:]) for t, ref in run.notes() if t.startswith("seen:")}
    assert seen["architecture_model"]["anchors"][0]["id"] == "a_1" and seen["threat_model"]["architecture_model"]["entities"][0]["name"] == "orders"
    assert run.artifact("architecture_model")["vuln_classes"] == [{"cwe": "CWE-639"}] and run.artifact("threat_model")["intent"] == "production"
    minted = [a for a in run.anchors() if a.tool == "threatmodel"]
    assert len(minted) == 1 and (minted[0].file, minted[0].line, minted[0].cwe) == ("orders.go", 31, "CWE-639")
    ids = {h.anchor_id: h for h in run.hyps[0] if h.anchor_id}
    assert set(ids) == {"a_1", "a_2", minted[0].id} and ids[minted[0].id].consult == "domain"  # ghost threat gated out
    assert ids[minted[0].id].id == "h0-1"  # priority 80 beats the anchors (60)
    assert any("ungrounded" in t for t, _ in run.notes()) and state[core.STATE_STOP_REASON] == ""


def test_helpers():
    assert parse_json("junk {\"a\": {\"b\": 1}} tail") == {"a": {"b": 1}}
    assert parse_json("nope") is None
    h = Hypothesis(id="h0-1", anchor_id="a_1")
    fs = [Finding(id="f1", anchor_id="a_1", status=core.REJECTED), Finding(id="f2", anchor_id="a_1", hypothesis_id="h0-1", status=core.CONFIRMED),
          Finding(id="f3", anchor_id="a_1", hypothesis_id="other", status=core.CONFIRMED)]
    assert dossier_from_store(fs, h).finding_id == "f2"
    assert dossier_from_store([], h).verdict == core.UNCERTAIN


def test_verify_payload_carries_skill_lists():
    """Investigators get the WSTG/class/analysis skill list; critics get the control skill first."""
    from scanner.adapter.skills import skills_for
    inv = skills_for("CWE-89", "sink")
    crit = skills_for("CWE-89", "", "critique")
    assert inv and inv[0].startswith("wstg-") and crit and crit[0].startswith("control-")
