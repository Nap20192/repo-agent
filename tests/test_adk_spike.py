"""ADK 2.9 Workflow spike (card 45, docs/plans/shannon-graph.md §4 open questions), each answer pinned by a test
so wave 2 builds the static graph on verified semantics, not on the plan's assumptions."""

import asyncio

import pytest
from google.adk.agents import LlmAgent
from google.adk.apps import App, ResumabilityConfig
from google.adk.events import Event
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.workflow import DEFAULT_ROUTE, FunctionNode, JoinNode, RetryConfig, Workflow
from google.genai import types
from pydantic import BaseModel

from scanner.core import ThreatModel
from tests.fakes import fake_parallel_node, fake_route_node, fake_schema_stage_node


def _go(wf: Workflow, app_kw: dict | None = None, session: str = "s", svc=None, resume: bool = False) -> list:
    """Run `wf` as the root of an App; with `resume`, run it a second time as the SAME invocation (no new
    message) — that is what replay keys on (_replay_manager.py:289). Returns every node output in order."""
    svc = svc or InMemorySessionService()

    async def run():
        app = App(name="t", root_agent=wf, **(app_kw or {}))
        r = Runner(app=app, session_service=svc)
        if await svc.get_session(app_name="t", user_id="u", session_id=session) is None:
            await svc.create_session(app_name="t", user_id="u", session_id=session)
        outs, inv = [], None
        msg = types.Content(role="user", parts=[types.Part(text="go")])
        for attempt in range(2 if resume else 1):
            kw = {"new_message": msg} if attempt == 0 else {"invocation_id": inv}
            try:
                async for ev in r.run_async(user_id="u", session_id=session, **kw):
                    inv = inv or ev.invocation_id
                    if ev.output is not None:
                        outs.append(ev.output)
            except Exception as e:  # noqa: BLE001 — a failing run is part of what the spike measures
                outs.append(("error", type(e).__name__))
        return outs
    return asyncio.run(run())


def _fn(name: str, calls: list, ret=None):
    def f(node_input):
        calls.append(name)
        return {"from": name} if ret is None else ret
    return FunctionNode(func=f, name=name)


# 1. route maps -----------------------------------------------------------------------------------------------

def test_q1_route_map_runs_only_the_routed_branch():
    """Event(route=...) selects the edge; the other route target never runs (_graph.py:133-170, event.py:170-224)."""
    calls: list[str] = []
    r = fake_route_node("r", "empty")
    wf = Workflow(name="w", edges=[("START", r), (r, {"empty": _fn("x", calls), DEFAULT_ROUTE: _fn("y", calls)})])
    _go(wf)
    assert calls == ["x"]


# 2. a terminal reachable from several routes ------------------------------------------------------------------

def test_q2_plain_terminal_with_many_predecessors_fires_on_the_first_route_taken():
    """A plain FunctionNode is triggered per incoming edge that fires (_workflow.py:866-890): with mutually
    exclusive routes it runs exactly once. This is the shape for `export`."""
    calls: list[str] = []
    r1, r2 = fake_route_node("r1", "go"), fake_route_node("r2", "none")
    export, mid = _fn("export", calls), _fn("mid", calls)
    wf = Workflow(name="w", edges=[  # export has 3 incoming edges (r1:skip, r2:none, mid); exactly one fires
        ("START", r1), (r1, {"skip": export, DEFAULT_ROUTE: r2}), (r2, {"none": export, DEFAULT_ROUTE: mid}), (mid, export),
    ])
    _go(wf)
    assert calls == ["export"]


def test_q2_join_terminal_waits_for_every_predecessor_so_a_route_skip_never_reaches_it():
    """JoinNode requires ALL predecessors COMPLETED (_join_node.py:38, _workflow.py:831-861): a predecessor
    skipped by a route never completes, so the join never fires — a JoinNode cannot be the multi-route terminal."""
    r1 = fake_route_node("r1", "skip")
    mid = _fn("mid", [])
    export = JoinNode(name="export")
    wf = Workflow(name="w", edges=[("START", r1), (r1, {"skip": export, DEFAULT_ROUTE: mid}), (mid, export)])
    outs = _go(wf)
    assert not any(isinstance(o, dict) and "mid" in o for o in outs)  # mid skipped, join never produced a dict


# 3. JoinNode fan-in ---------------------------------------------------------------------------------------------

def test_q3_join_output_is_a_dict_keyed_by_predecessor_name():
    calls: list[str] = []
    a, b, c, j = _fn("a", calls), _fn("b", calls, {"B": 1}), _fn("c", calls, {"C": 2}), JoinNode(name="join")
    wf = Workflow(name="w", edges=[("START", a), (a, (b, c)), ((b, c), j)])
    outs = _go(wf)
    assert outs[-1] == {"b": {"B": 1}, "c": {"C": 2}}


# 4. output_schema together with tools ------------------------------------------------------------------------

def test_q4_llm_agent_accepts_output_schema_and_tools_together():
    """llm_agent.py:449-452: 'The ADK supports using output_schema and tools together' — tools during the
    thought loop, structure enforced on the final output."""
    def read_file(path: str) -> str:
        return ""
    agent = LlmAgent(name="a", model="gemini-flash-lite-latest", instruction="x", tools=[read_file],
                     output_schema=ThreatModel, output_key="threat_model", mode="single_turn")
    assert agent.output_schema is ThreatModel and agent.tools == [read_file]
    assert [t.name for t in asyncio.run(agent.canonical_tools())] == ["read_file"]


# 5. RetryConfig ----------------------------------------------------------------------------------------------

def test_q5_retry_config_reruns_a_failing_node_once_then_succeeds():
    """RetryConfig(max_attempts=2) = the original + one retry (utils/_retry_utils.py:34-40); the node is
    re-executed, the workflow continues with the successful output."""
    calls: list[str] = []

    def flaky(node_input):
        calls.append("flaky")
        if len(calls) == 1:
            raise RuntimeError("boom")
        return {"ok": True}
    n = FunctionNode(func=flaky, name="flaky", retry_config=RetryConfig(max_attempts=2, initial_delay=0, jitter=0))
    outs = _go(Workflow(name="w", edges=[("START", n)]))
    assert calls == ["flaky", "flaky"] and outs[-1] == {"ok": True}


def test_q5_a_node_failing_past_max_attempts_fails_the_workflow():
    """Exhausted retries propagate: no static-edge 'continue with None' exists — degradation stays inside
    dynamic nodes (try/except around ctx.run_node), as ADR-0007 already requires."""
    calls: list[str] = []

    def dead(node_input):
        calls.append("dead")
        raise RuntimeError("boom")
    n = FunctionNode(func=dead, name="dead", retry_config=RetryConfig(max_attempts=2, initial_delay=0, jitter=0))
    after = _fn("after", calls)
    outs = _go(Workflow(name="w", edges=[("START", n), (n, after)]))
    assert calls == ["dead", "dead"] and outs[-1][0] == "error"


# 6. parallel worker on a static edge ------------------------------------------------------------------------

def test_q6_parallel_worker_fans_out_a_list_input_on_a_static_edge_in_input_order():
    """A @node(parallel_worker=True) node receives the predecessor's list and returns one output per item in
    input order (_parallel_worker.py:95-135); Workflow.max_concurrency bounds *nodes*, max_parallel_workers
    bounds *items* — independent limits (_workflow.py:_at_concurrency_limit vs _parallel_worker.py:104)."""
    src = _fn("src", [], [3, 1, 2])
    worker = fake_parallel_node("double", lambda x: x * 2, max_parallel_workers=2)
    outs = _go(Workflow(name="w", max_concurrency=1, edges=[("START", src), (src, worker)]))
    assert outs[-1] == [6, 2, 4]


# 7. resumability ------------------------------------------------------------------------------------------------

def test_q7_resumable_app_replays_completed_nodes_and_reruns_the_failed_one():
    """ResumabilityConfig(is_resumable=True): a second run of the same session fast-forwards nodes whose
    `node@run_id` checkpoint is in the events (_workflow.py:600-650) and executes the one that failed."""
    calls: list[str] = []
    attempts = {"n": 0}

    def third(node_input):
        attempts["n"] += 1
        calls.append("third")
        if attempts["n"] == 1:
            raise RuntimeError("boom")
        return {"done": True}
    a, b = _fn("a", calls), _fn("b", calls)
    c = FunctionNode(func=third, name="c")
    wf = Workflow(name="w", edges=[("START", a), (a, b), (b, c)])
    svc = InMemorySessionService()
    outs = _go(wf, {"resumability_config": ResumabilityConfig(is_resumable=True)}, svc=svc, resume=True)
    assert outs[-1] == {"done": True}
    assert calls.count("a") == 1 and calls.count("b") == 1 and calls.count("third") == 2  # a, b replayed, c re-run


# doubles ----------------------------------------------------------------------------------------------------------

def test_fake_schema_stage_node_validates_against_the_given_model():
    class Out(BaseModel):
        n: int

    class Store:
        def __init__(self):
            self.notes: list = []

        def add_note(self, text, ref=""):
            self.notes.append((text, ref))
    calls: list[str] = []
    n = fake_schema_stage_node(Store(), "stage", Out, {"n": 1, "extra": "dropped"})
    outs = _go(Workflow(name="w", edges=[("START", n), (n, _fn("after", calls))]))
    assert outs[0] == {"n": 1} and calls == ["after"]
    with pytest.raises(Exception, match="validation error"):
        fake_schema_stage_node(Store(), "bad", Out, {"n": "x"})


def test_event_route_kwarg_lands_in_actions_route():
    assert Event(author="x", route="empty").actions.route == "empty"
