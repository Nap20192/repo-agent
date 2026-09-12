"""One focused test per PipelineV2 node, exercised in isolation through the node's own method."""

import json
from typing import ClassVar

import pytest
from google.adk.agents import BaseAgent

from scanner import core
from scanner.adapter.store import Store
from scanner.app.pipeline_v2 import PipelineV2
from scanner.core import Anchor, Candidate, Finding, Hypothesis, Threat, ThreatModel
from tests.fakes import (
    A1,
    A2,
    FakeCritic,
    FakeRun,
    FakeStage,
    FakeVerifier,
    Node,
    _run,
    _scan,
    _text_event,
    notes_of,
)


def _node(run, body, **kw):
    kw.setdefault("verifier", FakeVerifier(name="verify", store=run))
    return Node(body=body, store=run, target="/t", has_anchor=lambda i: run.anchor(i) is not None,
                has_symbol=lambda s: False, entry_points_fn=list, **kw)


class Boom(BaseAgent):
    instruction: str = ""
    model_config: ClassVar[dict] = {"arbitrary_types_allowed": True}

    async def _run_async_impl(self, ctx):
        raise RuntimeError("boom")
        yield


# --- 1. Architect stage -------------------------------------------------------

def test_architect_valid_json_is_stored():
    run, out = FakeRun(), {}
    arch = FakeStage(name="architect", store=run, reply={"entities": [{"name": "api"}]})

    async def body(self, ctx):
        async for ev in self._stage(ctx, arch, "architecture_model", {"k": 1}, out):
            yield ev

    _run(_node(run, body))
    assert out["architecture_model"] == {"entities": [{"name": "api"}]} == run.artifact("architecture_model")


def test_architect_invalid_json_is_noted_and_skipped():
    run, out = FakeRun(), {}
    arch = FakeStage(name="architect", store=run, reply=None)  # replies "null": not a JSON object

    async def body(self, ctx):
        async for ev in self._stage(ctx, arch, "architecture_model", {}, out):
            yield ev

    _run(_node(run, body))
    assert out["architecture_model"] is None and run.artifact("architecture_model") is None
    assert any(t == "stage architecture_model: no valid JSON" for t, _ in notes_of(run))


def test_architect_exception_is_noted_and_pipeline_continues():
    run, out = FakeRun(), {}

    async def body(self, ctx):
        async for ev in self._stage(ctx, Boom(name="architect"), "architecture_model", {}, out):
            yield ev

    _run(_node(run, body))
    assert out["architecture_model"] is None
    assert any(t.startswith("stage architecture_model failed: boom") for t, _ in notes_of(run))


def test_architect_resume_skips_agent_when_artifact_exists():
    run, out = FakeRun(), {}
    run.put_artifact("architecture_model", {"entities": [{"name": "cached"}]})
    arch = FakeStage(name="architect", store=run, reply={"entities": [{"name": "fresh"}]})

    async def body(self, ctx):
        async for ev in self._stage(ctx, arch, "architecture_model", {}, out):
            yield ev

    _run(_node(run, body))
    assert out["architecture_model"]["entities"][0]["name"] == "cached"
    assert not any(t.startswith("seen:") for t, _ in notes_of(run))  # the agent never ran


# --- 2. ThreatModeler ---------------------------------------------------------

def test_threat_modeler_appends_threats_and_normalises_intent():
    run, out = FakeRun(), []
    tm = FakeStage(name="threat_modeler", store=run, reply={"intent": "SAMPLE_OR_TEST_ONLY", "threats": [
        {"cwe": "CWE-639", "claim": "idor", "symbol": "getOrder", "priority": 70},
        {"cwe": "CWE-79", "claim": "no symbol", "priority": 30}]})

    async def body(self, ctx):
        async for ev in self._model_threats(ctx, run.anchors(), out):
            yield ev

    _run(_node(run, body, threat_modeler=tm))
    assert [t.symbol for t in out] == ["getOrder", ""]  # the symbol-less threat is kept here; the gate drops it later
    assert ThreatModel.model_validate(run.artifact("threat_model")).intent == "sample"


def test_threat_modeler_runs_on_empty_model_without_architect():
    run = FakeRun()
    tm = FakeStage(name="threat_modeler", store=run, reply={"intent": "production", "threats": []})

    async def body(self, ctx):
        async for ev in self._model_threats(ctx, run.anchors(), []):
            yield ev

    _run(_node(run, body, threat_modeler=tm))
    seen = next(json.loads(t[5:]) for t, _ in notes_of(run) if t.startswith("seen:"))
    assert seen["architecture_model"]["entities"] == [] and seen["architecture_model"]["vuln_classes"] == []


def test_threat_without_symbol_is_gated_not_investigated():
    run = FakeRun()
    tm = FakeStage(name="threat_modeler", store=run, reply={"intent": "production", "threats": [
        {"cwe": "CWE-79", "claim": "ghost", "symbol": "", "priority": 90}]})
    _run(_scan(run, threat_modeler=tm, max_parallel=1))
    assert all(h.anchor_id in {"a_1", "a_2"} for h in run.hyps[0])
    assert any("ungrounded" in t for t, _ in notes_of(run))


# --- 3. Reconciler inside the pipeline --------------------------------------------

def test_queue_orders_threats_anchors_and_coverage_by_priority():
    run = FakeRun()
    threat = Threat(cwe="CWE-639", claim="idor", symbol="getOrder", priority=90)
    agent = PipelineV2(verifier=FakeVerifier(name="verify", store=run), store=run, target="/t",
                       has_anchor=lambda i: run.anchor(i) is not None, has_symbol=lambda s: s == "listOrders",
                       threats=[threat], locate=lambda s: ("orders.go", 5) if s == "getOrder" else None,
                       entry_points_fn=lambda: [Candidate(kind="entry", symbol="listOrders", file="list.go", line=3)],
                       max_parallel=1)
    _run(agent)
    kinds = [(h.kind, h.priority) for h in run.hyps[0]]
    assert kinds == [("authz", 90), ("sink", 60), ("sink", 60), ("entry", 10)]


def test_done_blocks_requeue_of_duplicate_new_hypotheses():
    run = FakeRun()
    state = _run(_scan(run, max_parallel=1))  # FakeVerifier proposes "dup of a_1" every time
    assert [h.anchor_id for h in run.hyps[0]] == ["a_1", "a_2"] and run.hyps[1] == []
    assert state[core.STATE_ROUND] == 2


def test_max_hyps_batches_queue_across_rounds():
    run = FakeRun()
    state = _run(_scan(run, max_hyps=1, max_rounds=5, max_parallel=1))
    assert [[h.anchor_id for h in run.hyps[r]] for r in (0, 1)] == [["a_1"], ["a_2"]]
    assert state[core.STATE_STOP_REASON] == ""  # queue drained, not the round limit


# --- 4. Investigator fan-out (_verify) --------------------------------------------

def _hyps():
    return [Hypothesis(id=f"h0-{i}", kind="sink", cwe=c, claim="x", anchor_id=a)
            for i, (c, a) in enumerate([("CWE-89", "a_1"), ("CWE-78", "a_2"), ("CWE-78", "a_2")], 1)]


def test_verify_chunks_and_takes_verdicts_from_store():
    run, res = FakeRun(), {}

    async def body(self, ctx):
        async for ev in self._verify(ctx, 0, _hyps(), res):
            run.add_note("ev:" + (ev.branch or ""))
            yield ev

    _run(_node(run, body, max_parallel=2))
    branches = {t[3:] for t, _ in notes_of(run) if t.startswith("ev:")}
    assert {"verify_round_0_0.verify_r0_0", "verify_round_0_0.verify_r0_1", "verify_round_0_2.verify_r0_2"} <= branches  # chunks of ≤2
    assert [d.verdict for d in res["dossiers"]] == [core.CONFIRMED, core.REJECTED, core.REJECTED]
    assert res["failed"] == "" and res["budget"] is False and all(d.notes == "n" for d in res["dossiers"])


def test_verify_marks_invalid_json_budget_and_failure():
    class BadJson(FakeVerifier):
        async def _run_async_impl(self, ctx):
            yield _text_event(self.name, ctx, json.dumps({"verdict": 5, "new_hypotheses": "x"}))

    run, res = FakeRun(), {}

    async def body(self, ctx):
        async for ev in self._verify(ctx, 0, _hyps()[:1], res):
            yield ev

    _run(_node(run, body, verifier=BadJson(name="verify")))
    assert res["dossiers"][0].error.startswith("invalid Dossier JSON")

    run, res = FakeRun(), {}
    _run(_node(run, body, verifier=FakeVerifier(name="verify", store=run, budget=True)))
    assert res["dossiers"][0].error == "budget" and res["budget"] is False  # own budget: run goes on

    run, res = FakeRun(), {}
    _run(_node(run, body, verifier=Boom(name="verify")))
    assert "boom" in res["failed"] and res["dossiers"][0].error == res["failed"]


def test_verify_failure_after_round0_finishes_with_reason():
    class FailsLater(FakeVerifier):
        async def _run_async_impl(self, ctx):
            h = json.loads(self.instruction.split("(JSON):\n", 1)[1])
            if h["id"].startswith("h1"):
                raise RuntimeError("late boom")
            async for ev in FakeVerifier._run_async_impl(self, ctx):
                yield ev

    run = FakeRun()
    state = _run(_scan(run, verifier=FailsLater(name="verify", store=run), max_hyps=1, max_parallel=1))
    assert state[core.STATE_STOP_REASON].startswith("verify round 1 failed: ") and 1 in run.doss


# --- 5. Critic pass -------------------------------------------------------------

class CountingCritic(FakeCritic):
    async def _run_async_impl(self, ctx):
        self.store.add_note("critic:" + self.name)
        async for ev in FakeCritic._run_async_impl(self, ctx):
            yield ev


def _seed(run, statuses):
    for i, s in enumerate(statuses, 1):
        run.report(Finding(anchor_id="a_1", cwe="CWE-89", file="main.go", title=f"f{i}", status=s, evidence=["x"]))


def test_critic_only_visits_confirmed_and_chunks():
    run = FakeRun()
    _seed(run, [core.CONFIRMED, core.REJECTED, core.CONFIRMED, core.CONFIRMED])

    async def body(self, ctx):
        async for ev in self._critic_pass(ctx):
            run.add_note("ev:" + (ev.branch or ""))
            yield ev

    _run(_node(run, body, critic=CountingCritic(name="critic", store=run), max_parallel=2))
    visited = sorted(t[7:] for t, _ in notes_of(run) if t.startswith("critic:"))
    assert visited == ["critic_0", "critic_1", "critic_2"]  # 3 confirmed, the rejected one skipped
    assert {t[3:] for t, _ in notes_of(run) if t.startswith("ev:")} >= {"critic_0.critic_0", "critic_0.critic_1", "critic_2.critic_2"}
    assert [f.status for f in run.findings()] == [core.UNCERTAIN, core.REJECTED, core.UNCERTAIN, core.UNCERTAIN]


def test_critic_chunk_failure_keeps_finding_confirmed():
    run = FakeRun()
    _seed(run, [core.CONFIRMED])

    async def body(self, ctx):
        async for ev in self._critic_pass(ctx):
            yield ev

    _run(_node(run, body, critic=Boom(name="critic")))
    assert run.findings()[0].status == core.CONFIRMED
    assert any(t.startswith("critic chunk 0 failed: boom") for t, _ in notes_of(run))


# --- 6. Reporter / store --------------------------------------------------------

def test_reporter_summary_and_sarif(tmp_path):
    store = Store(str(tmp_path / "s.db"))
    run = store.start_run("/t")
    run.save_anchors([A1, A2])
    run.put_artifact("threat_model", {"intent": "sample", "threats": []})
    run.report(Finding(anchor_id="a_1", cwe="CWE-89", file="main.go", line=22, title="sqli", status=core.CONFIRMED, evidence=["q"]))
    run.report(Finding(anchor_id="a_2", cwe="CWE-78", file="main.go", line=30, title="cmd", status=core.REJECTED))
    summary = json.loads(run.write_summary(tmp_path).read_text())
    assert summary["intent"] == "sample" and summary["confirmed"] == 1 and summary["rejected"] == 1
    assert all("score" in f["calibration"] for f in summary["findings"])
    sarif = json.loads(run.write_report(tmp_path).read_text())
    results = sarif["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == ["CWE-89"] and "score" in results[0]["properties"]["calibration"]
    run.set_status("f_1", core.UNCERTAIN, ["critic: safe"])  # disprove → reflected in the summary
    assert json.loads(run.write_summary(tmp_path).read_text())["uncertain"] == 1
    store.close()


# --- 7. State events -------------------------------------------------------------

@pytest.mark.parametrize("kw, stop", [({}, ""), ({"max_rounds": 1}, "round limit")])
def test_state_round_queue_and_stop_reason(kw, stop):
    run = FakeRun()
    state = _run(_scan(run, max_hyps=1, max_parallel=1, **kw))
    assert state[core.STATE_ROUND] >= 1 and isinstance(state["queue"], int)
    assert state[core.STATE_STOP_REASON] == stop


def test_budget_exit_path_sets_stop_reason():
    run = FakeRun()
    state = _run(_scan(run, verifier=FakeVerifier(name="verify", store=run, budget=True, global_flag=True)))
    assert state[core.STATE_STOP_REASON] == "budget" and state[core.STATE_ROUND] == 1


def test_anchor_fixture_sanity():
    assert isinstance(A1, Anchor) and A1.cwe == "CWE-89" and A2.cwe == "CWE-78"


# --- 8. Specialist routing (card 33) --------------------------------------------------

class Spy(FakeVerifier):
    """Specialist stand-in: the FakeVerifier verdict logic plus a note that it was chosen (clone-safe)."""

    async def _run_async_impl(self, ctx):
        payload = json.loads(self.instruction.split("(JSON):\n", 1)[1])
        self.store.add_note(f"spy:{self.name}:{payload.get('specialist')}:{'OVERLAY:go' in self.instruction}")
        async for ev in FakeVerifier._run_async_impl(self, ctx):
            yield ev


class SpyCritic(FakeCritic):
    async def _run_async_impl(self, ctx):
        self.store.add_note("spyc:" + self.name)
        async for ev in FakeCritic._run_async_impl(self, ctx):
            yield ev


def _router(item, lang, role):
    if role == "investigate":
        return ("taint", f"OVERLAY:{lang}") if getattr(item, "cwe", "") == "CWE-89" else ("", "")
    return "taint_critic", ""


def _routed_hyps():
    hs = _hyps()
    for h in hs:
        h.reads = ["main.go"]
    return hs


def test_verify_routes_cwe89_to_specialist_and_others_to_fallback():
    run, res = FakeRun(), {}

    async def body(self, ctx):
        async for ev in self._verify(ctx, 0, _routed_hyps(), res):
            yield ev

    _run(_node(run, body, specialists={"taint": Spy(name="taint", store=run)}, router=_router, max_parallel=1))
    assert [t for t, _ in notes_of(run) if t.startswith("spy:")] == ["spy:verify_r0_0:taint:True"]  # name kept, payload + overlay
    assert [d.verdict for d in res["dossiers"]] == [core.CONFIRMED, core.REJECTED, core.REJECTED]  # fallback verifier did the rest
    if "specialist" in core.Dossier.model_fields:
        assert [d.specialist for d in res["dossiers"]] == ["taint", "", ""]


def test_verify_retry_reuses_the_routed_specialist():
    class FlakySpy(Spy):
        async def _run_async_impl(self, ctx):
            first = not any(t == "flaky" for t, _ in notes_of(self.store))
            self.store.add_note("spyname:" + self.name)
            if first:
                self.store.add_note("flaky")
                yield _text_event(self.name, ctx, "prose, no braces")
                return
            assert "not valid JSON" in self.instruction and "OVERLAY:go" in self.instruction
            yield _text_event(self.name, ctx, json.dumps({"hypothesis_id": "h0-1", "verdict": "uncertain", "notes": "retried"}))

    run, res = FakeRun(), {}

    async def body(self, ctx):
        async for ev in self._verify(ctx, 0, _routed_hyps()[:1], res):
            yield ev

    _run(_node(run, body, specialists={"taint": FlakySpy(name="taint", store=run)}, router=_router))
    assert [t[8:] for t, _ in notes_of(run) if t.startswith("spyname:")] == ["verify_r0_0", "verify_r0_0_retry"]
    assert res["dossiers"][0].notes == "retried"


def test_critic_pass_routes_to_specialist_and_notes_it():
    run = FakeRun()
    _seed(run, [core.CONFIRMED])

    async def body(self, ctx):
        async for ev in self._critic_pass(ctx):
            yield ev

    _run(_node(run, body, critic=Boom(name="critic"), specialists={"taint_critic": SpyCritic(name="taint_critic", store=run)}, router=_router))
    assert [t for t, _ in notes_of(run) if t.startswith("spyc:")] == ["spyc:critic_0"]
    assert run.findings()[0].status == core.UNCERTAIN
    assert any(t == "critic:taint_critic reviewed f_1" for t, _ in notes_of(run))


def test_router_unknown_name_falls_back_and_no_router_is_unchanged():
    run, res = FakeRun(), {}

    async def body(self, ctx):
        async for ev in self._verify(ctx, 0, _routed_hyps(), res):
            yield ev

    _run(_node(run, body, specialists={}, router=lambda item, lang, role: ("nope", "x")))
    assert [d.verdict for d in res["dossiers"]] == [core.CONFIRMED, core.REJECTED, core.REJECTED]
    run, res = FakeRun(), {}
    _run(_node(run, body))
    assert [d.verdict for d in res["dossiers"]] == [core.CONFIRMED, core.REJECTED, core.REJECTED]


def test_new_architect_overlay_is_appended():
    from scanner.app.agents import new_architect
    a = new_architect("gemini-flash-lite-latest", [], 5, overlay="GO OVERLAY")
    assert a.instruction.endswith("GO OVERLAY")


# --- card 39: artifacts are grounded in code before they feed the queue --------------------------------

def test_pipeline_grounds_artifacts_before_reconcile():
    run = FakeRun()
    arch = FakeStage(name="architect", store=run, reply={"entities": [{"name": "X", "grounding_symbol": "nowhere"}],
                                                          "vuln_classes": [{"cwe": "CWE-89", "wstg_id": "WSTG-174"}]})
    dm = FakeStage(name="domain_modeler", store=run, reply={"entities": [], "roles": [], "gaps": [], "notes": [],
                                                              "rules": [{"id": "r1", "statement": "s", "entity": "Order", "symbol": "Server.login"}]})
    tm = FakeStage(name="threat_modeler", store=run, reply={"intent": "production", "notes": [], "threats": [
        {"cwe": "CWE-79", "claim": "ghost", "symbol": "nowhere", "priority": 90},
        {"cwe": "CWE-89", "claim": "real", "symbol": "searchHandler", "priority": 80, "wstg_id": "WSTG-999"}]})
    agent = PipelineV2(architect=arch, domain_modeler=dm, threat_modeler=tm, verifier=FakeVerifier(name="verify", store=run), store=run,
                       target="/t", has_anchor=lambda i: run.anchor(i) is not None, has_symbol=lambda s: s == "searchHandler",
                       locate=lambda s: ("main.go", 20) if s == "searchHandler" else None, entry_points_fn=list, max_parallel=1)
    state = _run(agent)
    assert run.artifact("architecture_model")["vuln_classes"][0]["wstg_id"] == "WSTG-INJT-05"
    assert run.artifact("architecture_model")["entities"] == []
    assert run.artifact("domain_map")["rules"] == [] and run.artifact("domain_map")["gaps"]
    assert [t["symbol"] for t in run.artifact("threat_model")["threats"]] == ["searchHandler"]
    claims = [h.claim for h in run.hyps[0]]
    assert "real" in claims and "ghost" not in claims  # the ungrounded threat never became a hypothesis
    assert state["grounding_dropped"] >= 3 and any("nowhere" in t for t, _ in notes_of(run))
