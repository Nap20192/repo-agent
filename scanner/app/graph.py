"""Shared graph machinery: JSON parsing, verdict-from-store, fan-out activations, the hypothesis gate,
a verify round and the Critic pass (`_Graph` base of PipelineV2)."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections.abc import AsyncGenerator, Callable

from google.adk.agents import BaseAgent, LlmAgent, ParallelAgent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.events import Event, EventActions
from google.genai import types
from pydantic import ConfigDict, Field

from scanner import core
from scanner.adapter import static
from scanner.adapter.skills import skill_for, skills_for
from scanner.core import Dossier, Finding, Hypothesis
from scanner.core.ports import Router, RunStore

log = logging.getLogger("scanner.graph")





_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)

def parse_json(text: str) -> dict | None:
    """Best-effort: strip fences, take first '{' … last '}'."""
    if not text:
        return None
    text = _FENCE.sub("", text.strip())
    i, j = text.find("{"), text.rfind("}")
    if i < 0 or j <= i:
        return None
    try:
        v = json.loads(text[i : j + 1])
    except json.JSONDecodeError:
        return None
    return v if isinstance(v, dict) else None

JSON_NUDGE = "Your previous reply was not valid JSON. Reply with the JSON object only."
STATE_JSON_RETRIES = "json_retries"


def activation(agent: BaseAgent, name: str, label: str, payload: dict, suffix: str = "") -> BaseAgent:
    """Fresh copy of `agent` for one run: payload goes into the instruction when the agent has one.
    `suffix` is an extra instruction line (e.g. the JSON nudge) placed before the payload."""
    if not isinstance(getattr(agent, "instruction", None), str):
        return agent.clone(update={"name": name})
    extra = f"\n\n{suffix}" if suffix else ""
    text = f"{agent.instruction}{extra}\n\n{label} (JSON):\n{json.dumps(payload, ensure_ascii=False)}"
    # LlmAgent: an InstructionProvider bypasses {state} templating, so JSON braces are safe.
    instr = (lambda _ctx: text) if isinstance(agent, LlmAgent) else text
    return agent.clone(update={"name": name, "instruction": instr})

async def with_deadline(agen: AsyncGenerator[Event, None], seconds: float) -> AsyncGenerator[Event, None]:
    """Re-yield `agen` but give up (asyncio.TimeoutError) once `seconds` have elapsed overall."""
    deadline = time.monotonic() + seconds
    try:
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError(f"stage exceeded {seconds:.0f}s")
            try:
                ev = await asyncio.wait_for(agen.__anext__(), left)
            except StopAsyncIteration:
                return
            yield ev
    finally:
        await agen.aclose()


def text_of(ev: Event) -> str:
    if not ev.content or not ev.content.parts or ev.get_function_calls():
        return ""
    return "".join(p.text or "" for p in ev.content.parts)

_RANK = {core.CONFIRMED: 2, core.REJECTED: 1}

def dossier_from_store(findings: list[Finding], h: Hypothesis) -> Dossier:
    """Verdict from facts: findings bound to the hypothesis (id, else anchor without foreign id)."""
    d = Dossier(hypothesis_id=h.id)
    best: Finding | None = None
    for f in findings:
        mine = (h.id and f.hypothesis_id == h.id) or (
            h.anchor_id and not f.hypothesis_id and f.anchor_id == h.anchor_id
        )
        if mine and (best is None or _RANK.get(f.status, 0) > _RANK.get(best.status, 0)):
            best = f
    if best:
        d.verdict, d.finding_id, d.evidence = best.status, best.id, list(best.evidence)
    return d

class Graph(BaseAgent):
    """Shared machinery of both graphs: fan-out activations, hypothesis gate, verify round, critic pass."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    verifier: BaseAgent
    critic: BaseAgent | None = None  # adversarial pass over confirmed findings
    # specialists by name + a pure router (item, lang, role) -> (name, instruction suffix); no router = one generic agent
    specialists: dict[str, BaseAgent] = Field(default_factory=dict)
    router: Router | None = None
    json_retry: bool = True  # one JSON-nudge retry when an activation ends without JSON
    store: RunStore
    target: str = ""
    has_anchor: Callable[[str], bool]
    has_symbol: Callable[[str], bool]
    max_rounds: int = 4
    max_hyps: int = 8
    max_parallel: int = 3

    def __init__(self, name: str, **kw):
        super().__init__(name=name, sub_agents=[], **kw)

    def _state_event(self, ctx: InvocationContext, delta: dict) -> Event:
        return Event(
            author=self.name, invocation_id=ctx.invocation_id, branch=ctx.branch,
            actions=EventActions(state_delta=delta),
        )

    async def _run_activations(
        self, ctx: InvocationContext, name: str, agents: list[BaseAgent], out: dict[str, str]
    ) -> AsyncGenerator[Event, None]:
        """Run `agents` in parallel on isolated sub-branches; final text per agent name → out."""
        # ParallelAgent stays by decision — see docs/adr/0001-parallel-fanout.md (Workflow cannot run inside a BaseAgent).
        par = ParallelAgent(name=name, sub_agents=agents)
        async for ev in par.run_async(ctx):
            if ev.author in {a.name for a in agents} and (t := _text_of(ev)):
                out[ev.author] = t
            yield ev

    async def _retry_json(
        self, ctx: InvocationContext, agent: BaseAgent, name: str, label: str, payload: dict, texts: dict[str, str],
        suffix: str = "",
    ) -> AsyncGenerator[Event, None]:
        """One more activation with the JSON nudge when `texts[name]` has no valid JSON; result lands in texts[name].
        Counted in session state `json_retries`; `json_retry=False` disables."""
        if not self.json_retry or parse_json(texts.get(name, "")) is not None:
            return
        retry = _activation(agent, f"{name}_retry", label, payload, suffix=f"{suffix}\n\n{JSON_NUDGE}" if suffix else JSON_NUDGE)
        async for ev in self._run_activations(ctx, f"{name}_retry_run", [retry], texts):
            yield ev
        if (t := texts.pop(retry.name, "")):
            texts[name] = t
        n = int(ctx.session.state.get(STATE_JSON_RETRIES) or 0) + 1
        log.info("json retry #%d for %s", n, name)
        yield self._state_event(ctx, {STATE_JSON_RETRIES: n})

    def _pick(self, item, role: str) -> tuple[BaseAgent, str, str]:
        """(agent, specialist name or "", instruction suffix): the router's choice, else the generic fallback."""
        fallback = self.verifier if role == "investigate" else self.critic
        if self.router is None:
            return fallback, "", ""
        files = list(getattr(item, "reads", None) or []) or [getattr(item, "file", "") or ""]
        lang = next((static.LANG_EXT[s] for f in files if (s := "." + f.rsplit(".", 1)[-1]) in static.LANG_EXT), "")
        name, suffix = self.router(item, lang, role)
        agent = self.specialists.get(name) if name else None
        if agent is None:
            if name:
                log.warning("router: unknown specialist %r for %s — using the generic %s", name, role, fallback.name)
            return fallback, "", ""
        return agent, name, suffix

    def _budget_hit(self, ctx: InvocationContext) -> bool:
        return bool(ctx.session.state.get(core.STATE_BUDGET_EXHAUSTED))

    def _gate(self, hs: list[Hypothesis], rnd: int) -> list[Hypothesis]:
        """Belt over the dispatch tool: drop ungrounded, cap at max_hyps, assign ids h<round>-<n>."""
        out = []
        for n, h in enumerate(hs, 1):
            h.id = h.id or f"h{rnd}-{n}"
            if reason := core.ground_hypothesis(h, self.has_anchor, self.has_symbol):
                log.warning("gate: dropped ungrounded hypothesis %s: %s", h.id, reason)
                self.store.add_note(f"dropped ungrounded hypothesis {h.id}: {reason}", h.id)
                continue
            out.append(h)
            if len(out) >= self.max_hyps:
                break
        return out

    async def _verify(
        self, ctx: InvocationContext, rnd: int, accepted: list[Hypothesis], out: dict
    ) -> AsyncGenerator[Event, None]:
        """One Verifier per hypothesis, ≤ max_parallel at a time. Verdict from STORE facts; the model's
        JSON only adds notes/new_hypotheses. out = {"dossiers", "failed", "budget"}."""
        texts: dict[str, str] = {}
        failed = ""
        routed = [self._pick(h, "investigate") for h in accepted]  # (agent, specialist name, suffix) per hypothesis
        payloads = [{**h.model_dump(), "skill": skill_for(h.cwe, h.kind), "skills": skills_for(h.cwe, h.kind), "specialist": name}
                    for h, (_, name, _) in zip(accepted, routed)]
        acts = [(h, _activation(agent, f"verify_r{rnd}_{i}", "Hypothesis", payloads[i], suffix=suffix))
                for i, (h, (agent, _, suffix)) in enumerate(zip(accepted, routed))]
        step = self.max_parallel if self.max_parallel > 0 else len(acts)
        for ci in range(0, len(acts), step):
            chunk = [a for _, a in acts[ci : ci + step]]
            try:
                async for ev in self._run_activations(ctx, f"verify_round_{rnd}_{ci}", chunk, texts):
                    yield ev
            except Exception as e:  # noqa: BLE001 — a failed chunk ends the round; round 0 is fatal in the caller
                failed = str(e)
                break
        if not failed:  # a verifier that answered in prose gets one nudge to hand over its Dossier JSON
            for i, (h, a) in enumerate(acts):
                if parse_json(texts.get(a.name, "")) is None and not self._budget_hit(ctx):
                    agent, _, suffix = routed[i]  # the retry goes to the same specialist with the same overlay
                    async for ev in self._retry_json(ctx, agent, a.name, "Hypothesis", payloads[i], texts, suffix=suffix):
                        yield ev
        budget = self._budget_hit(ctx)
        findings = self.store.findings()
        dossiers = []
        exhausted = {k.rsplit(".", 1)[-1] for k, v in ctx.session.state.items() if v and k.startswith(f"{core.STATE_BUDGET_EXHAUSTED}:")}
        for i, (h, a) in enumerate(acts):
            d = dossier_from_store(findings, h)
            if "specialist" in Dossier.model_fields:
                d = d.model_copy(update={"specialist": routed[i][1]})
            own_budget = a.name in exhausted  # this verifier ran out of calls; the run goes on
            raw = texts.get(a.name, "")
            md = parse_json(raw)
            if md is not None:
                try:
                    m = Dossier.model_validate(md)
                    d.notes, d.new_hypotheses = m.notes, m.new_hypotheses
                except ValueError as e:
                    d.error = f"invalid Dossier JSON: {e}"
            elif not d.finding_id:  # nothing in the store and no JSON: the verifier never got there
                d.error = failed or ("budget" if budget or own_budget else "no Dossier JSON and nothing reported")
            if d.error:
                log.warning("verify %s: %s", h.id, d.error)
            dossiers.append(d)
        out.update(dossiers=dossiers, failed=failed, budget=budget)

    async def _critic_pass(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        confirmed = [f for f in self.store.findings() if f.status == core.CONFIRMED]
        if not confirmed:
            return
        acts = []
        for i, f in enumerate(confirmed):
            a = self.store.anchor(f.anchor_id)
            agent, name, suffix = self._pick(f, "critique")
            payload = {"finding": f.model_dump(), "anchor": a.model_dump() if a else None, "specialist": name,
                       "skills": skills_for(f.cwe, "", "critique")}
            acts.append(_activation(agent, f"critic_{i}", "Finding", payload, suffix=suffix))
            if name:
                self.store.add_note(f"critic:{name} reviewed {f.id}", f.id)
        step = self.max_parallel if self.max_parallel > 0 else len(acts)
        texts: dict[str, str] = {}
        for ci in range(0, len(acts), step):
            try:
                async for ev in self._run_activations(ctx, f"critic_{ci}", acts[ci : ci + step], texts):
                    yield ev
            except Exception as e:  # noqa: BLE001 — critic failure never loses confirmed findings
                log.warning("critic chunk %d failed: %s", ci, e)
                self.store.add_note(f"critic chunk {ci} failed: {e}")
        still = sum(1 for f in self.store.findings() if f.status == core.CONFIRMED)
        log.info("critic: %d confirmed → %d survived", len(confirmed), still)

    async def _finish(self, ctx: InvocationContext, stop: str, rnd: int, timings: dict | None = None) -> AsyncGenerator[Event, None]:
        """Terminal: critic pass (if any), then the report event carrying stop_reason."""
        if self.critic is not None:
            t0 = time.monotonic()
            async for ev in self._critic_pass(ctx):
                yield ev
            if timings is not None:
                timings["critic"] = round(time.monotonic() - t0, 3)
        if stop:
            log.warning("%s: finish (%s)", self.name, stop)
        yield Event(
            author=self.name, invocation_id=ctx.invocation_id, branch=ctx.branch,
            content=types.Content(role="model", parts=[types.Part(text=f"rounds: {rnd}")]),
            actions=EventActions(state_delta={core.STATE_STOP_REASON: stop}),
        )


# Deprecated private aliases — kept one release for callers that import the old names.
_activation, _with_deadline, _text_of, _Graph = activation, with_deadline, text_of, Graph
