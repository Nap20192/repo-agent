"""v2 graph: Architect → DomainModeler → ThreatModeler → Reconciler → Investigator ⇄ queue → Critic → report.

Stage artifacts (architecture_model, domain_map, threat_model) are grounded in code before the queue is built."""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncGenerator, Callable
from dataclasses import dataclass
from pathlib import Path

from google.adk.agents import BaseAgent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.events import Event
from pydantic import Field

from scanner import core
from scanner.app.graph import (
    Graph,
    _ActivationSpec,
    activation,
    parse_json,
    with_deadline,
)
from scanner.app.reconcile import (
    KNOWN_WSTG,
    coverage,
    from_anchors,
    from_threats,
    ground_artifacts,
    key,
    reconcile,
)
from scanner.core import ArchitectureModel, Candidate, Hypothesis, Threat, ThreatModel
from scanner.core.ports import Closeable

log = logging.getLogger("scanner.pipeline_v2")


@dataclass
class _RoundResult:
    """Out-param for `_investigate_round`: an async generator can't `return` a value while still yielding events."""

    rnd: int = 0
    stop: str = ""


class PipelineV2(Graph):
    """v2 (step 2): no Lead. Reconciler builds one queue from anchors + threats + Verifier new_hypotheses;
    the Investigator (= Verifier) drains it in batches until empty, round limit or budget; then Critic."""

    architect: BaseAgent | None = None
    domain_modeler: BaseAgent | None = None  # Architect → DomainModeler → ThreatModeler
    threat_modeler: BaseAgent | None = None
    threats: list[Threat] = Field(default_factory=list)  # explicit threats (tests) — merged with the ThreatModel's
    locate: Callable[[str], tuple[str, int] | None] | None = None  # symbol → (file, line) for synthetic anchors
    entry_points_fn: Callable[[], list[Candidate]] | None = None
    index: Closeable | None = None  # the code Index (closed by the runner), not used by the graph itself
    stage_timeout: float = 600.0  # seconds per LLM stage; a slow stage is cancelled and noted, the scan goes on

    def __init__(self, name: str = "scan_v2", **kw):
        super().__init__(name=name, **kw)

    async def _stage(
        self, ctx: InvocationContext, agent: BaseAgent, stage: str, payload: dict, out: dict, timings: dict | None = None
    ) -> AsyncGenerator[Event, None]:
        """One LLM stage: run the agent on payload (bounded by `stage_timeout` seconds, one JSON-nudge retry),
        parse its JSON into out[stage] (None when invalid), persist."""
        if (cached := self.store.artifact(stage)) is not None:  # resume: the stage already ran for this run
            out[stage] = cached
            return
        texts: dict[str, str] = {}
        t0 = time.monotonic()
        limit = self.stage_timeout
        try:
            run = self._run_activations(ctx, f"stage_{stage}", [activation(agent, stage, stage, payload)], texts)
            async for ev in with_deadline(run, limit):
                yield ev
            act = _ActivationSpec(stage, stage, payload)
            async for ev in with_deadline(self._retry_json(ctx, agent, act, texts), limit):
                yield ev
        except Exception as e:  # noqa: BLE001 — a failed/slow model stage degrades to "no artifact", the scan goes on
            log.warning("stage %s failed: %s", stage, e)
            self.store.add_note(f"stage {stage} failed: {e}")
        if timings is not None:
            timings[stage] = round(time.monotonic() - t0, 3)
        parsed = parse_json(texts.get(stage, ""))
        if parsed is None:
            log.warning("stage %s: no valid JSON, continuing without it", stage)
            self.store.add_note(f"stage {stage}: no valid JSON")
        else:
            self.store.put_artifact(stage, parsed)
        out[stage] = parsed

    async def _model_threats(
        self, ctx: InvocationContext, anchors: list, out: list[Threat], timings: dict | None = None
    ) -> AsyncGenerator[Event, None]:
        """Architect → ThreatModeler; the ThreatModel's threats are appended to `out` (no agent state mutated)."""
        arts: dict = {}
        if self.architect is not None:
            skeleton = {
                "target": self.target,
                "entry_points": [c.model_dump() for c in (self.entry_points_fn() if self.entry_points_fn else [])],
                "anchors": [{"id": a.id, "tool": a.tool, "cwe": a.cwe, "file": a.file, "line": a.line, "message": a.message[:120]} for a in anchors],
            }
            async for ev in self._stage(ctx, self.architect, "architecture_model", skeleton, arts, timings):
                yield ev
        am = arts.get("architecture_model") or ArchitectureModel().model_dump()
        if self.domain_modeler is not None:
            from scanner.adapter.domain import (
                extract,  # adapter stays importable without the graph
            )

            skeleton = extract(Path(self.target), self.index).model_dump() if Path(self.target).is_dir() else {}
            async for ev in self._stage(ctx, self.domain_modeler, "domain_map", {"architecture_model": am, "skeleton": skeleton}, arts, timings):
                yield ev
        if self.threat_modeler is not None:
            payload = {"architecture_model": am, "domain_map": arts.get("domain_map") or {}}
            async for ev in self._stage(ctx, self.threat_modeler, "threat_model", payload, arts, timings):
                yield ev
            if arts.get("threat_model"):
                try:
                    tm = ThreatModel.model_validate(arts["threat_model"])
                    out.extend(tm.threats)
                    log.info("threat model: %d threats, intent=%s", len(tm.threats), tm.intent)
                except ValueError as e:
                    log.warning("threat_model: invalid: %s", e)

    async def _run_stages(self, ctx: InvocationContext, anchors: list, timings: dict) -> AsyncGenerator[Event, None]:
        """Architect → DomainModeler → ThreatModeler, then ground the artifacts in code: symbols must exist
        (index or locate), WSTG ids must be real. Grounded artifacts are persisted back to the store; the
        caller re-reads them (`architecture_model`, `threat_model`) once this generator is exhausted."""
        async for ev in self._model_threats(ctx, anchors, [], timings):  # threats are rebuilt from the grounded artifact
            yield ev
        def grounded(symbol: str) -> bool:
            return self.has_symbol(symbol) or bool(self.locate and self.locate(symbol))
        arts = [self.store.artifact(st) for st in ("architecture_model", "domain_map", "threat_model")]
        am_raw, dm_raw, tm_raw = arts
        am, dm, tm, notes = ground_artifacts(am_raw, dm_raw, tm_raw, grounded, KNOWN_WSTG)
        for st, art in zip(("architecture_model", "domain_map", "threat_model"), (am, dm, tm), strict=True):
            if art is not None:
                self.store.put_artifact(st, art)
        for n in notes:
            self.store.add_note(n)
        if notes:
            log.info("grounding: %d items dropped or corrected", len(notes))
        yield self._state_event(ctx, {"grounding_dropped": len(notes)})

    def _build_queue(self, anchors: list) -> tuple[list[Hypothesis], set[str]]:
        """One prioritized queue from the grounded threat model, the scanner anchors and entry-point coverage."""
        am = self.store.artifact("architecture_model") or {}
        tm = self.store.artifact("threat_model")
        threats = list(self.threats)
        if tm:
            try:
                threats += ThreatModel.model_validate(tm).threats
            except ValueError as e:
                log.warning("threat_model: invalid after grounding: %s", e)
        criticality = {e.get("grounding_symbol", ""): e.get("criticality", "") for e in am.get("entities", [])}
        hyps, minted = from_threats(threats, anchors, self.locate, criticality)
        if minted:
            self.store.save_anchors(minted)  # synthetic anchors keep the single anchor-only gate
            log.info("reconcile: %d synthetic anchors for grounded threats", len(minted))
        done: set[str] = set()
        queue = reconcile(from_anchors(anchors) + hyps, [], done)
        if self.entry_points_fn is not None:  # plan-stage rule: no entry point stays unexamined
            baseline, minted_entries = coverage(self.entry_points_fn(), queue, done)
            if minted_entries:
                self.store.save_anchors(minted_entries)  # inline handlers / PHP pages: anchors at file:line
            queue = reconcile(baseline, queue, done)
        return queue, done

    async def _investigate_round(
        self, ctx: InvocationContext, queue: list[Hypothesis], done: set[str], rnd: int, timings: dict,
        result: _RoundResult,
    ) -> AsyncGenerator[Event, None]:
        """Drain `queue` in ≤ max_hyps batches through the gate and the Verifier until empty, the round limit
        or the budget; final round/stop reason land in `result` (an async generator can't return a value)."""
        stop = ""
        while queue:
            if rnd >= self.max_rounds:
                stop = "round limit"
                break
            batch, queue = queue[: self.max_hyps], queue[self.max_hyps :]
            done |= {key(h) for h in batch}  # gated-out items are done too: they never become grounded
            accepted = self._gate(batch, rnd)
            self.store.put_hypotheses(rnd, accepted)
            yield self._state_event(ctx, {core.STATE_ROUND: rnd + 1, "queue": len(queue)})
            if not accepted:
                rnd += 1
                continue
            res: dict = {}
            t0 = time.monotonic()
            async for ev in self._verify(ctx, rnd, accepted, res):
                yield ev
            timings[f"verify_{rnd}"] = round(time.monotonic() - t0, 3)
            dossiers, failed, budget = res["dossiers"], res["failed"], res["budget"]
            if failed and not budget and rnd == 0:
                raise RuntimeError(f"verify round 0 failed: {failed}")
            self.store.put_dossiers(rnd, dossiers)
            rnd += 1
            if budget:
                stop = "budget"
                break
            if failed:
                stop = f"verify round {rnd - 1} failed: {failed}"
                break
            queue = reconcile([h for d in dossiers for h in d.new_hypotheses[:3]], queue, done)
        result.rnd, result.stop = rnd, stop

    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        anchors = self.store.anchors()
        timings: dict[str, float] = {}
        async for ev in self._run_stages(ctx, anchors, timings):
            yield ev
        queue, done = self._build_queue(anchors)
        rnd = int(ctx.session.state.get(core.STATE_ROUND) or 0)
        result = _RoundResult()
        async for ev in self._investigate_round(ctx, queue, done, rnd, timings, result):
            yield ev
        async for ev in self._finish(ctx, result.stop, result.rnd, timings):
            yield ev
        self.store.put_artifact("timings", timings)
