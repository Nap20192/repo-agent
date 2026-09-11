"""v2 graph: Architect → ThreatModeler → Reconciler → Investigator ⇄ queue → Critic → report. No Lead."""

from __future__ import annotations

import logging
import os
import time
from collections.abc import AsyncGenerator, Callable
from pathlib import Path
from typing import Any

from google.adk.agents import BaseAgent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.events import Event
from pydantic import Field

from scanner import core
from scanner.app.graph import _activation, _Graph, _with_deadline, parse_json
from scanner.app.reconcile import coverage, from_anchors, from_threats, key, reconcile
from scanner.core import ArchitectureModel, Candidate, Threat, ThreatModel

log = logging.getLogger("scanner.pipeline_v2")


class PipelineV2(_Graph):
    """v2 (step 2): no Lead. Reconciler builds one queue from anchors + threats + Verifier new_hypotheses;
    the Investigator (= Verifier) drains it in batches until empty, round limit or budget; then Critic."""

    architect: BaseAgent | None = None
    domain_modeler: BaseAgent | None = None  # Architect → DomainModeler → ThreatModeler
    threat_modeler: BaseAgent | None = None
    threats: list[Threat] = Field(default_factory=list)  # explicit threats (tests) — merged with the ThreatModel's
    locate: Callable[[str], tuple[str, int] | None] | None = None  # symbol → (file, line) for synthetic anchors
    entry_points_fn: Callable[[], list[Candidate]] | None = None
    index: Any = None  # the code Index (closed by the runner), not used by the graph itself

    def __init__(self, name: str = "scan_v2", **kw):
        super().__init__(name=name, **kw)

    async def _stage(
        self, ctx: InvocationContext, agent: BaseAgent, stage: str, payload: dict, out: dict, timings: dict | None = None
    ) -> AsyncGenerator[Event, None]:
        """One LLM stage: run the agent on payload (bounded by STAGE_TIMEOUT seconds, one JSON-nudge retry),
        parse its JSON into out[stage] (None when invalid), persist."""
        if (cached := self.store.artifact(stage)) is not None:  # resume: the stage already ran for this run
            out[stage] = cached
            return
        texts: dict[str, str] = {}
        t0 = time.monotonic()
        limit = float(os.environ.get("STAGE_TIMEOUT", "600") or 600)
        try:
            run = self._run_activations(ctx, f"stage_{stage}", [_activation(agent, stage, stage, payload)], texts)
            async for ev in _with_deadline(run, limit):
                yield ev
            async for ev in _with_deadline(self._retry_json(ctx, agent, stage, stage, payload, texts), limit):
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

    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        anchors = self.store.anchors()
        threats = list(self.threats)
        timings: dict[str, float] = {}
        async for ev in self._model_threats(ctx, anchors, threats, timings):
            yield ev
        hyps, minted = from_threats(threats, anchors, self.locate)
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
        rnd = int(ctx.session.state.get(core.STATE_ROUND) or 0)
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

        async for ev in self._finish(ctx, stop, rnd, timings):
            yield ev
        self.store.put_artifact("timings", timings)
