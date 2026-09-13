"""audit: drain the queue through the gate and the Investigator fan-out until empty, the round limit or the budget —
the one node whose shape depends on data."""

from __future__ import annotations

import time
from collections.abc import Callable

from google.adk.workflow import node

from scanner import core
from scanner.app.graph.helpers import gate_hypotheses, llm_findings
from scanner.app.graph.reconcile import key, reconcile
from scanner.core import Dossier
from scanner.core.ports import RunStore
from scanner.core.workflow import QueueState, ResearchResult


def audit_node(store: RunStore, verify_node, has_anchor: Callable[[str], bool], has_symbol: Callable[[str], bool],
               max_rounds: int, max_hyps: int, timings: dict[str, float]):
    async def audit(ctx, node_input: dict) -> dict:
        """Drain the queue in ≤ max_hyps batches through the gate and the Investigator fan-out until empty,
        the round limit or the budget — the one node whose shape depends on data."""
        qs = QueueState.model_validate(node_input)
        queue, done = list(qs.queue), set(qs.done)
        rnd, stop = int(ctx.state.get(core.STATE_ROUND) or 0), ""
        while queue:
            if rnd >= max_rounds:
                stop = "round limit"
                break
            batch, queue = queue[:max_hyps], queue[max_hyps:]
            done |= {key(h) for h in batch}  # gated-out items are done too: they never become grounded
            accepted = gate_hypotheses(batch, rnd, store, has_anchor, has_symbol, max_hyps)
            store.put_hypotheses(rnd, accepted)
            ctx.state[core.STATE_ROUND] = rnd + 1
            ctx.state["queue"] = len(queue)
            if not accepted:
                rnd += 1
                continue
            t0 = time.monotonic()
            outs = await ctx.run_node(verify_node, [h.model_dump() for h in accepted], run_id=f"verify_r{rnd}") or []
            timings[f"verify_{rnd}"] = round(time.monotonic() - t0, 3)
            dossiers = [Dossier.model_validate(o) for o in outs]
            budget = bool(ctx.state.get(core.STATE_BUDGET_EXHAUSTED))
            failed = "; ".join(d.error for d in dossiers if d.error) if outs and all(o.get("failed") for o in outs) else ""
            if failed and not budget and rnd == 0:
                raise RuntimeError(f"verify round 0 failed: {failed}")  # a failed run keeps no round-0 dossiers
            store.put_dossiers(rnd, dossiers)
            rnd += 1
            if budget:
                stop = "budget"
                break
            if failed:
                stop = f"verify round {rnd - 1} failed: {failed}"
                break
            queue = reconcile([h for d in dossiers for h in d.new_hypotheses[:3]], queue, done)
        ctx.state[core.STATE_STOP_REASON] = stop
        return ResearchResult(rounds=rnd, stop=stop, findings=len(llm_findings(store))).model_dump()
    return node(audit, rerun_on_resume=True, name="audit")
