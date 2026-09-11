"""ADK callbacks: model-call budgets (per branch or global) and tool-call logging."""

from __future__ import annotations

import logging

from google.adk.models.llm_response import LlmResponse
from google.genai import types

from scanner import core

log = logging.getLogger("scanner.callbacks")


BUDGET_LAST_CALL = ("Model-call budget is exhausted after this reply. Answer NOW with your final JSON only — "
                    "tools are disabled for this turn.")

def budget_callback(limit: int, per_branch: bool = False, stop_run: bool = False):
    """before_model_callback counting model calls (per branch or globally).

    Call `limit`: tools are stripped and the model is told to answer with its final JSON now.
    Beyond it: a canned reply ends the turn; state gets `budget_exhausted:<branch>`, and — only when
    stop_run — the global flag that makes the graph finish (the Lead's budget in v1)."""
    counters: dict[str | None, int] = {}

    def cb(callback_context, llm_request) -> LlmResponse | None:
        if limit <= 0:
            return None
        key = callback_context.branch if per_branch else None
        counters[key] = counters.get(key, 0) + 1
        if counters[key] < limit:
            return None
        if counters[key] == limit:  # last allowed call: force the answer
            llm_request.config.tools = None
            llm_request.contents.append(types.Content(role="user", parts=[types.Part(text=BUDGET_LAST_CALL)]))
            return None
        log.warning("budget: model-call limit %d exhausted (branch=%s)", limit, key)
        callback_context.state[f"{core.STATE_BUDGET_EXHAUSTED}:{callback_context.branch}"] = True
        if stop_run:
            callback_context.state[core.STATE_BUDGET_EXHAUSTED] = True
        return LlmResponse(
            content=types.Content(role="model", parts=[types.Part(text="budget exhausted")])
        )

    return cb

def tool_window_callback(keep: int = 3):
    """before_model_callback: within one activation only the last `keep` tool results stay verbatim; older
    function responses are replaced by a one-line digest (tool + args + size) so the prompt stops growing."""

    def cb(callback_context, llm_request) -> None:
        calls = {p.function_call.id: p.function_call for c in llm_request.contents for p in c.parts or [] if p.function_call}
        responses = [p for c in llm_request.contents for p in c.parts or [] if p.function_response]
        for p in responses[:-keep] if keep > 0 else responses:
            fr = p.function_response
            if isinstance(fr.response, dict) and set(fr.response) == {"digest"}:
                continue  # already digested
            call = calls.get(fr.id)
            args = " ".join(f"{k}={v}" for k, v in (call.args or {}).items()) if call else ""
            r = fr.response
            size = sum(len(v) if isinstance(v, str) else len(str(v)) for v in r.values()) if isinstance(r, dict) else len(str(r))
            p.function_response = types.FunctionResponse(
                id=fr.id, name=fr.name, response={"digest": f"{fr.name} {args[:80]}: {size} chars".replace("  ", " ")}
            )

    return cb


def log_tools_callback(tool, args: dict, tool_context) -> None:
    log.info("agent tool %s branch=%s args=%s", tool.name, tool_context.branch, args)
