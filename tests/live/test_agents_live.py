"""Live per-agent eval against a real model. Opt-in: LIVE_EVAL=1 uv run pytest -m live tests/live."""

import asyncio
import os

import pytest

pytestmark = [pytest.mark.live, pytest.mark.skipif(os.environ.get("LIVE_EVAL") != "1", reason="set LIVE_EVAL=1 (needs a running model)")]


def test_every_agent_produces_a_graded_trial():
    from eval.agents import TRIALS, run_all

    only = set(os.environ.get("EVAL_ONLY", "").split(",")) - {""} or None  # e.g. EVAL_ONLY=taint,authz_critic
    card = asyncio.run(run_all(os.environ.get("EVAL_MODEL", "openai/qwen3:1.7b"), k=1, budget=int(os.environ.get("EVAL_BUDGET", "8")), only=only))
    expected = (only or set(TRIALS)) | ({"tool_window"} if not only or "investigator" in only else set())
    assert set(card["agents"]) == expected
    for name, a in card["agents"].items():
        assert a["k"] == 1 and a["pass_at_k"] in (0, 1) and isinstance(a["failures"], list), name
    # a baseline reports, it does not gate: print the numbers for the run log
    print({n: (a["passes"], a["failures"]) for n, a in card["agents"].items()})
