"""Live per-agent eval (eval-driven development): run EACH agent alone against a real model k times and grade
with deterministic code graders; report pass@k (any of k passed) and pass^k (all k passed) per agent.

    uv run python -m eval.agents --model openai/qwen3:1.7b --k 3 --out eval/scorecard.json

Agents under test: Architect, ThreatModeler, Investigator (Verifier), Critic, the tool-window callback (graded from the
Investigator's model requests) and every specialist of scanner/app/specialists.py (taint, authz, dependency, secrets,
config, taint_critic, authz_critic, dependency_critic), each on its own fixture and routed like the graph does.
`--only taint,authz` selects a subset. Target fixtures: samples/02-vulnshop, 08-idor-go, 11-expressshop, temp files.
The model comes from --model: an `openai/<name>` LiteLLM spec (default ollama at localhost:11434) or a Gemini
model string when GOOGLE_API_KEY is set. Findings/anchors live in a throwaway Store under a temp dir.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import json
import os
import tempfile
import time
from pathlib import Path

from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.workflow import FunctionNode
from google.genai import types

from scanner import core
from scanner.adapter.index import build_index
from scanner.adapter.store import Store
from scanner.adapter.tools import ToolContext
from scanner.app.agents import build
from scanner.app.agents.registry import AGENTS
from scanner.app.graph.helpers import parse_json, text_of
from scanner.app.graph.reconcile import KNOWN_WSTG
from scanner.core import (
    Anchor,
    ArchitectureModel,
    Finding,
    Hypothesis,
    ThreatModel,
    new_anchor_id,
)

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "02-vulnshop"

TRIAL_TIMEOUT = 300  # seconds per activation

SQLI = Anchor(id=new_anchor_id("gosec", "G202", "main.go", 22), tool="gosec", rule_id="G202", cwe="CWE-89", severity="high",
              file="main.go", line=22, message="SQL string concatenation", snippet='db.Query("SELECT id FROM users WHERE name = \'" + name + "\'")')

SAFE = Anchor(id=new_anchor_id("gosec", "G202", "main.go", 37), tool="gosec", rule_id="G202", cwe="CWE-89", severity="high",
              file="main.go", line=37, message="SQL string formatting", snippet='db.Query("SELECT id FROM users WHERE name = $1", name)')

CMDI = Anchor(id=new_anchor_id("gosec", "G204", "main.go", 30), tool="gosec", rule_id="G204", cwe="CWE-78", severity="high",
              file="main.go", line=30, message="Subprocess launched with variable", snippet='exec.Command("sh", "-c", "ping -c1 "+host)')

SKELETON = {
    "target": str(SAMPLE),
    "entry_points": [{"kind": "entry", "file": "main.go", "line": 13, "symbol": "searchHandler"},
                     {"kind": "entry", "file": "main.go", "line": 14, "symbol": "pingHandler"}],
    "anchors": [{"id": a.id, "tool": a.tool, "cwe": a.cwe, "file": a.file, "line": a.line, "message": a.message} for a in (SQLI, CMDI)],
}

ARCH_MODEL = ArchitectureModel(
    entities=[{"name": "http handlers", "files": ["main.go"], "role": "HTTP API", "grounding_symbol": "searchHandler", "criticality": "STANDARD"},
              {"name": "shell runner", "files": ["main.go"], "role": "ping via sh -c", "grounding_symbol": "pingHandler", "criticality": "STANDARD"}],
    trust_boundaries=["http handlers: searchHandler — query param `name` from the network",
                      "shell runner: pingHandler — query param `host` from the network"],
    vuln_classes=[{"cwe": "CWE-89", "wstg_id": "WSTG-INJT-05", "why": "string-built SQL"}, {"cwe": "CWE-78", "wstg_id": "WSTG-INJT-12", "why": "sh -c"}],
    deployment_signals=["http.ListenAndServe(\":8080\")"],
).model_dump()

HYP = Hypothesis(id="h0-1", kind="sink", cwe="CWE-89", claim="user input from r.URL.Query().Get(\"name\") reaches db.Query at main.go:22 "
                 "by string concatenation without parameterization", anchor_id=SQLI.id, reads=["main.go"], priority=80)


def make_model(spec: str):
    if spec.startswith("gemini"):
        if not os.environ.get("GOOGLE_API_KEY"):
            raise SystemExit("gemini model needs GOOGLE_API_KEY in the environment")
        return spec
    from google.adk.models.lite_llm import LiteLlm

    return LiteLlm(model=spec, api_base=os.environ.get("LLM_BASE_URL", "http://localhost:11434/v1"),
                   api_key=os.environ.get("LLM_API_KEY", "ollama"))


class Probe:
    """before_model_callback: counts model calls and, per request, verbatim vs digested tool responses."""

    def __init__(self):
        self.calls, self.windows = 0, []  # windows: (total function responses, verbatim ones)

    def __call__(self, callback_context, llm_request):
        self.calls += 1
        rs = [p.function_response for c in llm_request.contents for p in c.parts or [] if p.function_response]
        verbatim = sum(1 for r in rs if not (isinstance(r.response, dict) and set(r.response) == {"digest"}))
        self.windows.append((len(rs), verbatim))


async def _activate(agent, label: str, payload: dict, probe: Probe, suffix: str = "") -> tuple[str, list[str]]:
    """Run one activation like the graph does (the payload is the user turn of a dynamic `ctx.run_node`; `label`
    is kept for the callers, the JSON carries its own shape); returns (final text, tool call names)."""
    cbs = agent.before_model_callback
    agent.before_model_callback = [*(cbs if isinstance(cbs, list) else [cbs] if cbs else []), probe]
    if suffix:
        payload = {**payload, "instructions": suffix}

    async def driver(ctx, node_input):
        return await ctx.run_node(agent, payload, run_id=f"eval_{agent.name}")
    svc = Runner(app_name="eval", node=FunctionNode(func=driver, name="driver", rerun_on_resume=True),
                 session_service=InMemorySessionService())
    await svc.session_service.create_session(app_name="eval", user_id="u", session_id="s")
    text, tools = "", []
    async for ev in svc.run_async(user_id="u", session_id="s", new_message=types.Content(role="user", parts=[types.Part(text="go")])):
        tools += [fc.name for fc in ev.get_function_calls()]
        text = (ev.output if isinstance(ev.output, str) else "") or text_of(ev) or text
    return text, tools


def _agent(name: str, model, run, target: Path, index, budget: int, only: tuple[str, ...] = ()):
    """One registry agent with the trial's budget; `only` narrows the roster (the ThreatModeler trial gives it consult_owasp alone)."""
    spec = AGENTS[name]
    if only:
        spec = dataclasses.replace(spec, tools=only)
    return build(dataclasses.replace(spec, budget=budget), model, ToolContext(target, run, index=index))


def _store(tmp: Path, anchors: list[Anchor]):
    store = Store(str(tmp / f"state-{time.time_ns()}.db"))
    run = store.start_run(str(SAMPLE))
    run.save_anchors(anchors)
    return store, run


def _refusals(run) -> list[str]:
    return [r[:90] for (r,) in run.db.execute("SELECT reason FROM gate_log WHERE run=?", (run.id,))]


async def trial_architect(model, tmp, index, budget, probe):
    store, run = _store(tmp, [SQLI, CMDI])
    text, tools = await _activate(_agent("model", model, run, SAMPLE, index, budget), "Skeleton", SKELETON, probe)
    store.close()
    if not {"list_entry_points", "grep", "read_file", "lsp_symbols"} & set(tools):
        return False, f"never looked at the code (tools: {sorted(set(tools))})"
    parsed = parse_json(text)
    if parsed is None:
        return False, "final text is not JSON"
    try:
        am = ArchitectureModel.model_validate(parsed)
    except ValueError as e:
        return False, f"not an ArchitectureModel: {str(e)[:80]}"
    grounded = [e for e in am.entities if e.grounding_symbol and index.has_symbol(e.grounding_symbol)]
    if not grounded:
        return False, f"no entity grounded on a real symbol ({[e.grounding_symbol for e in am.entities]})"
    ghosts = [e.grounding_symbol for e in am.entities if e.grounding_symbol and not index.has_symbol(e.grounding_symbol)]
    if ghosts:
        return False, f"entities grounded on symbols that do not exist: {ghosts}"
    fake = [v.wstg_id for v in am.vuln_classes if v.wstg_id and v.wstg_id not in KNOWN_WSTG]
    if fake:
        return False, f"fabricated WSTG ids: {fake} (consult_owasp was not used)"
    return True, ""


async def trial_threat_modeler(model, tmp, index, budget, probe):
    text, _ = await _activate(_agent("threat_modeler", model, None, SAMPLE, None, budget, only=("consult_owasp",)), "ArchitectureModel", {"architecture_model": ARCH_MODEL}, probe)
    parsed = parse_json(text)
    if parsed is None:
        return False, "final text is not JSON"
    try:
        tm = ThreatModel.model_validate(parsed)
    except ValueError as e:
        return False, f"not a ThreatModel: {str(e)[:80]}"
    if not tm.threats:
        return False, "no threats"
    known = {"searchHandler", "pingHandler"}
    bad = [t for t in tm.threats if not t.cwe.startswith("CWE-") or t.symbol.split(".")[-1] not in known]
    if bad:
        return False, f"{len(bad)}/{len(tm.threats)} threats without cwe or with a symbol not in the model"
    return (True, "") if tm.intent in ("production", "sample") else (False, f"intent={tm.intent}")


async def trial_verifier(model, tmp, index, budget, probe):
    store, run = _store(tmp, [SQLI, CMDI])
    _, tools = await _activate(_agent("verify", model, run, SAMPLE, index, budget), "Hypothesis",
                               {**HYP.model_dump(), "skill": "sql-injection"}, probe)
    fs, refusals = run.findings(), _refusals(run)
    store.close()
    if "report_finding" not in tools:
        return False, f"never called report_finding (tools: {tools})"
    ok = [f for f in fs if f.anchor_id == SQLI.id and f.status == core.CONFIRMED and any("db.Query" in e for e in f.evidence)]
    if not ok:
        return False, f"no confirmed finding quoting db.Query (findings: {[(f.status, f.anchor_id[:8]) for f in fs]}; gate refused: {refusals}; tools: {tools})"
    return (True, "") if not refusals else (False, f"{len(refusals)} gate refusals before the accepted finding: {refusals}")


async def trial_critic(model, tmp, index, budget, probe):
    store, run = _store(tmp, [SQLI, SAFE])
    fp = run.report(Finding(anchor_id=SAFE.id, cwe="CWE-89", file="main.go", line=37, title="SQL injection in safeHandler",
                            status=core.CONFIRMED, evidence=['rows, _ := db.Query("SELECT id FROM users WHERE name = $1", name)'], confidence=0.9))
    tp = run.report(Finding(anchor_id=SQLI.id, cwe="CWE-89", file="main.go", line=22, title="SQL injection in searchHandler",
                            status=core.CONFIRMED, evidence=['rows, _ := db.Query("SELECT id FROM users WHERE name = \'" + name + "\'")'], confidence=0.95))
    critic = _agent("critic", model, run, SAMPLE, index, budget)
    for f in (fp, tp):
        await _activate(critic, "Finding", {"finding": f.model_dump(), "anchor": run.anchor(f.anchor_id).model_dump()}, probe)
    st = {f.id: f for f in run.findings()}
    store.close()
    if st[tp.id].status != core.CONFIRMED:
        return False, f"real SQLi did not survive (status {st[tp.id].status})"
    if st[fp.id].status == core.CONFIRMED:
        return False, "parameterized /safe query still confirmed (false positive not disproved)"
    return (True, "") if any("$1" in e for e in st[fp.id].evidence) else (False, "disproved without quoting the $1 placeholder")


def grade_window(probe: Probe, keep: int = 3):
    big = [w for w in probe.windows if w[0] >= 5]
    if not big:
        return False, f"model never reached 5 tool results in one activation (max {max((w[0] for w in probe.windows), default=0)})"
    worst = max(v for _, v in big)
    return (worst <= keep, "" if worst <= keep else f"{worst} verbatim tool responses kept, expected ≤{keep}")

FAKE_TOKEN = "ghp_9Q3xL2mV8nB4kT7pW1rY6sD0fH5jZ2aC3eG9"

ELSE_BRANCH_GO = """package main

import (
	"encoding/json"
	"net/http"
)

type Order struct {
	ID     string
	UserID string
}

var orders = map[string]Order{}

func currentUser(r *http.Request) string { return r.Header.Get("X-User") }

func getOrder(w http.ResponseWriter, r *http.Request) {
	order := orders[r.URL.Query().Get("id")]
	if r.Header.Get("X-Admin") == "1" {
		json.NewEncoder(w).Encode(order)
	} else {
		if order.UserID != currentUser(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(order)
	}
}

func main() { http.HandleFunc("/order", getOrder) }
"""

TRIALS = {
    "model": trial_architect, "threat_modeler": trial_threat_modeler, "investigator": trial_verifier, "critic": trial_critic,
}


async def run_all(model_spec: str, k: int, budget: int, only: set[str] | None = None) -> dict:
    model = make_model(model_spec)
    index = build_index(SAMPLE)
    card: dict = {"model": model_spec, "k": k, "budget": budget, "agents": {}}
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for name, trial in TRIALS.items():
            if only and name not in only:
                continue
            rows, window_probes = [], []
            for i in range(k):
                probe, t0 = Probe(), time.monotonic()
                try:
                    passed, reason = await asyncio.wait_for(trial(model, tmp, index, budget, probe), TRIAL_TIMEOUT)
                except Exception as e:  # noqa: BLE001 — a crash is a failed trial, not a crashed harness
                    passed, reason = False, f"{type(e).__name__}: {str(e)[:120]}"
                rows.append({"pass": passed, "reason": reason, "model_calls": probe.calls, "seconds": round(time.monotonic() - t0, 1)})
                print(f"  {name} #{i + 1}: {'PASS' if passed else 'FAIL'} {reason} ({probe.calls} model calls, {rows[-1]['seconds']}s)", flush=True)
                if name == "investigator":
                    window_probes.append(probe)
            card["agents"][name] = _summary(rows)
            if name == "investigator":
                wrows = [dict(zip(("pass", "reason"), grade_window(p), strict=True)) for p in window_probes]
                card["agents"]["tool_window"] = _summary([{**r, "model_calls": 0, "seconds": 0} for r in wrows])
    index.close()
    passes = [a["pass_at_k"] for a in card["agents"].values()]
    card["total"] = {"agents": len(passes), "pass_at_k": round(sum(passes) / len(passes), 2) if passes else 0,
                     "pass_pow_k": round(sum(a["pass_pow_k"] for a in card["agents"].values()) / len(passes), 2) if passes else 0}
    return card


def _summary(rows: list[dict]) -> dict:
    n, p = len(rows), sum(r["pass"] for r in rows)
    return {"k": n, "passes": p, "pass_at_k": int(p > 0), "pass_pow_k": int(p == n),
            "mean_model_calls": round(sum(r["model_calls"] for r in rows) / n, 1), "mean_seconds": round(sum(r["seconds"] for r in rows) / n, 1),
            "failures": [r["reason"] for r in rows if not r["pass"]]}


def print_table(card: dict) -> None:
    print(f"\nmodel={card['model']} k={card['k']} budget={card['budget']}")
    print(f"{'agent':15} {'passes':>6} {'pass@k':>6} {'pass^k':>6} {'calls':>6} {'sec':>6}  failures")
    for name, a in card["agents"].items():
        print(f"{name:15} {a['passes']:>3}/{a['k']:<2} {a['pass_at_k']:>6} {a['pass_pow_k']:>6} {a['mean_model_calls']:>6} {a['mean_seconds']:>6}  {'; '.join(a['failures'])[:90]}")
    print(f"total: pass@k {card['total']['pass_at_k']}  pass^k {card['total']['pass_pow_k']}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--model", default="openai/qwen3:1.7b")
    ap.add_argument("--k", type=int, default=3)
    ap.add_argument("--budget", type=int, default=12, help="model calls per activation")
    ap.add_argument("--only", default="", help="comma-separated agent names")
    ap.add_argument("--out", default="eval/scorecard.json")
    a = ap.parse_args(argv)
    card = asyncio.run(run_all(a.model, a.k, a.budget, set(a.only.split(",")) - {""} or None))
    Path(a.out).write_text(json.dumps(card, indent=1, ensure_ascii=False))
    print_table(card)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
