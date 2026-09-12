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
import json
import os
import tempfile
import time
from pathlib import Path

from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from scanner import core
from scanner.adapter.index import build_index
from scanner.adapter.owasp import consult_owasp
from scanner.adapter.store import Store
from scanner.adapter.tools import architect_tools, critic_tools, verifier_tools
from scanner.app import specialists as sp
from scanner.app.agents import (
    new_architect,
    new_critic,
    new_threat_modeler,
    new_verifier,
)
from scanner.app.domain import make_consult_domain
from scanner.app.graph import _activation, _text_of, parse_json
from scanner.core import (
    Anchor,
    ArchitectureModel,
    Finding,
    Hypothesis,
    ThreatModel,
    new_anchor_id,
)
from scanner.core.domain import DomainMap

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "02-vulnshop"
TRIAL_TIMEOUT = 300  # seconds per activation

# anchors of samples/02-vulnshop as the pre-pass would mint them (gosec G202/G204)
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
    """Run one activation like the graph does; returns (final text, tool call names)."""
    cbs = agent.before_model_callback
    agent.before_model_callback = [*(cbs if isinstance(cbs, list) else [cbs] if cbs else []), probe]
    act = _activation(agent, f"eval_{agent.name}", label, payload, suffix=suffix)
    svc = Runner(app_name="eval", agent=act, session_service=InMemorySessionService())
    await svc.session_service.create_session(app_name="eval", user_id="u", session_id="s")
    text, tools = "", []
    async for ev in svc.run_async(user_id="u", session_id="s", new_message=types.Content(role="user", parts=[types.Part(text="go")])):
        tools += [fc.name for fc in ev.get_function_calls()]
        text = _text_of(ev) or text
    return text, tools


def _store(tmp: Path, anchors: list[Anchor]):
    store = Store(str(tmp / f"state-{time.time_ns()}.db"))
    run = store.start_run(str(SAMPLE))
    run.save_anchors(anchors)
    return store, run


def _refusals(run) -> list[str]:
    return [r[:90] for (r,) in run.db.execute("SELECT reason FROM gate_log WHERE run=?", (run.id,))]


# --- one trial per agent: returns (passed, reason) ---------------------------------------------------

async def trial_architect(model, tmp, index, budget, probe):
    store, run = _store(tmp, [SQLI, CMDI])
    text, tools = await _activate(new_architect(model, architect_tools(run, SAMPLE, index=index), budget), "Skeleton", SKELETON, probe)
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
    return (True, "") if grounded else (False, f"no entity grounded on a real symbol ({[e.grounding_symbol for e in am.entities]})")


async def trial_threat_modeler(model, tmp, index, budget, probe):
    text, _ = await _activate(new_threat_modeler(model, [consult_owasp], budget), "ArchitectureModel", {"architecture_model": ARCH_MODEL}, probe)
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
    _, tools = await _activate(new_verifier(model, verifier_tools(run, SAMPLE, index=index), budget), "Hypothesis",
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
    critic = new_critic(model, critic_tools(run, SAMPLE, index=index), budget)
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


# --- specialists (scanner/app/specialists.py): one trial each, routed like the graph does ------------------

IDOR = Path(__file__).resolve().parent.parent / "samples" / "08-idor-go"
IDOR_ANCHOR = Anchor(id=new_anchor_id("threatmodel", "WSTG-ATHZ-04", "main.go", 30), tool="threatmodel", rule_id="WSTG-ATHZ-04",
                     cwe="CWE-639", severity="high", file="main.go", line=30, message="getOrder returns any order by id without an owner check")
DOMAIN_MAP = DomainMap(
    entities=[{"name": "Order", "fields": ["ID", "UserID"], "owner_field": "UserID", "symbol": "Order", "file": "main.go", "line": 9}],
    rules=[{"id": "r1", "statement": "An Order is returned only to the user whose UserID equals the session user (currentUser)",
            "entity": "Order", "symbol": "getMyOrder", "evidence": ["main.go:46"]}],
).model_dump()
EXPRESS_DEP = Anchor(id=new_anchor_id("osv", "express@4.17.1", "package.json", 1), tool="osv", rule_id="GHSA-rv95-896h-c2vc",
                     rule_ids=["GHSA-rv95-896h-c2vc", "CVE-2024-29041"], severity="high", file="package.json", line=1,
                     message="express@4.17.1: 1 advisories (GHSA-rv95-896h-c2vc) — open redirect in res.location / res.redirect with malformed URLs",
                     snippet="express 4.17.1")
FAKE_TOKEN = "ghp_9Q3xL2mV8nB4kT7pW1rY6sD0fH5jZ2aC3eG9"


def _fixture(tmp: Path, name: str, files: dict[str, str]) -> Path:
    t = tmp / name
    t.mkdir(exist_ok=True)
    for f, body in files.items():
        (t / f).write_text(body)
    return t


def _pick(spec_name: str, run, target: Path, index, item, model, lang: str = "go", role: str = "investigate", kind: str = ""):
    """Build the roster for this run and return (agent, overlay suffix) the graph's router would use."""
    agent = sp.build(model, run, target, index)[spec_name]
    spec, suffix = sp.route(item, lang, role, kind)
    assert spec.name == spec_name, f"router picked {spec.name} for the {spec_name} trial"
    return agent, suffix


def _swap_tool(agent, fn) -> None:
    agent.tools = [fn if getattr(t, "__name__", "") == fn.__name__ else t for t in agent.tools]


async def trial_taint(model, tmp, index, budget, probe):
    store, run = _store(tmp, [SQLI, CMDI])
    agent, suffix = _pick("taint", run, SAMPLE, index, HYP, model)
    if suffix != sp.LANG_OVERLAYS["go"] or not suffix:
        return False, "go overlay missing from the routed activation"
    _, tools = await _activate(agent, "Hypothesis", {**HYP.model_dump(), "skill": "sql-injection", "specialist": "taint"}, probe, suffix)
    fs, refusals = run.findings(), _refusals(run)
    store.close()
    ok = [f for f in fs if f.anchor_id == SQLI.id and f.status == core.CONFIRMED and any("db.Query" in e for e in f.evidence)]
    if not ok:
        return False, f"no confirmed finding quoting db.Query (findings: {[(f.status, f.anchor_id[:8]) for f in fs]}; refused: {refusals}; tools: {tools})"
    return True, ""


async def trial_authz(model, tmp, index, budget, probe):
    idx = build_index(IDOR)
    store = Store(str(tmp / f"state-{time.time_ns()}.db"))
    run = store.start_run(str(IDOR))
    run.save_anchors([IDOR_ANCHOR])
    run.put_artifact("domain_map", DOMAIN_MAP)
    hyp = Hypothesis(id="h0-1", kind="authz", cwe="CWE-639", consult="domain", anchor_id=IDOR_ANCHOR.id, reads=["main.go"], priority=80,
                     claim="getOrder returns the Order for any id from the query without comparing Order.UserID to currentUser(r)")
    agent, suffix = _pick("authz", run, IDOR, idx, hyp, model)
    _swap_tool(agent, make_consult_domain(run, idx))  # the map-backed consultant (the runner wires it the same way)
    _, tools = await _activate(agent, "Hypothesis", {**hyp.model_dump(), "skill": "authz-idor", "specialist": "authz"}, probe, suffix)
    fs, refusals = run.findings(), _refusals(run)
    store.close(); idx.close()
    if "consult_domain" not in tools:
        return False, f"never consulted the domain map (tools: {tools})"
    ok = [f for f in fs if f.anchor_id == IDOR_ANCHOR.id and f.status == core.CONFIRMED and any(e.lower().startswith("domain:") for e in f.evidence)]
    return (True, "") if ok else (False, f"no confirmed IDOR with a domain: ref (findings: {[(f.status, f.evidence[:1]) for f in fs]}; refused: {refusals})")


async def trial_dependency(model, tmp, index, budget, probe):
    target = Path(__file__).resolve().parent.parent / "samples" / "11-expressshop"
    idx = build_index(target)
    store = Store(str(tmp / f"state-{time.time_ns()}.db"))
    run = store.start_run(str(target))
    run.save_anchors([EXPRESS_DEP])
    hyp = Hypothesis(id="h0-1", kind="dependency", consult="knowledge", anchor_id=EXPRESS_DEP.id, reads=["package.json", "server.js"], priority=70,
                     claim="express@4.17.1 is affected by GHSA-rv95-896h-c2vc and the app calls res.redirect with user input")
    agent, suffix = _pick("dependency", run, target, idx, hyp, model, lang="node")
    _, tools = await _activate(agent, "Hypothesis", {**hyp.model_dump(), "skill": "dependency-advisory", "specialist": "dependency"}, probe, suffix)
    fs = run.findings()
    store.close(); idx.close()
    if "shell" in tools:
        return False, "dependency specialist must not have/use shell"
    if not ({"consult_knowledge", "knowledge"} & set(tools)):
        return False, f"never consulted knowledge (tools: {tools})"
    ok = [f for f in fs if f.anchor_id == EXPRESS_DEP.id and any(e.lower().startswith("knowledge:") for e in f.evidence)]
    return (True, "") if ok else (False, f"no verdict citing knowledge: (findings: {[(f.status, f.evidence[:1]) for f in fs]}; tools: {tools})")


async def trial_secrets(model, tmp, index, budget, probe):
    target = _fixture(tmp, "secrets", {"config.js": f'const GITHUB_TOKEN = "{FAKE_TOKEN}"; // used by deploy.js\nmodule.exports = {{ GITHUB_TOKEN }};\n'})
    idx = build_index(target)
    store = Store(str(tmp / f"state-{time.time_ns()}.db"))
    run = store.start_run(str(target))
    sec = Anchor(id=new_anchor_id("gitleaks", "github-pat", "config.js", 1), tool="gitleaks", rule_id="github-pat", cwe="CWE-798", severity="high",
                 file="config.js", line=1, message="GitHub personal access token", snippet=core.redact_secrets(f'const GITHUB_TOKEN = "{FAKE_TOKEN}"'))
    run.save_anchors([sec])
    hyp = Hypothesis(id="h0-1", kind="secret", cwe="CWE-798", anchor_id=sec.id, reads=["config.js"], priority=60,
                     claim="config.js commits a live GitHub token that the code uses")
    agent, suffix = _pick("secrets", run, target, idx, hyp, model, lang="node")
    _, tools = await _activate(agent, "Hypothesis", {**hyp.model_dump(), "skill": "information-disclosure", "specialist": "secrets"}, probe, suffix)
    fs = run.findings()
    store.close(); idx.close()
    if "shell" in tools:
        return False, "secrets specialist must not use shell"
    mine = [f for f in fs if f.anchor_id == sec.id]
    if not mine:
        return False, f"no verdict recorded (tools: {tools})"
    leaked = [e for f in mine for e in f.evidence if FAKE_TOKEN in e]
    return (False, "raw token in evidence") if leaked else (True, "")


async def trial_config(model, tmp, index, budget, probe):
    target = _fixture(tmp, "config", {"server.js": 'const express = require("express");\nconst app = express();\n'
                                       'app.post("/login", (req, res) => {\n  const sid = newSession(req.body.user);\n'
                                       '  res.cookie("sid", sid);\n  res.send("ok");\n});\n'})
    idx = build_index(target)
    store = Store(str(tmp / f"state-{time.time_ns()}.db"))
    run = store.start_run(str(target))
    a = Anchor(id=new_anchor_id("semgrep", "express-cookie-session-no-httponly", "server.js", 5), tool="semgrep", rule_id="express-cookie-session-no-httponly",
               cwe="CWE-614", severity="medium", file="server.js", line=5, message="Session cookie set without httpOnly/secure/sameSite", snippet='res.cookie("sid", sid);')
    run.save_anchors([a])
    hyp = Hypothesis(id="h0-1", kind="sink", cwe="CWE-614", anchor_id=a.id, reads=["server.js"], priority=40,
                     claim="the session cookie is set without HttpOnly/Secure/SameSite")
    agent, suffix = _pick("config", run, target, idx, hyp, model, lang="node")
    _, tools = await _activate(agent, "Hypothesis", {**hyp.model_dump(), "skill": "information-disclosure", "specialist": "config"}, probe, suffix)
    fs = run.findings()
    store.close(); idx.close()
    mine = [f for f in fs if f.anchor_id == a.id]
    return (True, "") if mine else (False, f"no verdict recorded (tools: {tools})")


async def trial_taint_critic(model, tmp, index, budget, probe):
    store, run = _store(tmp, [SQLI, SAFE])
    fp = run.report(Finding(anchor_id=SAFE.id, cwe="CWE-89", file="main.go", line=37, title="SQL injection in safeHandler",
                            status=core.CONFIRMED, evidence=['rows, _ := db.Query("SELECT id FROM users WHERE name = $1", name)'], confidence=0.9))
    tp = run.report(Finding(anchor_id=SQLI.id, cwe="CWE-89", file="main.go", line=22, title="SQL injection in searchHandler",
                            status=core.CONFIRMED, evidence=['rows, _ := db.Query("SELECT id FROM users WHERE name = \'" + name + "\'")'], confidence=0.95))
    agent, suffix = _pick("taint_critic", run, SAMPLE, index, fp, model, role="critique")
    tools_all = []
    for f in (fp, tp):
        _, tools = await _activate(agent, "Finding", {"finding": f.model_dump(), "anchor": run.anchor(f.anchor_id).model_dump(), "specialist": "taint_critic"}, probe, suffix)
        tools_all += tools
    st = {f.id: f for f in run.findings()}
    store.close()
    if st[tp.id].status != core.CONFIRMED:
        return False, f"real SQLi did not survive (status {st[tp.id].status})"
    if st[fp.id].status == core.CONFIRMED:
        return False, f"parameterized /safe query still confirmed (tools: {tools_all})"
    if "check_dominance" not in tools_all:
        return False, "disproved without calling check_dominance"
    return True, ""


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


async def trial_authz_critic(model, tmp, index, budget, probe):
    target = _fixture(tmp, "authz_critic", {"main.go": ELSE_BRANCH_GO, "go.mod": "module fixture\n\ngo 1.22\n"})
    idx = build_index(target)
    store = Store(str(tmp / f"state-{time.time_ns()}.db"))
    run = store.start_run(str(target))
    a = Anchor(id=new_anchor_id("threatmodel", "WSTG-ATHZ-04", "main.go", 20), tool="threatmodel", rule_id="WSTG-ATHZ-04", cwe="CWE-639",
               severity="high", file="main.go", line=20, message="admin header bypasses the owner check")
    run.save_anchors([a])
    run.put_artifact("domain_map", DOMAIN_MAP)
    f = run.report(Finding(anchor_id=a.id, cwe="CWE-639", file="main.go", line=20, title="IDOR: X-Admin header skips the owner check",
                           status=core.CONFIRMED, evidence=["domain:r1", 'if r.Header.Get("X-Admin") == "1" {', "json.NewEncoder(w).Encode(order)"], confidence=0.9))
    agent, suffix = _pick("authz_critic", run, target, idx, f, model, role="critique")
    _swap_tool(agent, make_consult_domain(run, idx))
    _, tools = await _activate(agent, "Finding", {"finding": f.model_dump(), "anchor": a.model_dump(), "specialist": "authz_critic"}, probe, suffix)
    st = {x.id: x for x in run.findings()}
    store.close(); idx.close()
    if st[f.id].status != core.CONFIRMED:
        return False, f"finding wrongly disproved: the owner check sits in the else branch (tools: {tools}; evidence: {st[f.id].evidence[-2:]})"
    return True, ""


async def trial_dependency_critic(model, tmp, index, budget, probe):
    target = _fixture(tmp, "dep_critic", {"package.json": '{"name": "x", "dependencies": {"express": "4.17.1"}}\n',
                                          "server.js": 'const express = require("express");\nconst app = express();\n'
                                                       'app.get("/", (req, res) => res.send("hi"));\napp.listen(3000);\n'})
    idx = build_index(target)
    store = Store(str(tmp / f"state-{time.time_ns()}.db"))
    run = store.start_run(str(target))
    run.save_anchors([EXPRESS_DEP])
    f = run.report(Finding(anchor_id=EXPRESS_DEP.id, cwe="", file="package.json", line=1, title="express open redirect GHSA-rv95-896h-c2vc reachable",
                           status=core.CONFIRMED, evidence=["knowledge:GHSA-rv95-896h-c2vc", '"express": "4.17.1"'], confidence=0.8))
    agent, suffix = _pick("dependency_critic", run, target, idx, f, model, lang="node", role="critique", kind="dependency")
    _, tools = await _activate(agent, "Finding", {"finding": f.model_dump(), "anchor": EXPRESS_DEP.model_dump(), "specialist": "dependency_critic"}, probe, suffix)
    st = {x.id: x for x in run.findings()}
    store.close(); idx.close()
    if st[f.id].status == core.CONFIRMED:
        return False, f"still confirmed although res.redirect/res.location is never called (tools: {tools})"
    if not ({"lsp_path_to_entry", "lsp_references", "grep"} & set(tools)):
        return False, f"disproved without checking reachability (tools: {tools})"
    return True, ""


TRIALS = {
    "architect": trial_architect, "threat_modeler": trial_threat_modeler, "investigator": trial_verifier, "critic": trial_critic,
    "taint": trial_taint, "authz": trial_authz, "dependency": trial_dependency, "secrets": trial_secrets, "config": trial_config,
    "taint_critic": trial_taint_critic, "authz_critic": trial_authz_critic, "dependency_critic": trial_dependency_critic,
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
                wrows = [dict(zip(("pass", "reason"), grade_window(p))) for p in window_probes]
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
