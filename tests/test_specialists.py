"""Specialist roster + deterministic router (docs/plans/specialists.md tasks 1-3)."""


import pytest

from scanner.adapter.skills import SKILLS
from scanner.app import specialists as sp
from scanner.app.instructions import OPERATING_PRINCIPLES
from scanner.core import Finding, Hypothesis
from tests.test_tools import IDOR, SQL, FakeRun


def test_registry_names_and_roles():
    names = {s.name: s.role for s in sp.REGISTRY}
    assert names == {"taint": "investigate", "authz": "investigate", "dependency": "investigate", "secrets": "investigate",
                     "config": "investigate", "taint_critic": "critique", "authz_critic": "critique", "dependency_critic": "critique"}
    for s in sp.REGISTRY:
        assert set(s.skills) <= set(SKILLS), s.name


def test_route_cwe_beats_kind_then_kind_then_generic():
    assert sp.route(Hypothesis(kind="sink", cwe="CWE-862", claim="x"))[0].name == "authz"  # cwe wins over kind
    assert sp.route(Hypothesis(kind="sink", cwe="CWE-89", claim="x"))[0].name == "taint"
    assert sp.route(Hypothesis(kind="dependency", cwe="", claim="x"))[0].name == "dependency"  # kind when cwe empty
    assert sp.route(Hypothesis(kind="secret", cwe="CWE-798", claim="x"))[0].name == "secrets"
    assert sp.route(Hypothesis(kind="sink", cwe="CWE-614", claim="x"))[0].name == "config"  # cookie flags: A05
    assert sp.route(Hypothesis(kind="sink", cwe="CWE-338", claim="x"))[0].name == "config"  # weak PRNG: crypto hygiene
    assert sp.route(Hypothesis(kind="sink", cwe="CWE-287", claim="x"))[0].name == "authz"  # A07 authentication
    assert sp.route(Hypothesis(kind="entry", cwe="", claim="x"))[0].name == "taint"  # entry points are taint work
    assert sp.route(Hypothesis(kind="sink", cwe="CWE-9999", claim="x"))[0].name == "taint"  # unknown CWE: kind decides
    assert sp.route(Hypothesis(kind="other", cwe="CWE-9999", claim="x"))[0].name == "verifier"  # generic fallback
    assert sp.ROUTER(Hypothesis(kind="other", cwe="", claim="x"), "go", "investigate") == ("", sp.LANG_OVERLAYS["go"])
    assert sp.ROUTER(Finding(cwe="CWE-89", title="t"), "", "critique") == ("taint_critic", "")


def test_route_findings_for_critics():
    assert sp.route(Finding(cwe="CWE-89", title="t"), role="critique")[0].name == "taint_critic"
    assert sp.route(Finding(cwe="CWE-639", title="t"), role="critique")[0].name == "authz_critic"
    assert sp.route(Finding(cwe="", title="t"), role="critique", kind="dependency")[0].name == "dependency_critic"
    assert sp.route(Finding(cwe="CWE-9999", title="t"), role="critique")[0].name == "critic"


def test_language_overlay_by_suffix():
    assert sp.lang_of(["app/routes/index.js"]) == "node" and sp.lang_of(["x.ts"]) == "node"
    assert sp.lang_of(["main.go"]) == "go" and sp.lang_of(["a.py"]) == "python"
    assert sp.lang_of(["index.php"]) == "" and sp.lang_of([]) == ""
    _, suffix = sp.route(Hypothesis(kind="sink", cwe="CWE-89", claim="x"), lang="node")
    assert suffix == sp.LANG_OVERLAYS["node"] and "req.query" in suffix
    assert sp.route(Hypothesis(kind="sink", cwe="CWE-89", claim="x"), lang="")[1] == ""


def test_max_calls_env_override(monkeypatch):
    secrets = next(s for s in sp.REGISTRY if s.name == "secrets")
    assert sp.max_calls(secrets) == 10
    monkeypatch.setenv("SPECIALIST_SECRETS_MAX_CALLS", "3")
    assert sp.max_calls(secrets) == 3


def test_build_makes_one_agent_per_specialist(tmp_path):
    (tmp_path / "main.go").write_text("package main\n")
    agents = sp.build("gemini-flash-lite-latest", FakeRun([SQL, IDOR]), tmp_path, None)
    assert set(agents) == {s.name for s in sp.REGISTRY}
    for s in sp.REGISTRY:
        a = agents[s.name]
        assert a.name == s.name and a.instruction.startswith(OPERATING_PRINCIPLES) and a.include_contents == "none"
        assert {t.__name__ for t in a.tools} == s.tool_names


@pytest.mark.parametrize("name,must,must_not", [
    ("authz", {"consult_domain", "report_finding"}, set()),
    ("dependency", {"consult_knowledge", "report_finding"}, {"shell"}),
    ("secrets", {"report_finding"}, {"shell"}),
    ("config", {"report_finding", "consult_owasp", "lsp_references"}, {"shell", "consult_domain"}),
    ("taint", {"report_finding", "shell", "lsp_definition"}, {"disprove_finding"}),
    ("taint_critic", {"disprove_finding", "check_dominance"}, {"report_finding"}),
    ("authz_critic", {"disprove_finding", "consult_domain"}, set()),
    ("dependency_critic", {"disprove_finding", "consult_knowledge", "lsp_path_to_entry"}, {"shell"}),
])
def test_tool_subsets(name, must, must_not):
    s = next(x for x in sp.REGISTRY if x.name == name)
    assert must <= s.tool_names and not (must_not & s.tool_names)


def test_architect_overlay_by_stack():
    assert "net/http" in sp.architect_overlay({"go"}) and sp.architect_overlay(set()) == ""
    assert sp.architect_overlay({"python", "javascript"}).count("##") == 2


def test_top10_coverage_maps_every_category_to_existing_specialists():
    names = {s.name for s in sp.REGISTRY} | {"domain", "threat_modeler"}
    assert set(sp.TOP10_COVERAGE) == {f"A{i:02d}" for i in range(1, 11)}
    for cat, who in sp.TOP10_COVERAGE.items():
        for part in who.replace("(502)", "").split("+"):
            assert part in names, (cat, part)
    config = next(x for x in sp.REGISTRY if x.name == "config")
    assert config.max_calls == 12 and {"CWE-614", "CWE-532", "CWE-1357"} <= config.cwes
    secrets = next(x for x in sp.REGISTRY if x.name == "secrets")
    assert secrets.cwes == frozenset({"CWE-798", "CWE-312", "CWE-321"})


def test_route_translates_lang_ext_names_to_overlays():
    from scanner.app import specialists as sp
    from scanner.core import Hypothesis
    h = Hypothesis(kind="sink", cwe="CWE-89", claim="x", reads=["a.ts"])
    _, ts = sp.route(h, "typescript")
    _, js = sp.route(h, "javascript")
    _, node = sp.route(h, "node")
    assert ts == js == node and node and "Node" in node


def test_knowledge_budget_is_per_invocation():
    from google.adk.models.llm_request import LlmRequest

    from scanner.app.callbacks import budget_callback

    class Ctx:
        def __init__(self, inv): self.invocation_id, self.branch, self.state = inv, None, {}

    cb = budget_callback(2, per_invocation=True)
    a, b = Ctx("inv-a"), Ctx("inv-b")
    assert cb(a, LlmRequest()) is None and cb(a, LlmRequest()) is None and cb(a, LlmRequest()) is not None  # a exhausted
    assert cb(b, LlmRequest()) is None  # b starts fresh
