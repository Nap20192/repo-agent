"""The class overlay that replaced the specialist agents (card 51): CWE beats kind, critics get their own section, the
language overlay rides along; the OWASP Top 10 table names only existing sections."""

from scanner.app.agents import registry as sp
from scanner.app.agents.shared import LANG_OVERLAYS, SPECIALIST_SECTIONS
from scanner.core import Finding, Hypothesis


def test_class_of_cwe_beats_kind_then_kind_then_nothing():
    assert sp.class_of(Hypothesis(kind="sink", cwe="CWE-89", claim="x")) == "taint"
    assert sp.class_of(Hypothesis(kind="sink", cwe="CWE-862", claim="x")) == "authz"  # cwe wins over kind
    assert sp.class_of(Hypothesis(kind="sink", cwe="CWE-614", claim="x")) == "config"
    assert sp.class_of(Hypothesis(kind="secret", cwe="CWE-798", claim="x")) == "secrets"
    assert sp.class_of(Hypothesis(kind="dependency", cwe="", claim="x")) == "dependency"  # kind when cwe empty
    assert sp.class_of(Hypothesis(kind="entry", cwe="", claim="x")) == "taint"  # entry points are taint work
    assert sp.class_of(Hypothesis(kind="other", cwe="CWE-9999", claim="x")) == ""  # generic prompt alone


def test_overlay_is_the_role_section_plus_the_language():
    cls, text = sp.overlay(Hypothesis(kind="sink", cwe="CWE-89", claim="x"), "go", "investigate")
    assert cls == "taint" and text.startswith(SPECIALIST_SECTIONS["taint"]) and text.endswith(LANG_OVERLAYS["go"])
    cls, text = sp.overlay(Finding(cwe="CWE-639", title="t"), "javascript", "critique")
    assert cls == "authz" and SPECIALIST_SECTIONS["authz_critic"] in text and LANG_OVERLAYS["node"] in text
    cls, text = sp.overlay(Finding(cwe="CWE-9999", title="t"), "", "critique")
    assert cls == "" and text == ""
    assert sp.overlay(Finding(cwe="CWE-798", title="t"), "", "critique")[1] == ""  # no critic section for secrets: generic critic


def test_lang_of_and_architect_overlay():
    assert sp.lang_of(["main.go"]) == "go" and sp.lang_of(["a.py"]) == "python"
    assert sp.lang_of(["app/routes/index.js"]) == "node" and sp.lang_of(["x.ts"]) == "node"
    assert sp.lang_of(["index.php"]) == "" and sp.lang_of([]) == ""
    assert "net/http" in sp.architect_overlay({"go"}) and sp.architect_overlay(set()) == ""
    assert sp.architect_overlay({"python", "javascript"}).count("##") == 2


def test_top10_coverage_maps_every_category_to_existing_sections():
    names = {n for n, _, _ in sp.CLASSES} | {"model"}
    assert set(sp.TOP10_COVERAGE) == {f"A{i:02d}" for i in range(1, 11)}
    for who in sp.TOP10_COVERAGE.values():
        for part in who.replace("(502)", "").split("+"):
            assert part in names, who


def test_five_agents_two_consultants():
    assert list(sp.AGENTS) == ["model", "verify", "critic", "knowledge", "domain"] and sp.CONSULTANTS == ("knowledge", "domain")
    assert sp.AGENTS["verify"].consults == ("knowledge", "domain") and sp.AGENTS["critic"].consults == ("knowledge", "domain")
    assert sp.AGENTS["knowledge"].per_invocation and not sp.AGENTS["knowledge"].per_branch  # AgentTool: budget per call
