"""Static contracts between instructions, tools, skills and the graph: what a prompt names must exist."""

import inspect
import re
import typing

from google.adk.workflow import FunctionNode

from scanner import core
from scanner.adapter.skills import SKILLS, skill_for
from scanner.adapter.tools import architect_tools, critic_tools, subset, verifier_tools
from scanner.app import instructions as ins
from scanner.app.agents import (
    new_architect,
    new_critic,
    new_threat_modeler,
    new_verifier,
)
from scanner.core import ArchitectureModel, Dossier, Threat, ThreatModel
from tests.fakes import FakeRun, _run, _workflow

MODEL = "gemini-flash-lite-latest"  # constructing an LlmAgent never touches the network
TOOL_RX = re.compile(r"\b(load_skill|list_skills|report_finding|disprove_finding|consult_\w+|lsp_\w+|read_file|grep|shell|"
                     r"list_anchors|list_findings|note_add|note_list|list_entry_points)\b")


def _agents(tmp_path):
    run = FakeRun()

    return {
        "verifier": new_verifier(MODEL, verifier_tools(run, tmp_path)),
        "critic": new_critic(MODEL, critic_tools(run, tmp_path)),
        "architect": new_architect(MODEL, architect_tools(run, tmp_path)),
        "threat_modeler": new_threat_modeler(MODEL, subset(architect_tools(run, tmp_path), {"consult_owasp", "read_file", "grep"})),
    }


def test_every_tool_named_in_an_instruction_exists_on_that_agent(tmp_path):
    agents = _agents(tmp_path)
    for name, agent in agents.items():
        have = {t.__name__ for t in agent.tools}
        own = agent.instruction.removeprefix(ins.OPERATING_PRINCIPLES)  # the shared preamble is checked below
        mentioned = set(TOOL_RX.findall(own))
        assert mentioned <= have, f"{name}: instruction names tools the agent lacks: {mentioned - have}"
    everyone = {t.__name__ for a in agents.values() for t in a.tools}
    assert set(TOOL_RX.findall(ins.OPERATING_PRINCIPLES)) <= everyone


def test_every_skill_named_in_instructions_exists():
    for text in (ins.VERIFIER_INSTRUCTION, ins.CRITIC_INSTRUCTION):
        para = next(p for p in text.split("\n\n") if "load_skill" in p)
        hyphenated = set(re.findall(r"\b[a-z]+(?:-[a-z]+)+\b", para))
        assert hyphenated <= set(SKILLS), f"unknown skills named: {hyphenated - set(SKILLS)}"
    assert {"xss", "ssrf", "ssti", "xxe", "csrf", "idor", "rce", "counterevidence", "verifier-proof"} <= set(SKILLS)


def test_json_shapes_in_instructions_match_the_models():
    def keys(text, marker):
        block = text[text.index(marker):]
        return set(re.findall(r'"([a-z_]+)"', block.split("}", 1)[0]))

    assert keys(ins.VERIFIER_INSTRUCTION, "Answer with the Dossier") <= set(Dossier.model_fields)
    assert keys(ins.ARCHITECT_INSTRUCTION, "Answer with the ArchitectureModel") <= set(ArchitectureModel.model_fields)
    assert keys(ins.THREAT_MODELER_INSTRUCTION, "Answer with the ThreatModel") <= set(ThreatModel.model_fields)
    assert keys(ins.THREAT_MODELER_INSTRUCTION, "threats[]:") <= set(Threat.model_fields)


def test_skill_for_covers_every_gated_cwe_class():
    for cwe in core.AUTHZ_CWES | core.TAINT_CWES:
        assert skill_for(cwe, "sink") in SKILLS, cwe
    for kind in ("dependency", "authz", "secret"):
        assert skill_for("", kind) in SKILLS


def test_verifier_payload_carries_the_skill_hint():
    seen = []

    async def spy(ctx, node_input: dict):
        seen.append((node_input["cwe"], node_input.get("skill")))

    run = FakeRun()
    _run(_workflow(run, verifier=FunctionNode(func=spy, name="verify", rerun_on_resume=True), max_parallel=1))
    assert seen and all(skill == skill_for(cwe, "sink") and skill in SKILLS for cwe, skill in seen)


def test_tools_have_docstrings_and_primitive_params(tmp_path):
    run = FakeRun()
    tools = {t.__name__: t for t in verifier_tools(run, tmp_path) + critic_tools(run, tmp_path) + architect_tools(run, tmp_path)}
    allowed = {str, int, float, bool, dict, list, list[str]}
    for name, t in tools.items():
        assert (t.__doc__ or "").strip(), f"{name}: empty docstring (it is the tool description)"
        for p in inspect.signature(t).parameters.values():
            ann = typing.get_type_hints(t).get(p.name, p.annotation)
            assert ann in allowed, f"{name}.{p.name}: {ann!r} is not an ADK-schema primitive"


def test_every_specialist_instruction_names_only_its_tools_and_skills(tmp_path):
    """Per-specialist contract: tools named in the instruction ⊆ the specialist's tools; skills exist;
    the Dossier/answer JSON keys match the models; every instruction starts with the shared preamble."""
    from scanner.app import specialists as sp

    (tmp_path / "main.go").write_text("package main\n")
    agents = sp.build(MODEL, FakeRun(), tmp_path, None)
    for spec in sp.REGISTRY:
        agent = agents[spec.name]
        have = {t.__name__ for t in agent.tools}
        own = agent.instruction.removeprefix(ins.OPERATING_PRINCIPLES)
        mentioned = set(TOOL_RX.findall(own)) | set(re.findall(r"\bcheck_dominance\b", own))
        assert mentioned <= have, f"{spec.name}: instruction names tools it lacks: {mentioned - have}"
        assert set(spec.skills) <= set(SKILLS), spec.name
        assert agent.instruction.startswith(ins.OPERATING_PRINCIPLES)
        if spec.role == "investigate":
            assert "report_finding" in have and "disprove_finding" not in have
            keys = set(re.findall(r'"([a-z_]+)"', own[own.index("Answer with the Dossier"):].split("}", 1)[0]))
            assert keys <= set(Dossier.model_fields), spec.name
        else:
            assert "disprove_finding" in have and "report_finding" not in have


def test_specialist_sections_are_hunting_checklists():
    """Card 44/3: the taint/authz/config sections say what to grep for, what is proof and what is not."""
    from scanner.app.instructions import SPECIALIST_SECTIONS as S
    for name, anchors in {
        "taint": ["$where", "innerHTML", "slot", "after", "Not a finding", "SSRF", "ReDoS"],
        "authz": ["ownership", "before the side effect", "isAdmin", "CSRF", "fixation", "Not a finding"],
        "config": ["SameSite", "trust proxy", "helmet", "Not a finding"],
    }.items():
        for a in anchors:
            assert a in S[name], (name, a)


def test_threat_modeler_may_read_code():
    from scanner.app.instructions import THREAT_MODELER_INSTRUCTION as T
    assert "read_file" in T and "grep" in T and "no code tools" not in T
