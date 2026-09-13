"""Static contracts between instructions, tools, skills and the graph: what a prompt names must exist."""

import inspect
import re
import typing
from pathlib import Path

from google.adk.workflow import FunctionNode

from scanner import core
from scanner.adapter.skills import SKILLS, skill_for
from scanner.adapter.tools import TOOLS, ToolContext, make
from scanner.app.agents import build
from scanner.app.agents import registry as sp
from scanner.app.agents import shared as ins
from scanner.app.agents.registry import AGENTS
from scanner.app.agents.shared import SPECIALIST_SECTIONS
from scanner.core import ArchitectureModel, Dossier, Threat, ThreatModel
from scanner.core.settings import Settings
from tests.fakes import FakeRun, _run, _workflow

MODEL = "gemini-flash-lite-latest"  # constructing an LlmAgent never touches the network
TOOL_RX = re.compile(r"\b(load_skill|list_skills|report_finding|disprove_finding|consult_\w+|lsp_\w+|read_file|grep|shell|"
                     r"list_anchors|list_findings|note_add|note_list|list_entry_points)\b")


def _agents(tmp_path):
    from google.adk.tools.agent_tool import AgentTool

    ctx = ToolContext(tmp_path, FakeRun())
    return {name: build(spec, MODEL, ctx, extra_tools=[AgentTool(build(AGENTS[c], MODEL, ctx)) for c in spec.consults])
            for name, spec in AGENTS.items()}


def test_every_agent_folder_follows_the_template():
    """One folder per agent with the same four files; the SPEC's roster names exist in the tool registry; its budget is a
    Settings field or a literal; its node kind is one of the graph's wrappers."""
    root = Path(__file__).resolve().parent.parent / "scanner" / "app" / "agents"
    for name, spec in AGENTS.items():
        folder = root / spec.app
        assert {f.name for f in folder.iterdir() if f.suffix == ".py"} == {"__init__.py", "agent.py", "instruction.py", "tools.py"}, name
        assert set(spec.tools) <= set(TOOLS), (name, set(spec.tools) - set(TOOLS))
        assert isinstance(spec.budget, int) or hasattr(Settings(), spec.budget), name
        assert spec.node in ("", "stage", "worker", "tool"), name
        assert spec.instruction.startswith(ins.OPERATING_PRINCIPLES) or name in sp.CONSULTANTS  # consultants answer one question, never report


# Pre-existing gaps the template test surfaced (card 47 follow-up): the instruction names a tool the roster lacks.
KNOWN_GAPS: dict[str, set[str]] = {}  # instruction ↔ roster gaps allowlisted on purpose (none today)


def test_every_tool_named_in_an_instruction_exists_on_that_agent(tmp_path):
    agents = _agents(tmp_path)
    for name, agent in agents.items():
        have = {getattr(t, "__name__", getattr(t, "name", "")) for t in agent.tools} | KNOWN_GAPS.get(name, set())
        own = agent.instruction.removeprefix(ins.OPERATING_PRINCIPLES)  # the shared preamble is checked below
        mentioned = set(TOOL_RX.findall(own))
        assert mentioned <= have, f"{name}: instruction names tools the agent lacks: {mentioned - have}"
    everyone = {getattr(t, "__name__", getattr(t, "name", "")) for a in agents.values() for t in a.tools}
    assert set(TOOL_RX.findall(ins.OPERATING_PRINCIPLES)) <= everyone


def test_every_skill_named_in_instructions_exists():
    for text in (AGENTS["verify"].instruction, AGENTS["critic"].instruction):
        para = next(p for p in text.split("\n\n") if "load_skill" in p)
        hyphenated = set(re.findall(r"\b[a-z]+(?:-[a-z]+)+\b", para))
        assert hyphenated <= set(SKILLS), f"unknown skills named: {hyphenated - set(SKILLS)}"
    assert {"xss", "ssrf", "ssti", "xxe", "csrf", "idor", "rce", "counterevidence", "verifier-proof"} <= set(SKILLS)


def test_json_shapes_in_instructions_match_the_models():
    def keys(text, marker):
        block = text[text.index(marker):]
        return set(re.findall(r'"([a-z_]+)"', block.split("}", 1)[0]))

    assert keys(AGENTS["verify"].instruction, "Answer with the Dossier") <= set(Dossier.model_fields)
    text = AGENTS["model"].instruction
    arch = text[text.index('"architecture_model":'):text.index('"threat_model":')]
    assert set(re.findall(r'"([a-z_]+)"', arch)) - {"architecture_model"} <= set(ArchitectureModel.model_fields)
    assert set(re.findall(r'"([a-z_]+)"', text[text.index('"threat_model":'):])) - {"threat_model"} <= set(ThreatModel.model_fields)
    assert keys(text, "threats[]:") <= set(Threat.model_fields)


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
    tools = {t.__name__: t for t in make(TOOLS, ToolContext(tmp_path, FakeRun()))}
    allowed = {str, int, float, bool, dict, list, list[str]}
    for name, t in tools.items():
        assert (t.__doc__ or "").strip(), f"{name}: empty docstring (it is the tool description)"
        for p in inspect.signature(t).parameters.values():
            ann = typing.get_type_hints(t).get(p.name, p.annotation)
            assert ann in allowed, f"{name}.{p.name}: {ann!r} is not an ADK-schema primitive"


def test_every_class_section_names_only_tools_the_agents_have(tmp_path):
    """The class sections (once the specialists' prompts) ride on verify / critic activations: whatever tool they name
    must exist on that agent; a section must not tell the Investigator to disprove or the Critic to report."""
    agents = _agents(tmp_path)
    for name, section in SPECIALIST_SECTIONS.items():
        agent = agents["critic"] if name.endswith("_critic") else agents["verify"]
        have = {getattr(t, "__name__", getattr(t, "name", "")) for t in agent.tools}
        mentioned = set(TOOL_RX.findall(section)) | set(re.findall(r"\b(knowledge|domain)(?=\()", section))
        assert mentioned <= have, f"{name}: section names tools the agent lacks: {mentioned - have}"


def test_specialist_sections_are_hunting_checklists():
    """Card 44/3: the taint/authz/config sections say what to grep for, what is proof and what is not."""
    S = SPECIALIST_SECTIONS
    for name, anchors in {
        "taint": ["$where", "innerHTML", "slot", "after", "Not a finding", "SSRF", "ReDoS"],
        "authz": ["ownership", "before the side effect", "isAdmin", "CSRF", "fixation", "Not a finding"],
        "config": ["SameSite", "trust proxy", "helmet", "Not a finding"],
    }.items():
        for a in anchors:
            assert a in S[name], (name, a)


def test_model_stage_may_read_code():
    T = AGENTS["model"].instruction
    assert "read_file" in T and "grep" in T and "no code tools" not in T
