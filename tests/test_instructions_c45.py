"""Card 45: review / viability / confirm / triage-batch instructions, agent factories and tool rosters."""

from pathlib import Path

from scanner.adapter.tools import ToolContext
from scanner.app.agents import build, shared
from scanner.app.agents.registry import AGENTS
from scanner.core.workflow import Confirmation, ReviewVerdict, TriageBatch, Viability
from tests.fakes import FakeRun

REVIEW_KEYS = ["hypothetical_misuse", "hygiene_only", "not_triggerable", "pedantic_linting", "flaw_stretching",
               "questionable_path", "resource_exhaustion", "intrinsic_flaw", "mitigation_hallucinated", "wrong_location",
               "by_design_contract", "source_coherence", "trust_boundary"]


def test_review_instruction_names_the_13_checklist_keys_statuses_and_the_fp_gate():
    t = AGENTS["review"].instruction
    assert shared.REVIEW_CHECKLIST == REVIEW_KEYS and len(REVIEW_KEYS) == 13
    assert all(k in t for k in REVIEW_KEYS)
    assert all(s in t for s in ("VALID", "FALSE_POSITIVE", "PROVISIONALLY_VALID", "NEEDS_RESEARCH"))
    assert all(o in t for o in ("PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE"))
    assert "disprove_finding" in t and "NEEDS_RESEARCH" in t.split("FALSE_POSITIVE", 1)[1]  # FP without a counter-quote → NEEDS_RESEARCH
    assert shared.OPERATING_PRINCIPLES in t


def test_viability_instruction_has_the_routes_and_the_fail_safe():
    t = AGENTS["viability"].instruction
    assert all(s in t for s in ("VIABLE", "CONDITIONAL_VIABLE", "NON_VIABLE", "SAMPLE_OR_TEST"))
    assert "check_dominance" in t and "disprove_finding" in t and "lsp_path_to_entry" in t
    assert "CONDITIONAL_VIABLE" in t.split("missing", 1)[1].lower().upper()  # missing file/line → CONDITIONAL_VIABLE


def test_confirm_and_triage_batch_instructions():
    c = AGENTS["confirm"].instruction
    assert "PROVISIONALLY_VALID" in c and "report_finding" in c and "statically_confirmed" in c and "not_attempted" in c
    b = AGENTS["triage_batch"].instruction
    assert "classifications" in b and "flagged" in b and "classes" in b and "why" in b
    assert "could not read" in b and "leave it out" in b  # unreadable file → not classified → fold marks it missing


def test_factories_build_agents_with_budgets_schemas_and_tools(tmp_path):
    ctx = ToolContext(tmp_path, FakeRun())
    rv, vi, co, tb = (build(AGENTS[n], "m", ctx) for n in ("review", "viability", "confirm", "triage_batch"))
    assert (rv.name, vi.name, co.name, tb.name) == ("review", "viability", "confirm", "triage_batch")
    assert rv.output_schema is ReviewVerdict and vi.output_schema is Viability and co.output_schema is Confirmation
    assert tb.output_schema is TriageBatch
    assert {t.__name__ for t in vi.tools} == {"disprove_finding", "check_dominance", "lsp_path_to_entry", "read_file", "grep"}
    names = {t.__name__ for t in co.tools}
    assert "report_finding" in names and "read_file" in names and "grep" in names and "lsp_symbols" in names and "disprove_finding" not in names
    assert {t.__name__ for t in rv.tools} == set(AGENTS["critic"].tools)  # the review roster is the critic's
    assert rv.include_contents == "none" and len(rv.before_model_callback) == 2  # budget + window, like every agent


def test_notices_mention_the_verdict_ladder():
    assert "review" in Path("THIRD_PARTY_NOTICES.md").read_text().lower()
