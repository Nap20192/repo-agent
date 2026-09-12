"""Vocabulary Literals reject typos at parse time; LLM-facing fields deliberately stay str (gate messages)."""

import pytest
from pydantic import ValidationError

from scanner import core
from scanner.core import Anchor, Candidate, Finding, ThreatModel


def test_program_set_fields_are_literals():
    with pytest.raises(ValidationError):
        Anchor(id="a", tool="gosek", file="f", line=1)
    with pytest.raises(ValidationError):
        Anchor(id="a", tool="gosec", severity="HIGH", file="f", line=1)
    with pytest.raises(ValidationError):
        Candidate(kind="route")
    assert Anchor(id="a", tool="entrypoint", severity="low", file="f", line=1).severity == "low"


def test_llm_facing_fields_stay_strings_for_gate_messages():
    """report_finding answers a bad status with a reason; a ValidationError would crash the tool instead."""
    f = Finding(title="t", status="maybe", severity="HUGE")
    assert core.validate_finding(f).startswith("finding: status must be")


def test_intent_is_normalised_then_validated():
    assert ThreatModel(intent="SAMPLE_OR_TEST_ONLY").intent == "sample"
    assert ThreatModel(intent="PRODUCTION").intent == "production"


def test_cwe_taxonomy_covers_gate_sets_and_consult_rule():
    assert set(core.CWE_CLASSES) >= (core.AUTHZ_CWES | core.TAINT_CWES)
    assert core.CWE_CLASSES["CWE-639"] == "authz" and core.CWE_CLASSES["CWE-798"] == "secret"
    assert core.consult_required("CWE-639") == (False, True)
    assert core.consult_required("CWE-352") == (False, False)  # routes to authz, gate needs no domain: ref (today's rule)
    assert core.consult_required("", tool="osv") == (True, False) and core.consult_required("CWE-1", rule_id="GHSA-x") == (True, False)


def test_asvs_id_round_trips():
    assert Finding.model_validate({"asvs_id": "V1.2.4"}).asvs_id == "V1.2.4"
