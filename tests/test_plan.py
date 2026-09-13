"""The pure planning helpers that survived card 51: dedupe and the deterministic calibration."""

from scanner import core
from scanner.app.graph import planning
from scanner.core import Finding


def _f(i, cwe="CWE-89", file="a.go", line=10, title="SQL injection in search", conf=0.9, source="llm", status=core.CONFIRMED):
    return Finding(id=f"f_{i}", anchor_id="a_1", cwe=cwe, file=file, line=line, title=title, status=status, evidence=["x"],
                   confidence=conf, source=source)


def test_dedupe_pairs_near_same_class_similar_titles_keeps_the_stronger():
    a, b, far, other = _f(1, conf=0.7), _f(2, line=12, conf=0.95), _f(3, line=400), _f(4, cwe="CWE-78")
    assert planning.dedupe([a, b, far, other]) == [("f_2", "f_1")]


def test_dedupe_skips_direct_and_non_confirmed():
    assert planning.dedupe([_f(1, source="direct"), _f(2, line=11, source="direct")]) == []
    assert planning.dedupe([_f(1, status=core.UNCERTAIN), _f(2, line=11)]) == []
