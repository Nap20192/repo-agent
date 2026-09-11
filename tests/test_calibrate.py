from scanner.core import CONFIRMED, REJECTED, UNCERTAIN, Finding
from scanner.core.calibrate import calibrate


def _f(**kw):
    base = {"cwe": "CWE-89", "file": "main.go", "line": 22, "title": "t", "severity": "high", "status": CONFIRMED,
            "evidence": ["x"], "confidence": 0.9}
    return Finding(**{**base, **kw})


def test_sqli_exposed_is_high_not_critical():
    r = calibrate(_f(), exposure="exposed")
    assert r["impact"] == 4 and r["likelihood"] == 3 and r["multiplier"] == 0.8
    assert r["score"] == 5.6 and r["priority"] == "MEDIUM" and r["rules_applied"] == ["static_confirmation"]
    rce = calibrate(_f(cwe="CWE-78"), exposure="exposed")
    assert rce["score"] == 6.4 and rce["priority"] == "HIGH"  # (5+3)*0.8; static cap forbids CRITICAL


def test_caps_most_restrictive_wins():
    xss = calibrate(_f(cwe="CWE-79"), exposure="exposed")
    assert xss["priority"] == "MEDIUM" and "strict_xss" in xss["rules_applied"] and "user_interaction" in xss["rules_applied"]
    dep = calibrate(_f(cwe="", file="go.mod", line=1))
    assert dep["score"] <= 2.0 and dep["priority"] == "LOW" and "third_party_reachability" in dep["rules_applied"]
    unc = calibrate(_f(status=UNCERTAIN))
    assert unc["likelihood"] == 1 and unc["priority"] == "LOW" and "unreachable_inputs" in unc["rules_applied"]
    hyg = calibrate(_f(cwe="CWE-676"), exposure="exposed")
    assert hyg["impact"] == 1 and hyg["priority"] == "LOW" and "hygiene_only" in hyg["rules_applied"]


def test_sample_intent_and_exposure_scale_down():
    prod = calibrate(_f(cwe="CWE-78"), exposure="exposed")
    sample = calibrate(_f(cwe="CWE-78"), intent="sample", exposure="exposed")
    internal = calibrate(_f(cwe="CWE-78"), exposure="privileged")
    assert sample["score"] < internal["score"] < prod["score"]
    assert "sample_or_test" in sample["rules_applied"] and "internal_nested" in internal["rules_applied"]
    assert calibrate(_f(severity="low"))["impact"] == 2
    assert calibrate(_f(status=REJECTED))["priority"] == "LOW"
