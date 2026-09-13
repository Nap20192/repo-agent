"""adapter.osv (the one vulnerability database) and the osv_query tool: normalized advisories, batch lookups,
a closed network → an empty answer / a tool error, never an exception into the model."""

import json

import pytest

from scanner.adapter import osv
from scanner.adapter.tools.consult.osv_query import make
from scanner.adapter.tools.context import ToolContext
from tests.fakes import FakeRun

ADVISORY = {"id": "GHSA-abcd", "aliases": ["CVE-2024-1"], "summary": "prototype pollution", "details": "d" * 3000,
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
            "database_specific": {"cwe_ids": ["CWE-1321"]}}


def test_normalize_keeps_the_fields_the_verifier_cites():
    n = osv.normalize(ADVISORY)
    assert (n["id"], n["aliases"], n["fixed"], n["cwes"]) == ("GHSA-abcd", ["CVE-2024-1"], ["4.17.21"], ["CWE-1321"])
    assert n["vector"].startswith("CVSS:3.1/") and len(n["details"]) == 2000 and n["summary"] == "prototype pollution"
    assert osv.normalize({}) == {"id": "", "aliases": [], "summary": "", "details": "", "fixed": [], "vector": "", "cwes": []}


def test_vuln_and_batch_go_through_fetch(monkeypatch):
    calls = []

    def fake_fetch(url, data=None, timeout=10):
        calls.append((url, data))
        if url.endswith("/querybatch"):
            return {"results": [{"vulns": [{"id": "GHSA-abcd"}, {"id": "GHSA-efgh"}]}, {}]}
        return ADVISORY
    monkeypatch.setattr(osv, "fetch", fake_fetch)
    assert osv.vuln("GHSA-abcd")["fixed"] == ["4.17.21"] and calls[0][0] == "https://api.osv.dev/v1/vulns/GHSA-abcd"
    assert osv.batch([("npm", "lodash", "4.13.1"), ("PyPI", "x", "1")]) == {"lodash@4.13.1": ["GHSA-abcd", "GHSA-efgh"], "x@1": []}
    assert calls[1][1]["queries"][0] == {"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.13.1"}
    assert osv.batch([]) == {} and len(calls) == 2


def test_closed_network_is_an_empty_answer_not_an_exception():
    assert osv.vuln("GHSA-none") == {} and osv.batch([("npm", "a", "1")]) == {}  # conftest closes urlopen


def test_fetch_refuses_oversized_bodies_and_redirects(monkeypatch):
    class Big:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n): return b"x" * n
    monkeypatch.setattr(osv._OPENER, "open", lambda *a, **k: Big())
    with pytest.raises(ValueError):
        osv.fetch("https://api.osv.dev/v1/vulns/GHSA-big")
    assert osv._NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://evil.example/") is None


def test_osv_query_tool_returns_gate_refs(monkeypatch, tmp_path):
    monkeypatch.setattr(osv, "fetch", lambda url, data=None, timeout=10: ADVISORY if "/vulns/" in url
                        else {"results": [{"vulns": [{"id": "GHSA-abcd"}]}]})
    q = make(ToolContext(tmp_path, FakeRun()))
    by_id = q("GHSA-abcd")
    assert by_id["ref"] == "knowledge:GHSA-abcd" and by_id["fixed"] == ["4.17.21"] and "error" not in by_id
    assert q("npm:lodash@4.13.1") == {"ids": ["GHSA-abcd"], "refs": ["knowledge:GHSA-abcd"]}
    assert json.dumps(by_id)  # plain JSON for the model


def test_osv_query_tool_errors_are_answers(monkeypatch, tmp_path):
    monkeypatch.setattr(osv, "fetch", lambda url, data=None, timeout=10: {"results": [{}]} if "batch" in url else {})
    q = make(ToolContext(tmp_path, FakeRun()))
    assert q("GHSA-nope")["status"] == "error" and q("npm:nothing@0.0.1")["status"] == "error"


def test_osv_query_tool_validates_the_query_before_anything_leaves(monkeypatch, tmp_path):
    """Model-written text is not forwarded as is: a malformed shape is a tool error, never a request or an exception."""
    sent = []
    monkeypatch.setattr(osv, "fetch", lambda url, data=None, timeout=10: sent.append(url) or {})
    q = make(ToolContext(tmp_path, FakeRun()))
    for bad in ("lodash@4.17.20:npm", "", "GHSA", "x" * 300, "SELECT * FROM users -- secret", "npm:a b@1", "../../etc"):
        assert q(bad)["status"] == "error", bad
    assert sent == []
    assert q("npm:@scope/name@1.2.3")["status"] == "error" and sent  # the scoped-package shape does go out
