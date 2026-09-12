"""Knowledge consultant: DB clients (fixtures, no network), cache, osv enrichment rounds, reachability."""

import json

import pytest

from scanner.adapter import knowledge as kn
from scanner.core import Anchor

OSV_VULN = {"id": "GHSA-23hp-3jrh-7fpw", "aliases": ["CVE-2021-32803"], "summary": "node-tar DoS",
            "details": "The function `extract` in tar.js ... in Parser.write",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
            "affected": [{"package": {"ecosystem": "npm", "name": "tar"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.4.16"}]}]}],
            "database_specific": {"cwe_ids": ["CWE-22"]}}
GHSA = [{"ghsa_id": "GHSA-23hp-3jrh-7fpw", "cve_id": "CVE-2021-32803", "severity": "high",
         "cvss": {"score": 8.2, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
         "cwes": [{"cwe_id": "CWE-22"}],
         "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "tar"}, "patched_versions": "4.4.16",
                              "vulnerable_functions": ["tar.extract"]}]}]
NVD = {"vulnerabilities": [{"cve": {"id": "CVE-2021-32803", "metrics": {"cvssMetricV31": [{"cvssData": {
    "baseScore": 8.2, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}}]},
    "weaknesses": [{"description": [{"value": "CWE-22"}]}]}}]}
EPSS = {"data": [{"cve": "CVE-2021-32803", "epss": "0.91234", "percentile": "0.99"}]}
KEV = {"vulnerabilities": [{"cveID": "CVE-2021-32803"}, {"cveID": "CVE-2020-0001"}]}
OSV_BATCH = {"results": [{"vulns": [{"id": "GHSA-23hp-3jrh-7fpw"}, {"id": "GHSA-9r2w-394v-53qc"}]}]}
DEPS = {"advisoryKeys": [{"id": "GHSA-23hp-3jrh-7fpw"}], "licenses": ["ISC"]}


def route(url, data=None):
    if "querybatch" in url:
        return OSV_BATCH
    if "osv.dev/v1/vulns/" in url:
        return OSV_VULN
    if "api.github.com/advisories" in url:
        return GHSA
    if "nvd.nist.gov" in url:
        return NVD
    if "first.org" in url:
        return EPSS
    if "cisa.gov" in url:
        return KEV
    if "deps.dev" in url:
        return DEPS
    raise AssertionError(f"unexpected url {url}")


@pytest.fixture
def offline(tmp_path, monkeypatch):
    monkeypatch.setenv("KNOWLEDGE_CACHE", str(tmp_path / "k.db"))
    monkeypatch.delenv("GHSA_DIR", raising=False)
    calls = []

    def fake_fetch(url, data=None, headers=None, timeout=10):
        calls.append(url)
        return route(url, data)

    monkeypatch.setattr(kn, "fetch", fake_fetch)
    return calls


def test_clients_parse_fixtures(offline):
    assert kn.osv_batch([("npm", "tar", "4.4.8")]) == {"tar@4.4.8": ["GHSA-23hp-3jrh-7fpw", "GHSA-9r2w-394v-53qc"]}
    v = kn.osv_vuln("GHSA-23hp-3jrh-7fpw")
    assert v["aliases"] == ["CVE-2021-32803"] and v["fixed"] == ["4.4.16"] and v["cwes"] == ["CWE-22"]
    g = kn.ghsa("GHSA-23hp-3jrh-7fpw")
    assert g["cvss"] == 8.2 and g["functions"] == ["tar.extract"] and g["fixed"] == ["4.4.16"]
    n = kn.nvd_cve("CVE-2021-32803")
    assert n["cvss"] == 8.2 and n["vector"].startswith("CVSS:3.1") and n["cwes"] == ["CWE-22"]
    assert kn.epss(["CVE-2021-32803"]) == {"CVE-2021-32803": 0.91234}
    assert "CVE-2021-32803" in kn.kev() and "CVE-2020-0001" in kn.kev()
    assert kn.deps_dev("npm", "tar", "4.4.8")["advisories"] == ["GHSA-23hp-3jrh-7fpw"]


def test_cache_hit_avoids_fetch(offline):
    kn.nvd_cve("CVE-2021-32803")
    n = len(offline)
    kn.nvd_cve("CVE-2021-32803")
    assert len(offline) == n  # second call served from the sqlite cache


def test_ghsa_dir_offline_beats_network(offline, tmp_path, monkeypatch):
    d = tmp_path / "advisory-database" / "advisories" / "github-reviewed" / "2021" / "08" / "GHSA-23hp-3jrh-7fpw"
    d.mkdir(parents=True)
    (d / "GHSA-23hp-3jrh-7fpw.json").write_text(json.dumps(OSV_VULN | {"summary": "from disk"}))
    monkeypatch.setenv("GHSA_DIR", str(tmp_path / "advisory-database"))
    assert kn.osv_vuln("GHSA-23hp-3jrh-7fpw")["summary"] == "from disk" and not offline


def _osv_anchor():
    return Anchor(id="a_osv", tool="osv", rule_id="GHSA-23hp-3jrh-7fpw", rule_ids=["GHSA-23hp-3jrh-7fpw"],
                  severity="high", file="package-lock.json", line=1, snippet="tar 4.4.8",
                  message="tar@4.4.8: 1 advisories (GHSA-23hp-3jrh-7fpw) — node-tar DoS")


def test_enrich_merges_sources_into_the_anchor(offline):
    a, other = _osv_anchor(), Anchor(id="a_x", tool="gosec", cwe="CWE-89", file="m.go", line=1)
    out = kn.enrich([a, other])
    assert out[1] is other  # non-osv anchors untouched
    e = kn.enrichment_for("a_osv")
    assert e["aliases"] == ["CVE-2021-32803"] and e["cvss"] == 8.2 and e["epss"] == 0.91234 and e["kev"] is True
    assert e["fixed"] == ["4.4.16"] and "tar.extract" in e["functions"] and "extract" in e["functions"]
    assert "[CVSS 8.2 EPSS 0.91 KEV] fixed: 4.4.16" in out[0].message
    assert set(out[0].rule_ids) >= {"GHSA-23hp-3jrh-7fpw", "CVE-2021-32803"}
    assert kn.enrichment_for("nope") == {}


def test_enrich_skips_when_disabled(offline, monkeypatch):
    monkeypatch.setenv("KNOWLEDGE_ENRICH", "0")
    a = _osv_anchor()
    assert kn.enrich_if_enabled([a])[0].message == a.message and not offline


class FakeIndex:
    def find_symbol(self, fqn):
        return ("tar.js", 10) if fqn.rsplit(".", 1)[-1] == "extract" else None

    def path_to_entry(self, fqn, entries, max_depth=6):
        return ["main", "extract"] if "extract" in fqn else None


def test_reachable_symbols_via_index():
    e = {"functions": ["tar.extract", "Parser.write"]}
    assert kn.reachable_symbols(e, FakeIndex(), ["main"]) == [("tar.extract", ["main", "extract"])]
    assert kn.reachable_symbols({}, FakeIndex(), ["main"]) == []


def test_knowledge_agent_builds_and_exposes_tools(offline):
    from scanner.app.knowledge_agent import make_consult_knowledge, new_knowledge_agent

    agent = new_knowledge_agent("gemini-flash-lite-latest", max_calls=5)
    names = {t.__name__ for t in agent.tools if callable(t)}
    assert names >= {"osv_query", "ghsa", "nvd_cve", "epss", "kev", "deps_dev"} and "web_search" not in names
    tool = make_consult_knowledge("gemini-flash-lite-latest")
    assert tool.name == "knowledge" and tool.agent is not None


def test_fetch_rejects_oversized_responses(monkeypatch):
    from scanner.adapter import knowledge as kn

    class Big:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n=-1): return b"x" * n

    monkeypatch.setattr(kn.urllib.request, "urlopen", lambda req, timeout=10: Big())
    import pytest
    with pytest.raises(ValueError):
        kn.fetch("https://api.osv.dev/v1/vulns/x")


def test_cache_put_is_thread_safe(tmp_path):
    import threading

    from scanner.adapter import knowledge as kn
    c = kn._Cache(str(tmp_path / "k.db"))
    errors = []

    def w(i):
        try:
            for j in range(50):
                c.put("s", f"k{i}-{j}", {"i": i})
                c.get("s", f"k{i}-{j}", 10)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    ts = [threading.Thread(target=w, args=(i,)) for i in range(8)]
    for t in ts: t.start()
    for t in ts: t.join()
    assert not errors


def test_explicit_enabled_config_cannot_reach_the_network_under_pytest():
    """The conftest guard closes the fetch seam even when a caller bypasses KNOWLEDGE_ENRICH with its own config."""
    from scanner.adapter import knowledge as kn
    from scanner.core import Anchor
    cfg = kn.KnowledgeConfig(cache_path=":memory:", ghsa_dir="", github_token="", nvd_api_key="", enabled=True)
    a = Anchor(id="a", tool="osv", rule_id="GHSA-zzzz-zzzz-zzzz", severity="high", file="go.mod", line=1, rule_ids=["GHSA-zzzz-zzzz-zzzz"])
    out = kn.enrich([a], cfg)  # loaders swallow failures → anchor unchanged, no network
    assert out[0].message == a.message


def test_imported_by_counts_source_files(tmp_path):
    (tmp_path / "a.js").write_text("const _ = require('lodash');\n")
    (tmp_path / "b.ts").write_text("import x from 'lodash/fp'\n")
    (tmp_path / "c.py").write_text("import lodash\n")
    (tmp_path / "d.go").write_text('import "golang.org/x/text/width"\n')
    (tmp_path / "e.js").write_text("// lodash mentioned only in a comment, and lodashx is another package\n")
    assert kn.imported_by(tmp_path, "lodash") == 3
    assert kn.imported_by(tmp_path, "golang.org/x/text") == 1
    assert kn.imported_by(tmp_path, "nothing") == 0
