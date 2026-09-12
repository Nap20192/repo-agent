"""Knowledge consultant: vulnerability databases queried in parallel rounds, cached in SQLite.

Sources: OSV (batch + per id), GitHub Advisory DB (or a local clone via GHSA_DIR, offline first), NVD 2.0,
FIRST EPSS, CISA KEV, deps.dev. `enrich()` turns every osv anchor's advisory ids into aliases, CVSS, EPSS,
KEV, fixed versions and the vulnerable function names an advisory mentions; `reachable_symbols()` is the
third round: those names against the code Index (find_symbol / path_to_entry).
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from scanner.core import Anchor
from scanner.core.settings import Settings

log = logging.getLogger("scanner.knowledge")

TTL, TTL_KEV = 7 * 86400, 86400
UA = {"User-Agent": "repo-agent2-scanner (+https://github.com/vnkjd)"}
_ECOSYSTEM = {"go.mod": "Go", "go.sum": "Go", "package-lock.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm",
              "requirements.txt": "PyPI", "poetry.lock": "PyPI", "Pipfile.lock": "PyPI", "composer.lock": "Packagist",
              "Cargo.lock": "crates.io", "Gemfile.lock": "RubyGems", "pom.xml": "Maven", "gradle.lockfile": "Maven"}
_DEPS_SYSTEM = {"Go": "go", "npm": "npm", "PyPI": "pypi", "crates.io": "cargo", "Maven": "maven", "RubyGems": "rubygems"}
_NOT_A_SYMBOL = {"js", "ts", "go", "py", "php", "rb", "rs", "java", "c", "h", "json", "yaml", "yml", "md", "txt", "html"}


RESPONSE_CAP = 4 * 1024 * 1024  # advisory feeds are small; KEV is ~2 MB; anything bigger is not an answer


def fetch(url: str, data: dict | None = None, headers: dict | None = None, timeout: int = 10):
    """The one network seam (tests monkeypatch it). JSON in, JSON out; raises on HTTP/URL errors."""
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers={**UA, **(headers or {}), **({"Content-Type": "application/json"} if body else {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read(RESPONSE_CAP + 1)
    if len(raw) > RESPONSE_CAP:
        raise ValueError(f"response larger than {RESPONSE_CAP} bytes: {url}")
    return json.loads(raw)


# --- cache -------------------------------------------------------------------------------------------------
class _Cache:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS knowledge(source TEXT, key TEXT, json TEXT, fetched_at REAL, PRIMARY KEY(source, key))")
        self._lock = threading.Lock()  # enrich() writes from 8 threads through this one connection

    def get(self, source: str, key: str, ttl: float):
        with self._lock:
            r = self.db.execute("SELECT json, fetched_at FROM knowledge WHERE source=? AND key=?", (source, key)).fetchone()
        return json.loads(r[0]) if r and time.time() - r[1] < ttl else None

    def put(self, source: str, key: str, obj) -> None:
        with self._lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO knowledge VALUES(?,?,?,?)", (source, key, json.dumps(obj), time.time()))


_caches: dict[str, _Cache] = {}


@dataclass(frozen=True)
class KnowledgeConfig:
    """What the clients need from the outside: cache file, offline advisory clone, API tokens, on/off switch."""

    cache_path: str = ".state/knowledge.db"
    ghsa_dir: str = ""
    github_token: str = ""
    nvd_api_key: str = ""
    enabled: bool = True

    @classmethod
    def from_settings(cls, s: Settings) -> KnowledgeConfig:
        return cls(cache_path=s.knowledge_cache, ghsa_dir=s.ghsa_dir, github_token=s.github_token,
                   nvd_api_key=s.nvd_api_key, enabled=s.knowledge_enrich)


def default_config() -> KnowledgeConfig:
    """Config from the process environment, resolved at call time (callers may pass an explicit one instead)."""
    return KnowledgeConfig.from_settings(Settings.from_env())


def _cache(cfg: KnowledgeConfig | None = None) -> _Cache:
    path = (cfg or default_config()).cache_path
    if path not in _caches:
        _caches[path] = _Cache(path)
    return _caches[path]


def osv_query_package(name: str, cfg: KnowledgeConfig | None = None) -> dict:
    """Advisories for a package name via OSV /v1/query, cache-first (public wrapper for the tools layer)."""
    return _cached("osv-query", name, lambda: fetch("https://api.osv.dev/v1/query", data={"package": {"name": name}}), cfg=cfg)


def _cached(source: str, key: str, loader, ttl: float = TTL, cfg: KnowledgeConfig | None = None):
    """Cache-first; a failed loader (network down, 404) yields {} and is not cached."""
    c = _cache(cfg)
    v = c.get(source, key, ttl)
    if v is not None:
        return v
    try:
        v = loader()
    except Exception as e:  # noqa: BLE001 — a database being down is not a scan failure
        log.debug("knowledge %s %s: %s", source, key, e)
        return {}
    c.put(source, key, v)
    return v


# --- clients -----------------------------------------------------------------------------------------------
def osv_batch(pkgs: list[tuple[str, str, str]], cfg: KnowledgeConfig | None = None) -> dict[str, list[str]]:
    """{'name@version': [advisory ids]} for (ecosystem, name, version) triples — one POST for the uncached ones."""
    out, todo = {}, []
    cache = _cache(cfg)
    for eco, name, ver in pkgs:
        key = f"{name}@{ver}"
        hit = cache.get("osv_batch", f"{eco}:{key}", TTL)
        if hit is not None:
            out[key] = hit
        else:
            todo.append((eco, name, ver))
    if todo:
        try:
            data = fetch("https://api.osv.dev/v1/querybatch",
                         {"queries": [{"package": {"name": n, "ecosystem": e}, "version": v} for e, n, v in todo]})
            for (eco, name, ver), res in zip(todo, data.get("results", []), strict=False):
                ids = [v["id"] for v in res.get("vulns", []) if v.get("id")]
                cache.put("osv_batch", f"{eco}:{name}@{ver}", ids)
                out[f"{name}@{ver}"] = ids
        except Exception as e:  # noqa: BLE001
            log.debug("osv batch: %s", e)
    return out


@lru_cache(maxsize=1)
def _ghsa_dir_index(root: str) -> dict[str, str]:
    """GHSA id → json path inside a github/advisory-database clone (walked once per process)."""
    idx = {}
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            if f.startswith("GHSA-") and f.endswith(".json"):
                idx[f[:-5]] = os.path.join(dirpath, f)
    return idx


def _osv_normalize(v: dict) -> dict:
    vector = next((s.get("score", "") for s in v.get("severity", []) if str(s.get("type", "")).startswith("CVSS")), "")
    fixed = [ev["fixed"] for a in v.get("affected", []) for r in a.get("ranges", []) for ev in r.get("events", []) if ev.get("fixed")]
    return {"id": v.get("id", ""), "aliases": list(v.get("aliases", [])), "summary": (v.get("summary") or "")[:300],
            "details": (v.get("details") or "")[:2000], "fixed": fixed, "vector": vector,
            "cwes": list((v.get("database_specific") or {}).get("cwe_ids", []))}


def osv_vuln(vid: str, cfg: KnowledgeConfig | None = None) -> dict:
    """One advisory, normalized: aliases, summary, details, fixed versions, CVSS vector, CWEs. The local
    advisory-database clone (`cfg.ghsa_dir`) is consulted first."""
    cfg = cfg or default_config()
    ghsa_dir = cfg.ghsa_dir
    if ghsa_dir and vid.startswith("GHSA-"):
        p = _ghsa_dir_index(ghsa_dir).get(vid)
        if p:
            try:
                return _osv_normalize(json.loads(Path(p).read_text()))
            except (OSError, ValueError) as e:
                log.debug("GHSA_DIR %s: %s", vid, e)
    return _cached("osv", vid, lambda: _osv_normalize(fetch(f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(vid, safe='')}")), cfg=cfg)


def _ghsa_headers(cfg: KnowledgeConfig) -> dict:
    tok = cfg.github_token
    return {"Accept": "application/vnd.github+json", **({"Authorization": f"Bearer {tok}"} if tok else {})}


def _ghsa_normalize(g: dict) -> dict:
    vulns = g.get("vulnerabilities", [])
    return {"id": g.get("ghsa_id", ""), "cve": g.get("cve_id") or "", "severity": g.get("severity", ""),
            "cvss": (g.get("cvss") or {}).get("score"), "vector": (g.get("cvss") or {}).get("vector_string", ""),
            "cwes": [c.get("cwe_id") for c in g.get("cwes", []) if c.get("cwe_id")],
            "functions": [f for v in vulns for f in v.get("vulnerable_functions", []) or []],
            "fixed": [v["patched_versions"] for v in vulns if v.get("patched_versions")]}


def ghsa(id_or_pkg: str, cfg: KnowledgeConfig | None = None) -> dict:
    """GitHub Advisory DB: a GHSA id → normalized advisory (cvss, cwes, vulnerable functions, patched versions);
    'name@version' → {'ids': [...]} of advisories affecting it."""
    cfg = cfg or default_config()
    base = "https://api.github.com/advisories"
    if id_or_pkg.startswith("GHSA-"):
        def load():
            lst = fetch(f"{base}?ghsa_id={urllib.parse.quote(id_or_pkg, safe='')}", headers=_ghsa_headers(cfg))
            return _ghsa_normalize(lst[0]) if lst else {}
        return _cached("ghsa", id_or_pkg, load, cfg=cfg)
    return _cached("ghsa_affects", id_or_pkg, lambda: {"ids": [g.get("ghsa_id") for g in fetch(f"{base}?affects={urllib.parse.quote(id_or_pkg, safe='')}", headers=_ghsa_headers(cfg))]}, cfg=cfg)


def nvd_cve(cve: str, cfg: KnowledgeConfig | None = None) -> dict:
    """NVD 2.0: CVSS v3.1 score + vector and CWE ids for one CVE (`cfg.nvd_api_key` raises the rate limit)."""
    cfg = cfg or default_config()

    def load():
        hdr = {"apiKey": cfg.nvd_api_key} if cfg.nvd_api_key else {}
        data = fetch(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={urllib.parse.quote(cve, safe='')}", headers=hdr)
        items = data.get("vulnerabilities", [])
        if not items:
            return {}
        c = items[0].get("cve", {})
        m = ((c.get("metrics") or {}).get("cvssMetricV31") or [{}])[0].get("cvssData", {})
        cwes = [d.get("value") for w in c.get("weaknesses", []) for d in w.get("description", []) if str(d.get("value", "")).startswith("CWE-")]
        return {"id": c.get("id", cve), "cvss": m.get("baseScore"), "vector": m.get("vectorString", ""), "cwes": cwes}
    return _cached("nvd", cve, load, cfg=cfg)


def epss(cves: list[str], cfg: KnowledgeConfig | None = None) -> dict[str, float]:
    """FIRST EPSS exploit probability per CVE (0..1), fetched in one call for the uncached ones."""
    out, todo = {}, []
    cache = _cache(cfg)
    for c in cves:
        hit = cache.get("epss", c, TTL)
        if hit is not None:
            out[c] = hit
        else:
            todo.append(c)
    for i in range(0, len(todo), 100):
        chunk = todo[i:i + 100]
        try:
            data = fetch(f"https://api.first.org/data/v1/epss?cve={','.join(chunk)}")
            for row in data.get("data", []):
                out[row["cve"]] = float(row.get("epss", 0))
                cache.put("epss", row["cve"], out[row["cve"]])
        except Exception as e:  # noqa: BLE001
            log.debug("epss: %s", e)
    return out


def kev(cfg: KnowledgeConfig | None = None) -> set[str]:
    """CISA Known Exploited Vulnerabilities: the set of CVE ids (cached one day)."""
    data = _cached("kev", "catalog", lambda: {"ids": [v.get("cveID") for v in fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json").get("vulnerabilities", [])]}, TTL_KEV, cfg=cfg)
    return set(data.get("ids", []))


def deps_dev(system: str, pkg: str, ver: str, cfg: KnowledgeConfig | None = None) -> dict:
    """deps.dev cross-check for one package version: advisory ids and licenses."""
    url = (f"https://api.deps.dev/v3/systems/{urllib.parse.quote(system, safe='')}/packages/{urllib.parse.quote(pkg, safe='')}"
           f"/versions/{urllib.parse.quote(ver, safe='')}")
    def load():
        d = fetch(url)
        return {"advisories": [a.get("id") for a in d.get("advisoryKeys", [])], "licenses": d.get("licenses", [])}
    return _cached("deps_dev", f"{system}:{pkg}@{ver}", load, cfg=cfg)


# --- enrichment rounds -------------------------------------------------------------------------------------
def _functions_from_text(text: str) -> list[str]:
    """Function names an advisory text points at: 'function `x`', 'in Pkg.fn', '`x()`'. Heuristic, ponytail."""
    found = re.findall(r"function `?(\w+)`?", text) + re.findall(r"`(\w+(?:\.\w+)?)\(\)?`", text)
    found += [m for m in re.findall(r"\bin `?(\w+\.\w+)`?", text) if m.rsplit(".", 1)[-1] not in _NOT_A_SYMBOL]
    return list(dict.fromkeys(found))


def _enrich_one(a: Anchor, cfg: KnowledgeConfig) -> Anchor:
    name, ver = (a.snippet.split(" ", 1) + [""])[:2]
    eco = _ECOSYSTEM.get(Path(a.file).name, "")
    ids = list(dict.fromkeys(a.rule_ids or ([a.rule_id] if a.rule_id else []))) or osv_batch([(eco, name, ver)], cfg).get(f"{name}@{ver}", [])
    aliases, fixed, functions, cwes, vectors, scores = [], [], [], [], [], []
    for vid in ids[:10]:  # ponytail: ten advisories per package is plenty for a verdict
        v = osv_vuln(vid, cfg)
        aliases += [x for x in v.get("aliases", []) if x not in aliases]
        fixed += [f for f in v.get("fixed", []) if f not in fixed]
        cwes += [c for c in v.get("cwes", []) if c not in cwes]
        functions += [f for f in _functions_from_text(v.get("summary", "") + " " + v.get("details", "")) if f not in functions]
        if v.get("vector"):
            vectors.append(v["vector"])
        if vid.startswith("GHSA-"):
            g = ghsa(vid, cfg)
            functions = list(dict.fromkeys(g.get("functions", []) + functions))
            fixed += [f for f in g.get("fixed", []) if f not in fixed]
            if g.get("cvss") is not None:
                scores.append(float(g["cvss"]))
            if g.get("cve") and g["cve"] not in aliases:
                aliases.append(g["cve"])
    cves = [x for x in ids + aliases if x.startswith("CVE-")]
    for cve in cves[:5]:
        n = nvd_cve(cve, cfg)
        if n.get("cvss") is not None:
            scores.append(float(n["cvss"]))
        cwes += [c for c in n.get("cwes", []) if c not in cwes]
    ep = epss(cves, cfg)
    e = {"package": name, "version": ver, "ecosystem": eco, "ids": ids, "aliases": aliases,
         "cvss": max(scores) if scores else None, "vector": vectors[0] if vectors else "",
         "epss": max(ep.values()) if ep else None, "kev": any(c in kev(cfg) for c in cves),
         "fixed": fixed, "functions": functions, "cwes": cwes}
    _cache(cfg).put("anchor", a.id, e)
    tag = " ".join(x for x in (f"CVSS {e['cvss']}" if e["cvss"] is not None else "",
                               f"EPSS {e['epss']:.2f}" if e["epss"] is not None else "", "KEV" if e["kev"] else "") if x)
    msg = a.message
    if tag and f"[{tag}]" not in msg:
        msg += f" [{tag}]"
    if fixed and "fixed:" not in msg:
        msg += f" fixed: {', '.join(fixed[:3])}"
    return a.model_copy(update={"message": msg, "rule_ids": list(dict.fromkeys(list(a.rule_ids) + ids + aliases))})


def enrich(anchors: list[Anchor], cfg: KnowledgeConfig | None = None) -> list[Anchor]:
    """Round 1 ids per package (osv-scanner already gives them), round 2 per advisory across sources — anchors in
    parallel (8 threads); non-osv anchors pass through untouched. Enrichment is kept under ('anchor', id)."""
    cfg = cfg or default_config()
    osv = [a for a in anchors if a.tool == "osv"]
    if not osv:
        return anchors
    with ThreadPoolExecutor(max_workers=8) as ex:
        done = dict(zip([a.id for a in osv], ex.map(lambda a: _enrich_one(a, cfg), osv), strict=True))
    return [done.get(a.id, a) if a.tool == "osv" else a for a in anchors]


def enrich_if_enabled(anchors: list[Anchor], cfg: KnowledgeConfig | None = None) -> list[Anchor]:
    """`scan()` hook: a no-op when `cfg.enabled` is False (KNOWLEDGE_ENRICH=0). Tests keep it off (conftest)
    or monkeypatch `fetch`; with no `cfg` the process environment decides (compat for static.scan)."""
    cfg = cfg or default_config()
    if not cfg.enabled:
        return anchors
    try:
        return enrich(anchors, cfg)
    except Exception as e:  # noqa: BLE001
        log.warning("knowledge enrichment failed: %s", e)
        return anchors


def enrichment_for(anchor_id: str, cfg: KnowledgeConfig | None = None) -> dict:
    return _cache(cfg).get("anchor", anchor_id, float("inf")) or {}


def reachable_symbols(enrichment: dict, index, entries: list[str]) -> list[tuple[str, list[str] | None]]:
    """Round 3: the advisory's vulnerable function names that exist in the target, with the caller chain to an
    entry point (None = defined but no path found)."""
    out = []
    for fn in enrichment.get("functions", []):
        if index.find_symbol(fn):
            out.append((fn, index.path_to_entry(fn, entries)))
    return out
