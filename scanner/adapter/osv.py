"""osv.dev, the one vulnerability database the scan consults: one advisory by id, or the advisory ids of package
versions. No cache, no other feeds — the osv-scanner pre-pass already names the advisories; this answers the
Investigator's "what is it, what fixes it" (tool osv_query)."""

from __future__ import annotations

import json
import logging
import urllib.parse
import urllib.request

log = logging.getLogger("scanner.osv")

UA = {"User-Agent": "repo-agent2-scanner (+https://github.com/vnkjd)"}
RESPONSE_CAP = 4 * 1024 * 1024  # advisories are small; anything bigger is not an answer


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """api.osv.dev is the only host this process talks to: a redirect is an error, not a hop."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def fetch(url: str, data: dict | None = None, timeout: int = 10):
    """The one network seam (tests monkeypatch it). JSON in, JSON out; raises on HTTP/URL errors."""
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers={**UA, **({"Content-Type": "application/json"} if body else {})})
    with _OPENER.open(req, timeout=timeout) as r:
        raw = r.read(RESPONSE_CAP + 1)
    if len(raw) > RESPONSE_CAP:
        raise ValueError(f"response larger than {RESPONSE_CAP} bytes: {url}")
    return json.loads(raw)


def normalize(v: dict) -> dict:
    """An OSV advisory → id, aliases, summary, details, fixed versions, CVSS vector, CWEs."""
    vector = next((s.get("score", "") for s in v.get("severity", []) if str(s.get("type", "")).startswith("CVSS")), "")
    fixed = [ev["fixed"] for a in v.get("affected", []) for r in a.get("ranges", []) for ev in r.get("events", []) if ev.get("fixed")]
    return {"id": v.get("id", ""), "aliases": list(v.get("aliases", [])), "summary": (v.get("summary") or "")[:300],
            "details": (v.get("details") or "")[:2000], "fixed": fixed, "vector": vector,
            "cwes": list((v.get("database_specific") or {}).get("cwe_ids", []))}


def vuln(vid: str) -> dict:
    """One advisory, normalized; {} when osv.dev does not know it or is unreachable."""
    try:
        return normalize(fetch(f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(vid, safe='')}"))
    except Exception as e:  # noqa: BLE001 — a tool never raises into the model; the caller sees an empty answer
        log.debug("osv %r: %s", vid, e)
        return {}


def batch(pkgs: list[tuple[str, str, str]]) -> dict[str, list[str]]:
    """{'name@version': [advisory ids]} for (ecosystem, name, version) triples — one POST."""
    if not pkgs:
        return {}
    try:
        data = fetch("https://api.osv.dev/v1/querybatch",
                     {"queries": [{"package": {"name": n, "ecosystem": e}, "version": v} for e, n, v in pkgs]})
    except Exception as e:  # noqa: BLE001
        log.debug("osv batch: %s", e)
        return {}
    return {f"{name}@{ver}": [v["id"] for v in res.get("vulns", []) if v.get("id")]
            for (eco, name, ver), res in zip(pkgs, data.get("results", []), strict=False)}
