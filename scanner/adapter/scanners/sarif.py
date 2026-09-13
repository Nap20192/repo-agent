"""SARIF → Anchors (gosec, semgrep): rule ids, CWE from result/rule properties or the CWE relationship, file:line."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from scanner.adapter.fs import rel
from scanner.core import Anchor, new_anchor_id, norm_severity

log = logging.getLogger("scanner.scanners.sarif")

_CWE_RE = re.compile(r"^CWE[-_ :]?(\d{1,4})\b", re.IGNORECASE)


def _cwe_of(v) -> str:
    if isinstance(v, str):
        m = _CWE_RE.match(v.strip())
        if m:
            return f"CWE-{m.group(1)}"
        if v.strip().isdigit() and int(v) > 0:
            return f"CWE-{int(v)}"
    elif isinstance(v, (int, float)) and v > 0 and v == int(v):
        return f"CWE-{int(v)}"
    elif isinstance(v, dict):
        return _cwe_of(v.get("id"))
    elif isinstance(v, list):
        for e in v:
            if c := _cwe_of(e):
                return c
    return ""


def _cwe_props(props: dict | None) -> str:
    props = props or {}
    for k in ("cwe", "cwe_ids", "tags"):
        if c := _cwe_of(props.get(k)):
            return c
    return ""


def _rule_cwe(rule: dict) -> str:
    for r in rule.get("relationships", []):
        t = r.get("target", {})
        if t.get("toolComponent", {}).get("name", "").upper() == "CWE" and t.get("id"):
            return f"CWE-{t['id']}"
    return ""


def anchors_from_sarif(data: str, tool: str, target: Path) -> list[Anchor]:
    out = []
    for run in json.loads(data).get("runs", []):
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        by_id = {r.get("id"): r for r in rules}
        for res in run.get("results", []):
            rule = by_id.get(res.get("ruleId"))
            if rule is None and isinstance(res.get("ruleIndex"), int) and res["ruleIndex"] < len(rules):
                rule = rules[res["ruleIndex"]]
            rule = rule or {}
            rule_id = res.get("ruleId") or rule.get("id", "")
            cwe = _cwe_props(res.get("properties")) or _cwe_props(rule.get("properties")) or _rule_cwe(rule)
            for loc in res.get("locations", []):
                phys = loc.get("physicalLocation", {})
                file = phys.get("artifactLocation", {}).get("uri", "")
                region = phys.get("region", {})
                line = region.get("startLine", 0)
                if not file or not line:
                    log.debug("sarif %s: result %s without file/line dropped", tool, rule_id)
                    continue
                file = rel(target, file)
                out.append(Anchor(
                    id=new_anchor_id(tool, rule_id, file, line), tool=tool, rule_id=rule_id, cwe=cwe,
                    severity=norm_severity(res.get("level", "")), file=file, line=line,
                    message=(res.get("message", {}).get("text") or "").strip(),
                    snippet=(region.get("snippet", {}).get("text") or "").strip(),
                ))
    return out
