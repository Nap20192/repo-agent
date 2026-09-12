"""Reconciler: two candidate streams — scanner Anchors and modeled Threats — plus Verifier
new_hypotheses, merged into one prioritized queue of Hypotheses without duplicates. Pure functions."""

from __future__ import annotations

import logging
import math
import random
import re
from collections.abc import Callable

from scanner import core
from scanner.adapter import owasp
from scanner.core import Anchor, Candidate, Finding, Hypothesis, Threat, ThreatModel, new_anchor_id
from scanner.core.ports import RunStore

log = logging.getLogger("scanner.reconcile")

_KIND_CONSULT = {"dependency": "knowledge", "authz": "domain"}


def anchor_kind(a: Anchor) -> str:
    if a.tool == "osv" or a.rule_id.upper().startswith(("CVE-", "GHSA-")):
        return "dependency"
    if a.cwe == "CWE-798":
        return "secret"
    if a.cwe in core.AUTHZ_CWES:
        return "authz"
    return "sink"


def key(h: Hypothesis) -> str:
    """Identity of a queue item: the anchor, else symbol+cwe."""
    return h.anchor_id or f"{h.symbol}|{h.cwe}"


def _owasp_ids(cwe: str) -> dict:
    g = owasp.consult(cwe) if cwe else {}
    return {"wstg_id": g.get("wstg_id", ""), "asvs_id": g.get("asvs_id", "")}


DIRECT_TOOLS = ("osv", "gitleaks")


def is_direct(a: Anchor) -> bool:
    """A scanner result that certainly happened (dependency advisory, committed secret, semgrep at error level):
    it becomes a finding directly — dedup and a richer description, no LLM verdict (card 42)."""
    return a.tool in DIRECT_TOOLS or (a.tool == "semgrep" and a.severity in ("critical", "high"))


DIRECT_MAX = 200  # per tool; osv is already capped by static.OSV_MAX — a target with thousands of hits must not stall the start


def split_direct(anchors: list[Anchor], max_per_tool: int = DIRECT_MAX) -> tuple[list[Anchor], list[Anchor]]:
    """(direct, investigate): only the second list may become hypotheses. Direct anchors are capped per tool,
    highest severity first (security review M2: every direct anchor costs a synchronous store.report)."""
    direct = [a for a in anchors if is_direct(a)]
    kept: list[Anchor] = []
    for tool in sorted({a.tool for a in direct}):
        mine = sorted((a for a in direct if a.tool == tool), key=lambda a: -core.SEVERITY_RANK.get(a.severity, 0))
        if len(mine) > max_per_tool:
            log.warning("direct: %d %s anchors, keeping the %d most severe (DIRECT_MAX)", len(mine), tool, max_per_tool)
        kept.extend(mine[:max_per_tool])
    kept_ids = {a.id for a in kept}
    return [a for a in direct if a.id in kept_ids], [a for a in anchors if not is_direct(a)]


def _cvss_severity(e: dict, default: str) -> str:
    if e.get("kev"):
        return "critical"
    s = e.get("cvss")
    if s is None:
        return default
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"


def direct_finding(a: Anchor, enrichment: dict | None = None, imported_by: int | None = None) -> Finding:
    """Confirmed finding straight from a direct anchor. `enrichment` is the knowledge record of an osv anchor
    (ids, aliases, cvss, epss, kev, fixed, cwes); `imported_by` = source files importing the package (None =
    not computed). Secrets are redacted in title and evidence."""
    e = enrichment or {}
    at = f"{a.file}:{a.line}"
    secret = a.tool == "gitleaks" or a.cwe == "CWE-798"
    red = core.redact_secrets if secret else (lambda s: s)  # advisory ids and package names are not secrets
    evidence = [f"{at}: {red(a.snippet)}" if a.snippet else at]
    title, severity, cwe = a.message or a.rule_id, a.severity, a.cwe
    if a.tool == "osv":
        ids = [i for i in dict.fromkeys([*(a.rule_ids or [a.rule_id]), *e.get("aliases", [])]) if i]
        evidence += [f"knowledge:{i}" for i in ids]
        facts = (f"CVSS {e['cvss']}" if e.get("cvss") is not None else "",
                 f"EPSS {e['epss']:.2f}" if e.get("epss") is not None else "",
                 "KEV: known exploited" if e.get("kev") else "",
                 f"fixed: {', '.join(e['fixed'][:3])}" if e.get("fixed") else "")
        evidence += [x for x in facts if x]
        if imported_by is not None:
            evidence.append(f"imported by {imported_by} files" if imported_by
                            else "not imported by any source file (transitive or unused; reachability unknown)")
        pkg = f"{e['package']}@{e['version']}" if e.get("package") else "@".join(a.snippet.split()[:2]) or a.rule_id
        title = f"Vulnerable dependency {pkg}: {', '.join(ids[:3])}"
        severity = _cvss_severity(e, a.severity)
        cwe = a.cwe or (e.get("cwes") or [""])[0]
    elif a.tool == "gitleaks":
        title = f"Hardcoded secret ({a.rule_id}) in {a.file}"
        cwe = a.cwe or "CWE-798"
    return Finding(anchor_id=a.id, cwe=cwe, file=a.file, line=a.line, title=red(title),
                   severity=severity, status=core.CONFIRMED, evidence=evidence, confidence=1.0, source="direct")


def from_anchors(anchors: list[Anchor]) -> list[Hypothesis]:
    """Every anchor is a task: kind by class, consult by kind, claim from the scanner message, OWASP ids by CWE."""
    out = []
    for a in anchors:
        kind = anchor_kind(a)
        out.append(Hypothesis(
            kind=kind, cwe=a.cwe, anchor_id=a.id, consult=_KIND_CONSULT.get(kind, ""), **_owasp_ids(a.cwe),
            claim=f"{a.message or a.rule_id} at {a.file}:{a.line} is exploitable" + (f" ({a.cwe})" if a.cwe else ""),
            reads=[a.file], priority=core.SEVERITY_RANK.get(a.severity, 0) * 20,
        ))
    return out


def from_threats(
    threats: list[Threat], anchors: list[Anchor], locate: Callable[[str], tuple[str, int] | None] | None = None,
    criticality: dict[str, str] | None = None,
) -> tuple[list[Hypothesis], list[Anchor]]:
    """Threats → hypotheses, plus the synthetic anchors minted for them.

    A threat matching a scanner anchor by (file, cwe) is grounded on it (claim from the threat, +10 priority).
    Otherwise, if `locate` finds the definition of its symbol, a synthetic anchor (tool "threatmodel",
    file:line of the definition) is minted so the single anchor-only report_finding gate still applies.
    A threat with neither stays symbol-grounded and the dispatch gate decides its fate."""
    by_line = {(a.file, a.line, a.cwe): a for a in anchors if a.cwe}
    by_loc: dict[tuple[str, str], list[Anchor]] = {}
    for anchor in anchors:
        if anchor.cwe:
            by_loc.setdefault((anchor.file, anchor.cwe), []).append(anchor)
    hyps: list[Hypothesis] = []
    minted: list[Anchor] = []
    for t in threats:
        # exact (file, line, cwe) first; (file, cwe) only when unambiguous — never guess between two sinks
        a = by_line.get((t.file, t.line, t.cwe))
        if a is None and t.line == 0 and len(by_loc.get((t.file, t.cwe), [])) == 1:
            a = by_loc[(t.file, t.cwe)][0]
        if a is None and t.symbol and locate and (loc := locate(t.symbol)):
            sev = "high" if t.priority >= 70 else "medium" if t.priority >= 40 else "low"
            a = Anchor(id=new_anchor_id("threatmodel", t.wstg_id or t.cwe, loc[0], loc[1]), tool="threatmodel",
                       rule_id=t.wstg_id or "threat", cwe=t.cwe, severity=sev, file=loc[0], line=loc[1],
                       message=t.claim, snippet="")
            minted.append(a)
        kind = anchor_kind(a) if a else ("authz" if t.cwe in core.AUTHZ_CWES else "sink")
        ids = _owasp_ids(t.cwe)
        hyps.append(Hypothesis(
            kind=kind, cwe=t.cwe, claim=t.claim or f"{t.cwe or 'threat'} in {t.symbol or t.file}: modeled threat without a claim — prove or reject it", wstg_id=t.wstg_id or ids["wstg_id"], asvs_id=ids["asvs_id"], anchor_id=a.id if a else "", symbol="" if a else t.symbol,
            consult=_KIND_CONSULT.get(kind, ""), reads=t.reads or ([a.file] if a else [t.file] if t.file else []),
            priority=t.priority + (10 if a and a.tool != "threatmodel" else 0)
            + (10 if (criticality or {}).get(t.symbol.split(".")[-1]) == "CRITICAL" else 0),
        ))
    return hyps, minted


KNOWN_WSTG = {wid for wid, _ in owasp._WSTG.values()}


def _wstg_or_map(wid: str, cwe: str, known: set[str]) -> tuple[str, bool]:
    """(id, fabricated): an absent id stays absent; a known id stays; a fabricated one → the CWE's mapped id or ""."""
    if not wid or wid in known:
        return wid, False
    return (owasp.consult(cwe).get("wstg_id", "") if cwe else ""), True


def _drop_ungrounded_entities(entities: list[dict], sym_ok: Callable[[str], bool]) -> tuple[list[dict], list[str]]:
    """Entities whose `grounding_symbol` is not in the index are dropped; a note explains each drop."""
    kept, notes = [], []
    for e in entities:
        if e.get("grounding_symbol") and not sym_ok(e["grounding_symbol"]):
            notes.append(f"ungrounded entity {e.get('name', '?')}: symbol {e['grounding_symbol']!r} not in the index")
        else:
            kept.append(e)
    return kept, notes


def _fix_wstg(vuln_classes: list[dict], known_wstg: set[str]) -> tuple[list[dict], list[str]]:
    """A fabricated `wstg_id` on a vuln class → the CWE's mapped id (or cleared); real/absent ids pass through."""
    fixed, notes = [], []
    for v in vuln_classes:
        wid, fake = _wstg_or_map(v.get("wstg_id", ""), v.get("cwe", ""), known_wstg)
        if fake:
            notes.append(f"fabricated wstg id {v.get('wstg_id')!r} for {v.get('cwe')} → {wid or 'none'}")
            v = {**v, "wstg_id": wid}
        fixed.append(v)
    return fixed, notes


def _ground_rules(rules: list[dict], sym_ok: Callable[[str], bool]) -> tuple[list[dict], list[str]]:
    """Domain-map rules whose `symbol` is not in the index are dropped; a note (a "gap") explains each drop."""
    kept, notes = [], []
    for r in rules:
        if not sym_ok(r.get("symbol", "")):
            notes.append(f"rule {r.get('id', '?')} ungrounded: symbol {r.get('symbol')!r} not in the index — {r.get('statement', '')}")
        else:
            kept.append(r)
    return kept, notes


def _ground_threats(threats: list[dict], sym_ok: Callable[[str], bool], known_wstg: set[str]) -> tuple[list[dict], list[str]]:
    """A threat grounded on neither a symbol nor a (file, line) is dropped; survivors get `_fix_wstg`'s treatment."""
    kept, notes = [], []
    for t in threats:
        if not sym_ok(t.get("symbol", "")) and not (t.get("file") and t.get("line")):
            notes.append(f"ungrounded threat dropped: {t.get('claim', '')[:80]} (symbol {t.get('symbol')!r})")
            continue
        wid, fake = _wstg_or_map(t.get("wstg_id", ""), t.get("cwe", ""), known_wstg)
        if fake:
            notes.append(f"fabricated wstg id {t.get('wstg_id')!r} on threat {t.get('claim', '')[:40]!r} → {wid or 'none'}")
            t = {**t, "wstg_id": wid}
        kept.append(t)
    return kept, notes


def ground_artifacts(am: dict | None, dm: dict | None, tm: dict | None, has_symbol, known_wstg: set[str]):
    """Enforce in code what the prompts ask for: symbols must exist, WSTG ids must be real.

    Ungrounded entities/threats → `notes`; ungrounded domain rules → `gaps`; fabricated `wstg_id` → the CWE's
    mapped id (or cleared). Returns (am, dm, tm, notes) as new dicts, shape-preserving: keys are only added
    when something was dropped or corrected. None artifacts pass through."""
    notes: list[str] = []

    def sym_ok(sym: str) -> bool:
        return bool(sym) and (has_symbol(sym) or has_symbol(sym.split(".")[-1]))

    def noted(art: dict, key: str, msgs: list[str]) -> None:
        if msgs:
            art[key] = [*(art.get(key) or []), *msgs]

    if am is not None:
        am, mine = dict(am), []
        kept, entity_notes = _drop_ungrounded_entities(am.get("entities") or [], sym_ok)
        mine += entity_notes
        if "entities" in am:
            am["entities"] = kept
        vcs, wstg_notes = _fix_wstg(am.get("vuln_classes") or [], known_wstg)
        mine += wstg_notes
        if "vuln_classes" in am:
            am["vuln_classes"] = vcs
        noted(am, "notes", mine)
        notes += mine
    if dm is not None:
        dm, mine = dict(dm), []
        rules, rule_notes = _ground_rules(dm.get("rules") or [], sym_ok)
        mine += rule_notes
        if "rules" in dm:
            dm["rules"] = rules
        noted(dm, "gaps", mine)
        notes += mine
    if tm is not None:
        tm, mine = dict(tm), []
        threats, threat_notes = _ground_threats(tm.get("threats") or [], sym_ok, known_wstg)
        mine += threat_notes
        if "threats" in tm:
            tm["threats"] = threats
        noted(tm, "notes", mine)
        notes += mine
    return am, dm, tm, notes


def reconcile(new: list[Hypothesis], queue: list[Hypothesis], done: set[str]) -> list[Hypothesis]:
    """Merge `new` into `queue`: drop items already done or already queued (same key; the higher priority
    wins), sort by priority desc (stable). Ungrounded items are kept — the gate drops them when batched."""
    merged: dict[str, Hypothesis] = {key(h): h for h in queue if key(h) not in done}
    for h in new:
        k = key(h)
        if k in done or k == "|":
            continue
        if k not in merged or h.priority > merged[k].priority:
            merged[k] = h
    return sorted(merged.values(), key=lambda h: -h.priority)


# Planner (card 44, Shannon's per-class lanes decided in code): what to hunt at an entry point / in a file, from
# the words of its route, path and handler name. ponytail: substring heuristic — a table, not NLP.
HUNT = (
    (("login", "signin", "auth", "password", "session", "token", "logout", "signup", "register"), ("CWE-287", "CWE-307", "CWE-522")),
    (("profile", "update", "edit", "save", "settings", "comment", "post"), ("CWE-79", "CWE-639")),
    (("admin",), ("CWE-862", "CWE-285")),
    (("search", "filter", "query", "list", "find", "allocation", "benefit"), ("CWE-89", "CWE-943")),
    (("file", "path", "download", "upload", "static", "attachment"), ("CWE-22",)),
    (("redirect", "return", "next", "url", "callback", "learn"), ("CWE-601",)),
    (("eval", "template", "render", "exec", "contribution"), ("CWE-95", "CWE-1336")),
    (("regex", "validat", "match", "pattern"), ("CWE-1333",)),
)
_ID_PARAM = re.compile(r"[:{<][^/}>]*id[^/}>]*[}>]?|[?&][^=]*id=|/\d+\b", re.IGNORECASE)  # /:id {id} <int:id> ?userId= /42
DEFAULT_HUNT = ("CWE-79", "CWE-89", "CWE-639")
FILE_BASELINE_MAX = 60  # ponytail: rounds×hyps slots never reach more anyway; raise with the budget


def hunt_classes(route: str = "", file: str = "", symbol: str = "") -> list[str]:
    """Classes to hunt at an entry point, most specific first; DEFAULT_HUNT when nothing in the words says more."""
    text = f"{route} {file} {symbol}".lower()
    out: list[str] = ["CWE-639", "CWE-862"] if _ID_PARAM.search(f"{route} {symbol}") else []
    for words, cwes in HUNT:
        if any(w in text for w in words):
            out += cwes
    return list(dict.fromkeys(out)) or list(DEFAULT_HUNT)


def _baseline(where: str, file: str, line: int, symbol: str, classes: list[str], claim: str, priority: int) -> tuple[Hypothesis, Anchor]:
    """A baseline hypothesis with its own entrypoint anchor: every baseline can report (and, via the discovery
    gate, report elsewhere) — a symbol-only baseline had nothing to pass as anchor_id (NodeGoat run 18)."""
    a = Anchor(id=new_anchor_id("entrypoint", where, file, line), tool="entrypoint", rule_id=where,
               severity="low", file=file, line=line, message=claim)
    h = Hypothesis(kind="entry", cwe=classes[0], symbol=symbol, anchor_id=a.id, reads=[file] if file else [],
                   priority=priority, claim=claim, **_owasp_ids(classes[0]))
    return h, a


def coverage(entry_points: list[Candidate], queue: list[Hypothesis], done: set[str], files: list[str] = (),
             adversarial: float = 0.25, seed: int = 0) -> tuple[list[Hypothesis], list[Anchor]]:
    """Plan-stage rule (Shannon): nothing stays unexamined. Every entry point not covered by a queued/done item
    (same symbol) becomes a priority-10 baseline naming the classes to hunt (`hunt_classes`); a deterministic
    `adversarial` share of them also gets the sweep wording. Every production `file` nobody reads becomes a
    priority-8 file baseline (≤ FILE_BASELINE_MAX). Each baseline carries its own entrypoint anchor.
    Returns (hypotheses, minted anchors)."""
    covered_syms = {h.symbol for h in queue if h.symbol} | {k.split("|", 1)[0] for k in done if "|" in k}
    sweep = {h.symbol: h.claim for h in adversarial_sweep(entry_points, adversarial, seed)}
    hyps: list[Hypothesis] = []
    minted: list[Anchor] = []
    for c in entry_points:
        if (c.symbol and c.symbol in covered_syms) or not c.file:  # a file's anchor covers no handler
            continue
        where = c.symbol or " ".join(c.route) or c.file
        classes = hunt_classes(" ".join(c.route), c.file, c.symbol)
        claim = (f"Baseline: untrusted input entering {where} ({c.file}:{c.line}) — hunt {', '.join(classes)}: "
                 "a sink of one of these classes reached without the matching control")
        if c.symbol in sweep:
            claim += ". " + sweep[c.symbol]
        h, a = _baseline(where, c.file, c.line, c.symbol, classes, claim, 10)
        hyps.append(h)
        minted.append(a)
    read = {f for h in [*queue, *hyps] for f in h.reads}
    for f in [f for f in files if f not in read][:FILE_BASELINE_MAX]:
        classes = hunt_classes("", f, "")
        claim = f"Baseline file: read {f} for {', '.join(classes)} — no queued item examines it"
        h, a = _baseline(f, f, 1, "", classes, claim, 8)
        hyps.append(h)
        minted.append(a)
    return hyps, minted


def adversarial_sweep(candidates: list[Candidate], fraction: float = 0.25, seed: int = 0) -> list[Hypothesis]:
    """Plan-stage rule (Shannon): a deterministic fraction of otherwise-uncovered candidates gets an unconstrained
    sweep — ignore assumed safety, treat every input as untrusted. Same seed → same pick."""
    pool = [c for c in candidates if c.symbol]
    if not pool or fraction <= 0:
        return []
    picked = random.Random(seed).sample(pool, min(len(pool), math.ceil(len(pool) * fraction)))
    return [Hypothesis(
        kind="entry", symbol=c.symbol, reads=[c.file] if c.file else [], priority=5,
        claim=f"Adversarial sweep of {c.symbol} ({c.file}:{c.line}): ignore assumed safety and trust boundaries, "
              "treat every input as untrusted and malformed, look for any sink it can reach",
    ) for c in picked]


def build_queue(
    store: RunStore, anchors: list[Anchor], threats: list[Threat] | None = None,
    locate: Callable[[str], tuple[str, int] | None] | None = None,
    entry_points_fn: Callable[[], list[Candidate]] | None = None,
    source_files_fn: Callable[[], list[str]] | None = None,
) -> tuple[list[Hypothesis], set[str]]:
    """One prioritized queue from the grounded threat model (store artifacts), the scanner anchors and
    entry-point coverage; synthetic anchors minted on the way are saved to the store. Shared by the tests
    and the Workflow `plan` node (card 43)."""
    am = store.artifact("architecture_model") or {}
    tm = store.artifact("threat_model")
    threats = list(threats or [])
    if tm:
        try:
            threats += ThreatModel.model_validate(tm).threats
        except ValueError as e:
            log.warning("threat_model: invalid after grounding: %s", e)
    criticality = {e.get("grounding_symbol", ""): e.get("criticality", "") for e in am.get("entities", [])}
    hyps, minted = from_threats(threats, anchors, locate, criticality)
    if minted:
        store.save_anchors(minted)  # synthetic anchors keep the single anchor-only gate
        log.info("reconcile: %d synthetic anchors for grounded threats", len(minted))
    done: set[str] = set()
    queue = reconcile(from_anchors(anchors) + hyps, [], done)
    if entry_points_fn is not None or source_files_fn is not None:  # plan-stage rule: nothing stays unexamined
        baseline, minted_entries = coverage(entry_points_fn() if entry_points_fn else [], queue, done,
                                            files=source_files_fn() if source_files_fn else [])
        if minted_entries:
            store.save_anchors(minted_entries)  # every baseline reports from its own entrypoint anchor
        queue = reconcile(baseline, queue, done)
    return queue, done
