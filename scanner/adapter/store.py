"""State: one sqlite file per scanner. Runs, anchors, hypotheses, dossiers, findings, gate log, notes;
SARIF/summary are exports, the db is the truth. Ported from git-agent3 internal/adapter/state."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from scanner.adapter import owasp
from scanner.adapter.knowledge import enrichment_for
from scanner.core import (
    CONFIRMED,
    REJECTED,
    UNCERTAIN,
    Anchor,
    Dossier,
    Finding,
    Hypothesis,
    calibrate,
    exposure_for,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, target TEXT, status TEXT, reason TEXT, started REAL, finished REAL);
CREATE TABLE IF NOT EXISTS anchors(run INTEGER, id TEXT, json TEXT, PRIMARY KEY(run, id));
CREATE TABLE IF NOT EXISTS hypotheses(run INTEGER, round INTEGER, id TEXT, json TEXT);
CREATE TABLE IF NOT EXISTS dossiers(run INTEGER, round INTEGER, hypothesis_id TEXT, json TEXT);
CREATE TABLE IF NOT EXISTS findings(run INTEGER, n INTEGER, json TEXT, PRIMARY KEY(run, n));
CREATE TABLE IF NOT EXISTS gate_log(run INTEGER, time REAL, anchor_id TEXT, reason TEXT);
CREATE TABLE IF NOT EXISTS notes(run INTEGER, time REAL, text TEXT, ref TEXT);
CREATE TABLE IF NOT EXISTS artifacts(run INTEGER, stage TEXT, json TEXT, PRIMARY KEY(run, stage));
"""
NEAR_LINES = 6  # same CWE in the same file this close = one finding (eval() on four consecutive lines is one bug)
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_TAXONOMIES = {  # SARIF toolComponent name → (Finding field, GUID-less reference info)
    "WSTG": ("wstg_id", "OWASP Web Security Testing Guide", "https://owasp.org/www-project-web-security-testing-guide/"),
    "OWASP Top 10 2021": ("top10_2021", "OWASP Top 10 2021", "https://owasp.org/Top10/"),
    "OWASP Top 10 2025": ("top10", "OWASP Top 10 2025", "https://owasp.org/Top10/"),
    "ASVS": ("asvs_id", "OWASP ASVS 5.0", "https://owasp.org/www-project-application-security-verification-standard/"),
}


def _owasp_fill(f: Finding) -> dict:
    """Remediation / WSTG / Top 10 for a finding from its CWE, only where the finding has no value yet."""
    g = owasp.consult(f.cwe) if f.cwe else {}
    if not g or "status" in g:  # no CWE (dependency/entrypoint anchors) or unknown class: nothing to fill
        return {}
    return {k: v for k, v in {"remediation": g.get("remediation", ""), "remediation_url": g.get("remediation_url", ""),
                              "wstg_id": g.get("wstg_id", ""), "top10": g.get("top10_2025", "")}.items() if v and not getattr(f, k)}


def _taxa(f: Finding) -> list[dict]:
    g = owasp.consult(f.cwe) if f.cwe else {}
    vals = {"wstg_id": f.wstg_id or g.get("wstg_id", ""), "top10_2021": g.get("top10_2021", ""),
            "top10": f.top10 or g.get("top10_2025", ""), "asvs_id": g.get("asvs_id", "")}
    return [{"id": vals[field], "toolComponent": {"name": name}} for name, (field, _, _) in _TAXONOMIES.items() if vals[field]]


class Store:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)  # ponytail: one connection, tools run in threads
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(_SCHEMA)

    def close(self) -> None:
        self.db.close()

    def start_run(self, target: str) -> Run:
        with self.db:
            self.db.execute("UPDATE runs SET status='stopped', reason='orphaned' WHERE status='running'")
            cur = self.db.execute("INSERT INTO runs(target,status,started) VALUES(?,?,?)", (target, "running", time.time()))
        return Run(self.db, cur.lastrowid, target)


class Run:
    def __init__(self, db: sqlite3.Connection, run_id: int, target: str):
        self.db, self.id, self.target = db, run_id, target
        self.knowledge = None  # KnowledgeConfig set by the runner; None → environment defaults

    def save_anchors(self, anchors: list[Anchor]) -> None:
        with self.db:
            self.db.executemany("INSERT OR REPLACE INTO anchors VALUES(?,?,?)",
                                [(self.id, a.id, a.model_dump_json()) for a in anchors])

    def anchors(self) -> list[Anchor]:
        rows = self.db.execute("SELECT json FROM anchors WHERE run=? ORDER BY rowid", (self.id,))
        return [Anchor.model_validate_json(r[0]) for r in rows]

    def anchor(self, anchor_id: str) -> Anchor | None:
        r = self.db.execute("SELECT json FROM anchors WHERE run=? AND id=?", (self.id, anchor_id)).fetchone()
        return Anchor.model_validate_json(r[0]) if r else None

    def put_hypotheses(self, rnd: int, hs: list[Hypothesis]) -> None:
        with self.db:
            self.db.executemany("INSERT INTO hypotheses VALUES(?,?,?,?)",
                                [(self.id, rnd, h.id, h.model_dump_json()) for h in hs])

    def put_dossiers(self, rnd: int, ds: list[Dossier]) -> None:
        with self.db:
            self.db.executemany("INSERT INTO dossiers VALUES(?,?,?,?)",
                                [(self.id, rnd, d.hypothesis_id, d.model_dump_json()) for d in ds])

    def findings(self) -> list[Finding]:
        rows = self.db.execute("SELECT json FROM findings WHERE run=? ORDER BY n", (self.id,))
        return [Finding.model_validate_json(r[0]) for r in rows]

    def report(self, f: Finding) -> Finding:
        """Insert or return the duplicate (same anchor, or same cwe+file+line); higher confidence replaces verdict."""
        for i, old in enumerate(self.findings(), 1):
            same = (f.anchor_id and old.anchor_id == f.anchor_id) or \
                   (f.cwe and "direct" not in (f.source, old.source)  # direct osv findings share manifest:1 per CWE
                    and (old.cwe, old.file) == (f.cwe, f.file) and abs(old.line - f.line) <= NEAR_LINES)
            if not same:
                continue
            if f.confidence > old.confidence:
                old = old.model_copy(update={"status": f.status, "evidence": f.evidence, "confidence": f.confidence,
                                             "hypothesis_id": f.hypothesis_id or old.hypothesis_id})
                with self.db:
                    self.db.execute("UPDATE findings SET json=? WHERE run=? AND n=?", (old.model_dump_json(), self.id, i))
            return old
        n = self.db.execute("SELECT COALESCE(MAX(n),0)+1 FROM findings WHERE run=?", (self.id,)).fetchone()[0]
        f = f.model_copy(update={"id": f"f_{n}", **_owasp_fill(f)})
        with self.db:
            self.db.execute("INSERT INTO findings VALUES(?,?,?)", (self.id, n, f.model_dump_json()))
        return f

    def set_status(self, finding_id: str, status: str, evidence: list[str], note: str = "") -> Finding | None:
        """Change a finding's verdict (Critic: confirmed → uncertain); evidence is appended, note recorded."""
        for i, f in enumerate(self.findings(), 1):
            if f.id != finding_id:
                continue
            f = f.model_copy(update={"status": status, "evidence": [*f.evidence, *evidence]})
            with self.db:
                self.db.execute("UPDATE findings SET json=? WHERE run=? AND n=?", (f.model_dump_json(), self.id, i))
            if note:
                self.add_note(note, finding_id)
            return f
        return None

    ANNOTATIONS = ("review", "viability", "repro_status", "calibration")

    def annotate(self, finding_id: str, **fields) -> Finding | None:
        """Merge report-only annotations into a finding (card 45). Dict fields merge key-wise (review keeps earlier
        keys); anything outside ANNOTATIONS is refused — the verdict changes only through report/disprove."""
        bad = set(fields) - set(self.ANNOTATIONS)
        if bad:
            raise ValueError(f"annotate: {sorted(bad)} are not annotations (verdict fields belong to the gates)")
        for i, f in enumerate(self.findings(), 1):
            if f.id != finding_id:
                continue
            merged = {k: ({**getattr(f, k), **v} if isinstance(v, dict) else v) for k, v in fields.items()}
            f = f.model_copy(update=merged)
            with self.db:
                self.db.execute("UPDATE findings SET json=? WHERE run=? AND n=?", (f.model_dump_json(), self.id, i))
            return f
        return None

    def log_gate(self, anchor_id: str, reason: str) -> None:
        with self.db:
            self.db.execute("INSERT INTO gate_log VALUES(?,?,?,?)", (self.id, time.time(), anchor_id, reason))

    def add_note(self, text: str, ref: str = "") -> None:
        with self.db:
            self.db.execute("INSERT INTO notes VALUES(?,?,?,?)", (self.id, time.time(), text, ref))

    def notes(self) -> list[dict]:
        rows = self.db.execute("SELECT time,text,ref FROM notes WHERE run=? ORDER BY time", (self.id,))
        return [{"time": t, "text": x, "ref": r} for t, x, r in rows]

    def put_artifact(self, stage: str, obj: dict) -> None:
        """Stage artifact (architecture_model, threat_model, ...): one JSON per stage, replaces."""
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO artifacts VALUES(?,?,?)", (self.id, stage, json.dumps(obj)))

    def artifact(self, stage: str) -> dict | None:
        r = self.db.execute("SELECT json FROM artifacts WHERE run=? AND stage=?", (self.id, stage)).fetchone()
        return json.loads(r[0]) if r else None

    def finish(self, status: str, reason: str = "") -> None:
        with self.db:
            self.db.execute("UPDATE runs SET status=?, reason=?, finished=? WHERE id=?", (status, reason, time.time(), self.id))

    def _intent(self) -> str:
        return (self.artifact("threat_model") or {}).get("intent", "production")

    def _calibrate(self, f: Finding, intent: str) -> dict:
        exp, rules = exposure_for(f, self.artifact("architecture_model"))
        return calibrate(f, intent, exposure=exp, knowledge=enrichment_for(f.anchor_id, getattr(self, "knowledge", None)), extra_rules=rules)

    def write_report(self, out_dir: Path) -> Path:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        intent = self._intent()
        results = [{
            "ruleId": f.cwe or "unknown", "level": _LEVEL.get(f.severity, "warning"),
            "message": {"text": f.title + ("\n" + "\n".join(f.evidence) if f.evidence else "")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file}, "region": {"startLine": f.line}}}],
            "properties": {"finding_id": f.id, "anchor_id": f.anchor_id, "confidence": f.confidence,
                           "source": f.source, "calibration": f.calibration or self._calibrate(f, intent),
                           **{k: getattr(f, k) for k in ("review", "viability", "repro_status") if getattr(f, k)}},
            "taxa": _taxa(f),
            **({"fixes": [{"description": {"text": f.remediation}, "properties": {"url": f.remediation_url}}]}
               if f.remediation else {}),
        } for f in self.findings() if f.status == CONFIRMED]
        used: dict[str, set[str]] = {name: set() for name in _TAXONOMIES}
        for r in results:
            for t in r.get("taxa", []):
                used[t["toolComponent"]["name"]].add(t["id"])
        taxonomies = [{"name": name, "fullName": full, "informationUri": uri,
                       "taxa": [{"id": tid, "name": owasp.taxon_name(name, tid)} for tid in sorted(used[name])]}
                      for name, (_, full, uri) in _TAXONOMIES.items()]  # every result taxon is declared in its taxonomy
        sarif = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                 "runs": [{"tool": {"driver": {"name": "scanner"}}, "taxonomies": taxonomies, "results": results}]}
        p = out_dir / "report.sarif"
        p.write_text(json.dumps(sarif, indent=1))
        return p

    def write_summary(self, out_dir: Path) -> Path:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        fs = self.findings()
        gate = self.db.execute("SELECT COUNT(*) FROM gate_log WHERE run=?", (self.id,)).fetchone()[0]
        intent = self._intent()
        summary = {"run_id": self.id, "target": self.target,
                   **{s: sum(f.status == s for f in fs) for s in (CONFIRMED, REJECTED, UNCERTAIN)},
                   "findings": [{**f.model_dump(), "calibration": self._calibrate(f, intent)} for f in fs], "gate_refusals": gate,
                   "intent": intent}
        if (timings := self.artifact("timings")) is not None:
            summary["timings"] = timings
        p = out_dir / "summary.json"
        p.write_text(json.dumps(summary, indent=1))
        return p
