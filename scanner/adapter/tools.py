"""ADK function tools for Verifier (Investigator), Critic and Architect. Closures over the run store and target.

Port of git-agent3 internal/adapter/tools: list_candidates, dispatch, list_anchors,
report_finding (the evidence gate), list_findings, notes, consult_*, read/grep/shell.
Every tool returns a dict; errors are {"status": "error", "reason": ...}, never raised.
"""

from __future__ import annotations

import json
import re
import subprocess
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path

from scanner import core
from scanner.adapter import static
from scanner.adapter.dominance import make_check_dominance
from scanner.adapter.owasp import consult_owasp
from scanner.adapter.skills import list_skills, load_skill
from scanner.core import Finding
from scanner.core.ports import Index

OUT_CAP = 20_000
FILE_CAP = static.FILE_CAP
GREP_CAP = 4_000
DEF_CAP = 120  # lines of a definition body returned by lsp_definition
SYM_CAP = 200  # symbols listed by lsp_symbols
READ_WINDOW = 60
SHELL_TIMEOUT = 60


def _err(reason: str) -> dict:
    return {"status": "error", "reason": reason}


def _mismatch(name: str, got, want) -> str | None:
    if not got or not want or got == want:  # an anchor without the value (synthetic: no CWE) cannot disagree
        return None
    return f"{name} {got!r} does not match anchor's {want!r}"


def _default_reader(target: Path):
    return lambda file, line: static.read_lines(target, file, line, 3)


def _default_index(target: Path) -> Index:
    """The real multiplexer when the index package exists, else a grep-backed minimal Index."""
    try:
        from scanner.adapter.index import build_index

        return build_index(target)
    except ImportError:
        return _GrepIndex(target)


class _GrepIndex:
    """ponytail: grep-only Index (no bodies, no references) — used until scanner/adapter/index lands."""

    def __init__(self, target: Path):
        self.target = target

    def find_symbol(self, fqn):
        return static.find_symbol(self.target, fqn)

    def has_symbol(self, fqn):
        return static.find_symbol(self.target, fqn) is not None

    def definition_range(self, fqn):
        return None

    def references(self, fqn):
        return []

    def symbols(self, file):
        return []

    def close(self):
        pass


def _lsp_tools(target: Path, index: Index, entries_fn: Callable[[], list[str]] | None = None) -> list[Callable]:
    """lsp_symbols / lsp_definition / lsp_references / lsp_callers / lsp_callees / lsp_path_to_entry over the Index port."""
    entries_fn = entries_fn or (lambda: [c.symbol for c in static.entry_points(target) if c.symbol])

    def _inside(path: str) -> Path | None:
        p = (target / path).resolve()
        try:
            p.relative_to(target)
        except ValueError:
            return None
        return p

    def lsp_symbols(path: str) -> dict:
        """List the definitions declared in one file (name, kind, line, end_line, container) without reading its
        body. Use it to decide which symbol to open with lsp_definition instead of reading the whole file."""
        if _inside(path) is None:
            return _err(f"{path}: outside the target")
        syms = index.symbols(path)
        return {"path": path, "symbols": [s.model_dump() for s in syms[:SYM_CAP]], "truncated": len(syms) > SYM_CAP}

    def lsp_definition(symbol: str) -> dict:
        """Return ONLY the body of a symbol's definition as numbered lines (function/method/class), resolved by
        the language server; prefer lsp_definition over read_file — it returns only the symbol's body, so you
        quote exactly the lines that matter. Names: 'pingHandler', 'Server.login', '(*Server).login', 'pkg.Func'."""
        rng = index.definition_range(symbol)
        if rng is None:
            return _err(f"symbol {symbol!r} not found in the index — check the name with lsp_symbols or grep for it")
        file, start, end = rng
        p = _inside(file)
        if p is None or not p.is_file():
            return _err(f"{file}: not a file inside the target")
        lines = p.read_text(errors="replace").splitlines()
        start, last = max(start, 1), min(end, len(lines))
        truncated = last - start + 1 > DEF_CAP
        if truncated:
            last = start + DEF_CAP - 1
        text = "\n".join(f"{i}: {lines[i - 1]}" for i in range(start, last + 1))
        return {"symbol": symbol, "file": file, "start": start, "end": last, "truncated": truncated, "text": text}

    def lsp_references(symbol: str) -> dict:
        """Every place a symbol is used or called (file, line, line text), resolved by the language server — the
        exhaustive call-site list the proof standard requires. Capped at 50; [] when the symbol is unknown."""
        refs = [r for r in index.references(symbol) if _inside(r[0]) is not None][:50]  # never leak files outside the target
        return {"symbol": symbol, "references": [{"file": f, "line": ln, "text": t} for f, ln, t in refs]}

    def lsp_callers(symbol: str) -> dict:
        """Call sites of a symbol (file, line, calling symbol) from the language server's call hierarchy — who
        invokes it. Use it to walk from a sink back towards the trust boundary; capped at 50."""
        refs = [r for r in index.callers(symbol) if _inside(r[0]) is not None][:50]
        return {"symbol": symbol, "callers": [{"file": f, "line": ln, "symbol": s} for f, ln, s in refs]}

    def lsp_callees(symbol: str) -> dict:
        """Symbols a function calls (callee file, definition line, callee symbol) — walk from an entry point
        down towards sinks without reading whole files; capped at 50."""
        refs = [r for r in index.callees(symbol) if _inside(r[0]) is not None][:50]
        return {"symbol": symbol, "callees": [{"file": f, "line": ln, "symbol": s} for f, ln, s in refs]}

    def lsp_path_to_entry(symbol: str) -> dict:
        """Shortest caller chain from an entry point (route handler / main) to the symbol, e.g.
        ["main", "pingHandler", "runCmd"]; null when no entry reaches it within 6 hops. The Investigator
        uses it for reachability claims; the Critic uses a null path as the "unreachable" disproof, after
        confirming with lsp_callers that the chain is not merely cut by dynamic dispatch."""
        entries = entries_fn()
        return {"symbol": symbol, "entries": entries[:50], "path": index.path_to_entry(symbol, entries)}

    return [lsp_symbols, lsp_definition, lsp_references, lsp_callers, lsp_callees, lsp_path_to_entry]


def _common_tools(run) -> list[Callable]:
    def list_anchors(cwe: str = "", severity: str = "", file: str = "", limit: int = 0) -> dict:
        """List static-analysis anchors (facts file:line found by scanners). Every finding
        must reference one of these by anchor_id. Filter by cwe, severity, file; limit the count."""
        all_ = run.anchors()
        out = [
            a.model_dump()
            for a in all_
            if (not cwe or a.cwe == cwe)
            and (not severity or a.severity == severity)
            and (not file or a.file == file)
        ]
        return {"anchors": out[:limit] if limit > 0 else out, "total": len(all_)}

    def list_findings() -> dict:
        """List all findings reported so far in this run."""
        return {"findings": [f.model_dump() for f in run.findings()]}

    def note_add(text: str, ref: str = "") -> dict:
        """Add a note to the run's shared scratchpad (survives rounds). ref: anchor/file it is about."""
        run.add_note(text, ref)
        return {"status": "ok"}

    def note_list() -> dict:
        """List notes from the run's shared scratchpad."""
        return {"notes": run.notes()}

    def consult_knowledge(query: str) -> dict:
        """Look up a known vulnerability at osv.dev. query: an advisory id (GHSA-/CVE-/PYSEC-/GO-)
        or a package name. Cite the returned ref ('knowledge:<id>') in evidence — required by the
        gate for dependency findings."""
        q = query.strip()
        try:
            if re.match(r"^(GHSA|CVE|PYSEC|GO|RUSTSEC|OSV)-", q, re.IGNORECASE):
                req = urllib.request.Request(f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(q, safe='')}")
            else:
                req = urllib.request.Request(
                    "https://api.osv.dev/v1/query",
                    data=json.dumps({"package": {"name": q}}).encode(),
                    headers={"Content-Type": "application/json"},
                )
            with urllib.request.urlopen(req, timeout=10) as r:  # fixed https host
                data = json.load(r)
        except Exception as e:  # noqa: BLE001 best-effort consultant
            return _err(f"osv.dev: {e}")
        vulns = data.get("vulns") or ([data] if data.get("id") else [])
        if not vulns:
            return _err(f"no advisory for {q!r}")
        out = []
        for v in vulns[:5]:
            patched = [
                ev.get("fixed")
                for aff in v.get("affected", [])
                for rg in aff.get("ranges", [])
                for ev in rg.get("events", [])
                if ev.get("fixed")
            ]
            out.append({
                "ref": f"knowledge:{v['id']}",
                "summary": (v.get("summary") or v.get("details") or "")[:300],
                "affected": [a.get("package", {}).get("name") for a in v.get("affected", [])][:5],
                "patched": patched[:5],
            })
        return {"advisories": out}

    return [list_anchors, list_findings, note_add, note_list, consult_knowledge, consult_owasp]




def _quotes_in_target(target: Path, quotes: list[str]) -> bool:
    """Is at least one quote present verbatim somewhere in the target? One pass over the files."""
    for f in static.files(target):
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        if any(q in text for q in quotes):
            return True
    return False


def _code_tools(target: Path) -> list[Callable]:
    """read_file / grep / shell / consult_domain, all confined to the target directory."""

    def _inside(path: str) -> Path | None:
        p = (target / path).resolve()
        try:
            p.relative_to(target)
        except ValueError:
            return None
        return p

    def read_file(path: str, start: int = 1, end: int = 0) -> dict:
        """Read lines [start, end] of a file inside the target, numbered (default window: 60 lines from start).
        Prefer lsp_definition for a symbol's body; use read_file for context around a line. Quote these lines
        as evidence."""
        p = _inside(path)
        if p is None or not p.is_file():
            return _err(f"{path}: not a file inside the target")
        if p.stat().st_size > FILE_CAP:
            return _err(f"{path}: file larger than {FILE_CAP} bytes; use grep or lsp_definition")
        lines = p.read_text(errors="replace").splitlines()
        if start > len(lines):
            return _err(f"{path}: start {start} is past the last line ({len(lines)})")
        start = max(start, 1)
        end = min(end or start + READ_WINDOW - 1, len(lines))
        text = "\n".join(f"{i}: {lines[i - 1]}" for i in range(start, end + 1))
        return {"path": path, "start": start, "end": end, "text": text[:OUT_CAP]}

    def grep(pattern: str, path: str = ".") -> dict:
        """Search the target for a regex (rg -n). path: file or directory inside the target."""
        if _inside(path) is None:
            return _err(f"{path}: outside the target")
        out = shell(f"rg -n --no-heading -m 100 -e {_q(pattern)} {_q(path)} || grep -rn -E -m 100 -e {_q(pattern)} {_q(path)}")
        note = "\n… truncated: narrow the pattern or path"
        if "output" in out and len(out["output"]) > GREP_CAP:
            out["output"] = out["output"][: GREP_CAP - len(note)] + note
        return out

    def shell(command: str) -> dict:
        """Run a shell command in the target directory (cat, sed -n, ls, git, go build ...). 60s timeout,
        output capped. Use it to read code you need for evidence."""
        # ponytail: host exec without sandbox; run untrusted targets in Docker before scanning.
        try:
            p = subprocess.run(command, shell=True, cwd=target, capture_output=True, text=True, timeout=SHELL_TIMEOUT, check=False)
        except subprocess.TimeoutExpired:
            return _err(f"timeout after {SHELL_TIMEOUT}s")
        except Exception as e:  # noqa: BLE001 — a tool never raises into the model
            return _err(f"shell: {e}")
        out = (p.stdout + p.stderr)[:OUT_CAP]
        return {"exit_code": p.returncode, "output": out}

    def consult_domain(entity: str) -> dict:
        """Ask the domain consultant whether access to an entity is a hole or a business rule: returns
        its declaration and the ownership/role checks found near it. Cite the returned ref
        ('domain:<entity>') in evidence — required by the gate for authz/IDOR findings."""
        # ponytail: grep heuristic instead of a Domain Map; add an AST builder when Go targets need roles/routes.
        name = entity.split(".")[-1]
        decl = shell(f"rg -n -e {_q(rf'(type|struct|class|def|func(tion)?)\s+{re.escape(name)}\b')} . || true")["output"]
        files = sorted({ln.split(":", 1)[0] for ln in decl.splitlines() if ":" in ln})
        checks = []
        for f in files:
            checks += shell(f"rg -n -e {_q(r'UserID|user_id|owner|OwnerID|current_user|==\s*\S*id')} {_q(f)} || true")["output"].splitlines()
        return {
            "ref": f"domain:{entity}",
            "declaration": decl[:2000],
            "owner_checks": checks[:50],
            "note": "heuristic — decide hole vs business rule from the code",
        }

    return [read_file, grep, shell, consult_domain]


def verifier_tools(run, target: Path, reader: Callable[[str, int], str] | None = None, index: Index | None = None) -> list[Callable]:
    """Tools for the Verifier: anchors, report_finding gate, code reading, shell, consultants."""
    target = Path(target).resolve()
    read = reader or _default_reader(target)

    def report_finding(
        anchor_id: str,
        title: str,
        status: str,
        evidence: list[str],
        hypothesis_id: str = "",
        severity: str = "",
        confidence: float = 0.0,
        cwe: str = "",
        file: str = "",
        line: int = 0,
    ) -> dict:
        """Record a verdict on an anchor: confirmed, rejected or uncertain. anchor_id must come from
        list_anchors. 'confirmed' is accepted only with evidence — exact quotes of the code you read
        at the anchor. Dependency (osv/CVE/GHSA) and authz/IDOR anchors also require a consult
        reference in evidence: 'knowledge:<advisory id>' or 'domain:<entity>'. Findings without a
        real anchor, evidence or required consult are refused."""
        reason = _gate(anchor_id, title, status, evidence, hypothesis_id, severity, confidence, cwe, file, line)
        if isinstance(reason, str):
            run.log_gate(anchor_id, reason)
            return _err(f"report_finding: {reason}")
        return reason.model_dump()

    def _gate(anchor_id, title, status, evidence, hypothesis_id, severity, confidence, cwe, file, line) -> str | Finding:
        if not anchor_id:
            return "anchor_id is required — pick one from list_anchors"
        a = run.anchor(anchor_id)
        if a is None:
            return f"unknown anchor_id {anchor_id!r} — use ids from list_anchors"
        bad = [m for m in (_mismatch("cwe", cwe, a.cwe), _mismatch("file", file, a.file), _mismatch("line", line, a.line)) if m]
        if bad:
            return "; ".join(bad) + "; coordinates come from the anchor — omit them or pick the right anchor_id"
        if not a.cwe and cwe:  # synthetic anchors (entrypoint/threatmodel) carry no class: the model's CWE is recorded
            a = a.model_copy(update={"cwe": cwe.strip().upper()})
        f = Finding(
            anchor_id=a.id, hypothesis_id=hypothesis_id, cwe=a.cwe, file=a.file, line=a.line,
            title=title, severity=severity or a.severity, status=status,
            evidence=list(evidence or []), confidence=confidence,
        )
        secret = a.cwe == "CWE-798"  # never re-leak the secret: compare and store redacted
        if secret:
            f.evidence = [core.redact_secrets(e) for e in f.evidence]
        if f.status != core.UNCERTAIN and (r := core.check_consulted(a, f.evidence)):
            return r
        if f.status == core.CONFIRMED:
            try:
                code = read(a.file, a.line)
            except Exception as e:  # noqa: BLE001
                return f"cannot read {a.file}:{a.line} to verify evidence: {e}"
            if secret:
                code = core.redact_secrets(code)
            quotes = [e.strip() for e in f.evidence if e.strip() and not core.is_consult_ref(e)]
            if not any(q in code for q in quotes):
                return f"evidence does not match the code at {a.file}:{a.line} — quote the lines exactly as read"
        if r := core.validate_finding(f):
            return r
        return run.report(f)

    return [report_finding, *_code_tools(target), *_lsp_tools(target, index or _default_index(target)), *_common_tools(run), list_skills, load_skill]


def critic_tools(run, target: Path, in_target: Callable[[list[str]], bool] | None = None, index: Index | None = None) -> list[Callable]:
    """Tools for the Critic: disprove_finding (confirmed → uncertain under a counter-evidence gate) + code tools."""
    target = Path(target).resolve()
    found = in_target or (lambda qs: _quotes_in_target(target, qs))

    def disprove_finding(finding_id: str, counter_evidence: list[str], reason: str) -> dict:
        """Downgrade a confirmed finding to uncertain because you found a counter-fact: a sanitizer or
        validator that dominates the sink, a framework protection, unreachability, or a parameterized
        call. counter_evidence: exact code lines you read anywhere in the target that carry the
        counter-fact (at least one must exist in the code); reason: one sentence. Refused when the
        finding is not confirmed or the quotes are not found in the code."""
        f = next((x for x in run.findings() if x.id == finding_id), None)
        if f is None:
            return _err(f"unknown finding_id {finding_id!r} — use ids from list_findings")
        if f.status != core.CONFIRMED:
            return _err(f"finding {finding_id} is {f.status}, only confirmed findings can be disproved")
        quotes = [q.strip() for q in counter_evidence or [] if q.strip()]
        if not quotes or not found(quotes):
            return _err("counter_evidence is not found in the code — quote the lines exactly as read")
        upd = run.set_status(f.id, core.UNCERTAIN, [f"critic: {reason}", *quotes], f"critic disproved {f.id}: {reason}")
        return upd.model_dump() if upd else _err("update failed")

    idx = index or _default_index(target)
    return [disprove_finding, make_check_dominance(target, idx), *_code_tools(target), *_lsp_tools(target, idx),
            *_common_tools(run), list_skills, load_skill]


def architect_tools(run, target: Path, index: Index | None = None) -> list[Callable]:
    """Read-only tools for the Architect: entry points, anchors, read_file, grep, consult_owasp. No shell."""
    target = Path(target).resolve()
    read_file, grep, _shell, _domain = _code_tools(target)

    def list_entry_points() -> dict:
        """List the deterministic entry points (trust boundaries) found by the text detectors:
        route registrations and handlers, with file:line and the handler symbol."""
        return {"entry_points": [c.model_dump() for c in static.entry_points(target)]}

    list_anchors, *_ = _common_tools(run)
    return [list_entry_points, list_anchors, read_file, grep, *_lsp_tools(target, index or _default_index(target)), consult_owasp, list_skills, load_skill]


def subset(tools: list[Callable], names: set[str]) -> list[Callable]:
    """Pick tools by function name, in `names` order of the source list; an unknown name is a build-time typo."""
    by = {t.__name__: t for t in tools}
    missing = names - set(by)
    if missing:
        raise KeyError(f"unknown tools: {sorted(missing)}")
    return [t for t in tools if t.__name__ in names]


_READ = {"read_file", "grep", "lsp_symbols", "lsp_definition", "lsp_references", "lsp_callers", "lsp_callees", "lsp_path_to_entry"}
_COMMON = {"list_anchors", "list_findings", "note_add", "note_list", "consult_owasp", "load_skill", "list_skills"}
TAINT_TOOLS = {"report_finding", "shell"} | _READ | _COMMON
AUTHZ_TOOLS = TAINT_TOOLS | {"consult_domain"}
DEPENDENCY_TOOLS = {"report_finding", "consult_knowledge", "read_file", "grep", "lsp_definition", "lsp_references", "lsp_path_to_entry"} | _COMMON
SECRETS_TOOLS = {"report_finding", "read_file", "grep", "lsp_definition", "lsp_references"} | _COMMON
CONFIG_TOOLS = {"report_finding", "read_file", "grep", "lsp_definition", "lsp_references"} | _COMMON
TAINT_CRITIC_TOOLS = {"disprove_finding", "check_dominance", "shell"} | _READ | _COMMON
AUTHZ_CRITIC_TOOLS = TAINT_CRITIC_TOOLS | {"consult_domain"}
DEPENDENCY_CRITIC_TOOLS = {"disprove_finding", "consult_knowledge", "read_file", "grep", "lsp_definition", "lsp_references",
                           "lsp_path_to_entry"} | _COMMON


def _q(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"
