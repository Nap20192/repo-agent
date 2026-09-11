"""Deterministic layer: scanners → Anchors, text entry-point detectors, symbol check, code reader.

Ported from git-agent3 internal/adapter/{static,secrets,index/lsp/*entry}. Runs on the host.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from pydantic import BaseModel, Field

from scanner.core import (
    Anchor,
    Candidate,
    merge_duplicates,
    new_anchor_id,
    norm_severity,
    redact_secrets,
)

log = logging.getLogger("scanner.static")

# ponytail: host exec, no sandbox — do not scan untrusted repos with deps install.

SKIP_DIRS = {".git", "node_modules", "vendor", "venv", ".venv", "__pycache__", "dist", "build", ".targets"}
LANG_EXT = {".go": "go", ".py": "python", ".js": "javascript", ".ts": "typescript", ".tsx": "typescript",
            ".jsx": "javascript", ".php": "php"}


class ScanResult(BaseModel):
    anchors: list[Anchor] = Field(default_factory=list)
    ran: list[str] = Field(default_factory=list)
    failed: dict[str, str] = Field(default_factory=dict)


def files(target: Path):
    """Source files under target, skipping vendor/build/VCS dirs."""
    root_res = Path(target).resolve()
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not (Path(root) / d).is_symlink()]
        for f in files:
            p = Path(root) / f
            if p.is_symlink() and not p.resolve().is_relative_to(root_res):
                continue  # a symlink pointing outside the target is never read or reported
            yield p


def detect_langs(target: Path) -> set[str]:
    return {LANG_EXT[p.suffix] for p in files(target) if p.suffix in LANG_EXT}


def _rel(target: Path, file: str) -> str:
    file = file.removeprefix("file://").removeprefix("./")
    try:
        return str(Path(file).resolve().relative_to(target.resolve())) if os.path.isabs(file) else file
    except ValueError:
        return file


def _run(cmd: list[str], target: Path, timeout: int = 600) -> str:
    if shutil.which(cmd[0]) is None:
        raise FileNotFoundError(f"{cmd[0]} not installed")
    p = subprocess.run(cmd, cwd=target, capture_output=True, text=True, timeout=timeout, check=False)
    return p.stdout


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
    for rel in rule.get("relationships", []):
        t = rel.get("target", {})
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
                file = _rel(target, file)
                out.append(Anchor(
                    id=new_anchor_id(tool, rule_id, file, line), tool=tool, rule_id=rule_id, cwe=cwe,
                    severity=norm_severity(res.get("level", "")), file=file, line=line,
                    message=(res.get("message", {}).get("text") or "").strip(),
                    snippet=(region.get("snippet", {}).get("text") or "").strip(),
                ))
    return out


def _gosec(target: Path) -> list[Anchor]:
    return anchors_from_sarif(_run(["gosec", "-fmt", "sarif", "-quiet", "-no-fail", "./..."], target), "gosec", target)


# registry packs per language (validated against the registry; p/express does not exist)
_SEMGREP_PACKS = {"go": ["p/golang"], "python": ["p/python", "p/flask", "p/django"],
                  "javascript": ["p/javascript", "p/nodejs"], "typescript": ["p/typescript", "p/nodejs"], "php": ["p/php"]}
# noise sources semgrep should not scan: CI, docs, fixtures, tests, templates
_SEMGREP_EXCLUDES = [".github", "docs", "artifacts", "*.md", "*.html", "*.yml", "*.yaml", "*.txt",
                     "**/test/**", "**/tests/**", "*_test.go", "*.test.js", "test_*.py", *sorted(SKIP_DIRS)]


def _semgrep(target: Path) -> list[Anchor]:
    if cfg := os.environ.get("SEMGREP_CONFIG"):
        cfgs, metrics = [cfg], ([] if cfg == "auto" else ["--metrics=off"])  # semgrep refuses `auto` with metrics off
    else:
        cfgs = sorted({p for lang in detect_langs(target) for p in _SEMGREP_PACKS.get(lang, [])}) or ["p/default"]
        metrics = ["--metrics=off"]
    args = [a for c in cfgs for a in ("--config", c)] + [a for e in _SEMGREP_EXCLUDES for a in ("--exclude", e)]
    out = _run(["semgrep", "--sarif", "--quiet", *metrics, *args, "."], target)
    return anchors_from_sarif(out, "semgrep", target)


_MANIFESTS = {"go.mod", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "poetry.lock",
              "Pipfile.lock", "composer.lock", "Cargo.lock", "Gemfile.lock", "pom.xml", "gradle.lockfile"}


def _osv(target: Path) -> list[Anchor]:
    if shutil.which("osv-scanner") is None:
        raise FileNotFoundError("osv-scanner not installed")
    # explicit lockfiles: osv-scanner's git-aware directory walk finds nothing inside a shallow clone
    manifests = [str(p.relative_to(target)) for p in files(target) if p.name in _MANIFESTS]
    if not manifests:
        raise RuntimeError("no dependency manifests (go.mod, package-lock.json, requirements.txt, ...)")
    args = [a for m in manifests for a in ("-L", m)]
    p = subprocess.run(["osv-scanner", "--format", "json", *args], cwd=target, capture_output=True, text=True,
                       timeout=600, check=False)  # exit 1 = vulnerabilities found, JSON still on stdout
    if not p.stdout.strip():
        raise RuntimeError(p.stderr.strip()[:300] or "no output")
    return anchors_from_osv(json.loads(p.stdout), target)


OSV_MAX = int(os.environ.get("OSV_MAX", "40"))


def anchors_from_osv(data: dict, target: Path) -> list[Anchor]:
    """One anchor per vulnerable (manifest, package@version), all advisory ids merged into rule_ids;
    capped at OSV_MAX packages (most advisories first) — a stale lockfile must not flood the queue."""
    out = []
    for res in data.get("results", []):
        file = _rel(target, res.get("source", {}).get("path", ""))
        for pkg in res.get("packages", []):
            name = pkg.get("package", {}).get("name", "")
            ver = pkg.get("package", {}).get("version", "")
            vulns = pkg.get("vulnerabilities", [])
            ids = [v.get("id", "") for v in vulns if v.get("id")]
            if not ids:
                continue
            first = next((v for v in vulns if v.get("id", "").startswith("GHSA-")), vulns[0])
            out.append(Anchor(
                id=new_anchor_id("osv", f"{name}@{ver}", file, 1), tool="osv", rule_id=first.get("id", ""), rule_ids=ids,
                severity="high", file=file, line=1, snippet=f"{name} {ver}",
                message=f"{name}@{ver}: {len(ids)} advisories ({', '.join(ids[:4])}{'…' if len(ids) > 4 else ''}) — "
                        f"{first.get('summary', '')}".strip(),
            ))
    out.sort(key=lambda a: -len(a.rule_ids))
    if len(out) > OSV_MAX:
        log.warning("osv: %d vulnerable packages, keeping the %d with most advisories (OSV_MAX)", len(out), OSV_MAX)
    return out[:OSV_MAX]


def _gitleaks(target: Path) -> list[Anchor]:
    out = _run(["gitleaks", "detect", "--no-banner", "--no-git", "--report-format", "json",
                "--report-path", "/dev/stdout", "--exit-code", "0"], target)
    out = out[out.find("["):] if "[" in out else "[]"
    anchors = []
    for leak in json.loads(out or "[]"):
        file, line, rule = _rel(target, leak.get("File", "")), int(leak.get("StartLine", 0)), leak.get("RuleID", "")
        if not file or not line:
            continue
        anchors.append(Anchor(
            id=new_anchor_id("gitleaks", rule, file, line), tool="gitleaks", rule_id=rule, cwe="CWE-798",
            severity="high", file=file, line=line, message=leak.get("Description", ""),
            snippet=redact_secrets((leak.get("Match") or "")[:200]),
        ))
    return anchors


def scan(target: Path, skip_deps: bool = False) -> ScanResult:
    """Run every applicable scanner; a failed/missing scanner lands in `failed`, never raises."""
    target = Path(target)
    langs = detect_langs(target)
    jobs = []
    if "go" in langs or not langs:
        jobs.append(("gosec", _gosec))
    if os.environ.get("SEMGREP_CONFIG") or (langs - {"go"}):
        jobs.append(("semgrep", _semgrep))
    if not skip_deps:
        jobs.append(("osv", _osv))
    jobs.append(("gitleaks", _gitleaks))
    return _run_jobs(target, jobs)


def _run_jobs(target: Path, jobs) -> ScanResult:
    """Scanners run concurrently (one thread each: they are subprocesses); results are merged in job order."""
    res = ScanResult()

    def one(tool, fn):
        t0 = time.monotonic()
        try:
            return fn(target), None, time.monotonic() - t0
        except Exception as e:  # noqa: BLE001 — scanner failure is a result, not a crash
            return [], f"{type(e).__name__}: {e}"[:300], time.monotonic() - t0

    with ThreadPoolExecutor(max_workers=max(1, len(jobs))) as ex:
        futures = [(tool, ex.submit(one, tool, fn)) for tool, fn in jobs]
        for tool, fut in futures:
            anchors, err, secs = fut.result()
            log.info("static: %s %s in %.1fs", tool, "failed" if err else f"{len(anchors)} anchors", secs)
            if err:
                res.failed[tool] = err
            else:
                res.anchors += anchors
                res.ran.append(tool)
    for a in res.anchors:  # a secret-class anchor (semgrep private-key, gitleaks…) must not carry the secret itself
        if a.cwe == "CWE-798":
            a.snippet, a.message = redact_secrets(a.snippet), redact_secrets(a.message)
    res.anchors = merge_duplicates(res.anchors)
    return res


# --- entry points (text detectors) ---------------------------------------------------

_GO_ROUTE = re.compile(r"\.(?:HandleFunc|Handle|GET|POST|PUT|DELETE|PATCH|Any|Get|Post|Put|Delete|Patch|Options|Head)\(\s*\"[^\"]*\"\s*,\s*([\w.]+)")
_PY_ROUTE = re.compile(r"^\s*@\S+\.(?:route|get|post|put|delete|patch|api_route|websocket)\(\s*[\"'][^\"']+[\"']")
_PY_DEF = re.compile(r"^\s*(?:async\s+)?def\s+(\w+)")
_DJANGO_URL = re.compile(r"^\s*(?:path|re_path|url)\(\s*r?[\"'][^\"']*[\"']\s*,\s*([\w.]+)")
_JS_METHODS = r"(?:get|post|put|delete|patch|all|use)"
_JS_ROUTE = re.compile(rf"\b(?:app|router|server)\.({_JS_METHODS})\(\s*[\"'`]([^\"'`]*)[\"'`]\s*,[^;]{{0,200}}?([A-Za-z_$][\w$]*)\s*\)*\s*;?\s*$")
FILE_CAP = 2 * 1024 * 1024  # never slurp a multi-GB file for a small window (read_file, dominance)
MAX_DETECT_LINE = 1000  # entry detectors skip longer lines: minified bundles and adversarial input, no backtracking budget
_JS_INLINE = re.compile(rf"\b(?:app|router|server)\.({_JS_METHODS})\(\s*[\"'`]([^\"'`]*)[\"'`]\s*,\s*(?:async\s*)?(?:\([^)]*\)\s*=>|\w+\s*=>|function\s*\()")
_JS_CHAIN = re.compile(rf"\.route\(\s*[\"'`]([^\"'`]*)[\"'`]\s*\)\.({_JS_METHODS})\(\s*([A-Za-z_$][\w$]*)")
_PHP_ROUTE = re.compile(r"Route::(get|post|put|delete|patch|any|match)\(\s*['\"]([^'\"]*)['\"]\s*,\s*\[\s*(\w+)::class\s*,\s*['\"](\w+)['\"]")
_PHP_INPUT = re.compile(r"\$_(?:GET|POST|REQUEST)\b")


def _js_entries(rel: str, i: int, ln: str) -> list[Candidate]:
    if m := _JS_CHAIN.search(ln):
        return [Candidate(kind="entry", file=rel, line=i, symbol=m.group(3), route=[f"{m.group(2).upper()} {m.group(1)}"])]
    if m := _JS_INLINE.search(ln):  # inline handler: no symbol, the route is the identity
        return [Candidate(kind="entry", file=rel, line=i, symbol="", route=[f"{m.group(1).upper()} {m.group(2)}"])]
    if m := _JS_ROUTE.search(ln):
        return [Candidate(kind="entry", file=rel, line=i, symbol=m.group(3), route=[f"{m.group(1).upper()} {m.group(2)}"])]
    return []


def entry_points(target: Path) -> list[Candidate]:
    target = Path(target)
    out = []
    for p in files(target):
        lang = LANG_EXT.get(p.suffix)
        if lang is None:
            continue
        try:
            lines = p.read_text(errors="replace").splitlines()
        except OSError as e:
            log.warning("entry_points: unreadable %s: %s", p, e)
            continue
        rel = str(p.relative_to(target))
        pending = php_input_seen = False
        for i, ln in enumerate(lines, 1):
            if len(ln) > MAX_DETECT_LINE:
                continue
            if lang == "go":
                if m := _GO_ROUTE.search(ln):
                    out.append(Candidate(kind="entry", file=rel, line=i, symbol=m.group(1)))
            elif lang == "python":
                if _PY_ROUTE.match(ln):
                    pending = True
                elif pending and (m := _PY_DEF.match(ln)):
                    out.append(Candidate(kind="entry", file=rel, line=i, symbol=m.group(1)))
                    pending = False
                elif m := _DJANGO_URL.match(ln):
                    out.append(Candidate(kind="entry", file=rel, line=i, symbol=m.group(1).rsplit(".", 1)[-1]))
            elif lang == "php":
                if m := _PHP_ROUTE.search(ln):
                    out.append(Candidate(kind="entry", file=rel, line=i, symbol=f"{m.group(3)}.{m.group(4)}",
                                         route=[f"{m.group(1).upper()} {m.group(2)}"]))
                elif not php_input_seen and _PHP_INPUT.search(ln):  # plain PHP page: the file is the boundary
                    php_input_seen = True
                    out.append(Candidate(kind="entry", file=rel, line=i, symbol="", route=[rel]))
            else:
                out += _js_entries(rel, i, ln)
    return out


_DEF_KW = r"(?:func(?:\s*\([^)]*\))?|def|function|class|const|var|let|type)"


def find_symbol(target: Path, fqn: str, extensions: tuple[str, ...] | None = None) -> tuple[str, int] | None:
    """(file, line) of the definition of fqn's last segment in the target (text grep), or None.
    `extensions` restricts the search to one language's files (per-language grep fallback)."""
    target = Path(target)
    name = fqn.rsplit(".", 1)[-1].strip()
    if not re.fullmatch(r"\w+", name):
        return None
    # ponytail: text grep over the tree, no index; swap for LSP/ctags if targets get big
    rx = re.compile(rf"^\s*(?:<\?php\s*)?(?:export\s+|async\s+)*{_DEF_KW}\s+{re.escape(name)}\b")
    for p in files(target):
        if p.suffix not in LANG_EXT or (extensions and p.suffix not in extensions):
            continue
        try:
            with p.open(errors="replace") as fh:
                for i, ln in enumerate(fh, 1):
                    if rx.match(ln):
                        return str(p.relative_to(target)), i
        except OSError as e:
            log.warning("find_symbol: unreadable %s: %s", p, e)
            continue
    return None


def has_symbol(target: Path, fqn: str) -> bool:
    return find_symbol(target, fqn) is not None


def read_lines(target: Path, file: str, line: int, window: int = 3) -> str:
    target = Path(target).resolve()
    p = (target / file).resolve()
    if not p.is_relative_to(target):  # symlink or '..' escaping the target
        raise FileNotFoundError(f"{file}: outside the target")
    lines = p.read_text(errors="replace").splitlines()  # raises FileNotFoundError
    lo, hi = max(1, line - window), min(len(lines), line + window)
    return "\n".join(lines[lo - 1:hi])
