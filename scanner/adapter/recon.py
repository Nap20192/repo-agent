"""Recon: the deterministic stand-in for Shannon's pre-recon-code deliverables (set_*_sinks, set_injection_sources,
set_auth_deep_dive, set_critical_file_paths) — a grep inventory of sinks by class, auth guards and config files.

No model: one pass over `fs.source_files` (production code only, symlink-safe), bounded regexes (no nested
quantifiers), a cap per class. The result is the plain-dict shape of `core.workflow.ReconMap`."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from scanner.adapter import fs
from scanner.core import Candidate

log = logging.getLogger("scanner.recon")

CLASS_CAP = 200  # hits kept per sink class; the rest is logged and dropped (a generated bundle must not flood the plan)
SINK_CLASSES = ("injection", "xss", "ssrf", "path", "eval", "redirect", "nosql", "regex")

# ponytail: line regexes, not taint — a sink line is "call + request-ish data on the same line"; the specialists prove the flow
_REQ = r"(?:req\.(?:query|params|body|headers|cookies)|request\.(?:GET|POST|args|form|json|data)|r\.(?:URL|FormValue|Body)|c\.(?:Param|Query)|[A-Za-z_]\w*)"
_SINKS: dict[str, dict[str, str]] = {  # lang → class → regex; bounded, single-pass
    "javascript": {
        "injection": r"\.(?:query|raw|exec)\([^)\n]{0,200}\+|(?:exec|execSync|spawn)\(\s*['\"][^'\"\n]{0,120}['\"]\s*\+",
        "xss": r"innerHTML\s*=|outerHTML\s*=|document\.write\(|dangerouslySetInnerHTML|\{\{\{|res\.send\([^)\n]{0,200}\+|<%-",
        "ssrf": r"(?:fetch|axios(?:\.\w+)?|got|request|https?\.(?:get|request))\(\s*(?!['\"])[A-Za-z_]",
        "path": r"(?:sendFile|readFile|readFileSync|createReadStream|writeFile|unlink)\([^)\n]{0,200}(?:req\.|path\.join)|path\.join\([^)\n]{0,200}req\.",
        "eval": r"\beval\(|new\s+Function\(|vm\.(?:run|runInNewContext|runInThisContext)|child_process|\bexec(?:Sync)?\(",
        "redirect": r"res\.redirect\(|\.setHeader\(\s*['\"]Location['\"]|location\.href\s*=",
        "nosql": r"\$where|\$regex|\.find(?:One)?\(\s*\{[^}\n]{0,200}req\.",
        "regex": r"new\s+RegExp\(\s*(?!['\"/])[A-Za-z_]",
    },
    "python": {
        "injection": r"\.execute\([^)\n]{0,200}(?:%|\+|f['\"])|\.raw\(|\.extra\(|os\.system\(|shell\s*=\s*True",
        "xss": r"render_template_string\(|Markup\(|\|\s*safe\b|mark_safe\(|HttpResponse\([^)\n]{0,200}\+",
        "ssrf": r"(?:requests|httpx|urllib\.request)\.(?:get|post|urlopen|request)\(\s*(?!['\"])[A-Za-z_]",
        "path": r"open\([^)\n]{0,200}(?:request\.|os\.path\.join)|send_file\(|os\.path\.join\([^)\n]{0,200}request\.",
        "eval": r"\beval\(|\bexec\(|pickle\.loads?\(|yaml\.load\(|subprocess\.",
        "redirect": r"redirect\(\s*request\.|HttpResponseRedirect\(\s*request\.",
        "nosql": r"\$where|find(?:_one)?\(\s*\{[^}\n]{0,200}request\.",
        "regex": r"re\.(?:compile|match|search|sub|findall)\(\s*(?!r?['\"])[A-Za-z_]",
    },
    "go": {
        "injection": r"\.(?:Query|Exec|QueryRow|Raw)\([^)\n]{0,200}\+|fmt\.Sprintf\(\s*\"[^\"\n]{0,120}(?:SELECT|INSERT|UPDATE|DELETE)",
        "xss": r"template\.HTML\(|text/template|fmt\.Fprintf\(\s*w\s*,[^)\n]{0,200}r\.",
        "ssrf": r"http\.(?:Get|Post|NewRequest)\(\s*(?!\"|http)[A-Za-z_]",
        "path": r"os\.(?:Open|ReadFile|Create)\([^)\n]{0,200}(?:filepath\.Join|r\.)|filepath\.Join\([^)\n]{0,200}r\.",
        "eval": r"exec\.Command\(",
        "redirect": r"http\.Redirect\(|\.Redirect\(",
        "nosql": r"\$where|bson\.M\{[^}\n]{0,200}r\.",
        "regex": r"regexp\.(?:Compile|MustCompile)\(\s*(?!`|\")[A-Za-z_]",
    },
    "php": {
        "injection": r"(?:mysqli_query|->query|->exec|shell_exec|system|passthru|exec)\([^)\n]{0,200}(?:\$_(?:GET|POST|REQUEST)|\.\s*\$)",
        "xss": r"echo\s+\$_(?:GET|POST|REQUEST)|print\s+\$_(?:GET|POST|REQUEST)|\{!!",
        "ssrf": r"(?:file_get_contents|curl_setopt|fopen)\([^)\n]{0,200}\$",
        "path": r"(?:include|require|include_once|require_once|readfile|file_get_contents)\([^)\n]{0,200}\$_(?:GET|POST|REQUEST)",
        "eval": r"\beval\(|assert\(|create_function\(|unserialize\(",
        "redirect": r"header\(\s*['\"]Location:[^)\n]{0,200}\$",
        "nosql": r"\$where",
        "regex": r"preg_(?:match|replace|split)\(\s*\$",
    },
}
_SINKS["typescript"] = _SINKS["javascript"]
_AUTH = re.compile(
    r"\b(isLoggedIn|isAdmin|isAuthenticated|requireAuth|requireLogin|ensureAuthenticated|authorize|checkAuth|"
    r"passport\.authenticate|jwt\.verify|session\.userId|login_required|permission_required|user_passes_test|"
    r"IsAuthenticated|Depends\(\s*get_current_user|@PreAuthorize|auth\.middleware|withAuth)\b"
)
_CONFIG_NAMES = {"package.json", "requirements.txt", "pyproject.toml", "go.mod", "composer.json", "server.js", "app.js",
                 "index.js", "app.py", "wsgi.py", "asgi.py", "settings.py", "manage.py", ".env.example", "Dockerfile",
                 "Makefile", "Procfile", "web.config", "nginx.conf", "vercel.json", "serverless.yml"}
_CONFIG_PREFIX = ("docker-compose", "nginx", ".env.", "config.", "settings.")
_COMPILED = {lang: {cls: re.compile(rx) for cls, rx in table.items()} for lang, table in _SINKS.items()}


def recon(target: Path, entry_points: list[Candidate], langs: list[str], index=None) -> dict:
    """Sinks by class (file:line), auth guards (file:line: name), config files, and the entry points as sources.
    Never raises: an unreadable target yields empty lists."""
    target = Path(target)
    sinks: dict[str, list[str]] = {c: [] for c in SINK_CLASSES}
    dropped: dict[str, int] = {}
    auth: list[str] = []
    config: list[str] = []
    try:
        for rel_path in fs.source_files(target):
            table = _COMPILED.get(fs.LANG_EXT.get(Path(rel_path).suffix, ""))
            if table is None or not (langs and fs.LANG_EXT[Path(rel_path).suffix] in langs or not langs):
                continue
            p = target / rel_path
            try:
                if p.stat().st_size > fs.FILE_CAP:
                    continue
                text = p.read_text(errors="replace")
            except OSError:
                continue
            for n, line in enumerate(text.splitlines(), 1):
                if len(line) > fs.MAX_DETECT_LINE:
                    continue
                for cls, rx in table.items():
                    if rx.search(line):
                        if len(sinks[cls]) < CLASS_CAP:
                            sinks[cls].append(f"{rel_path}:{n}")
                        else:
                            dropped[cls] = dropped.get(cls, 0) + 1
                if (m := _AUTH.search(line)) and not line.lstrip().startswith(("//", "#", "*")):
                    auth.append(f"{rel_path}:{n}: {m.group(1)}")
        for p in fs.files(target):
            rel_path = p.relative_to(target).as_posix()
            if p.name in _CONFIG_NAMES or p.name.startswith(_CONFIG_PREFIX) or rel_path.startswith("config/"):
                config.append(rel_path)
    except OSError as e:  # missing / unreadable target: the plan proceeds on entry points alone
        log.warning("recon: %s", e)
    for cls, n in dropped.items():
        log.warning("recon: %s: %d hits over CLASS_CAP=%d dropped", cls, n, CLASS_CAP)
    return {"sources": list(entry_points), "sinks": sinks, "auth": auth[:CLASS_CAP], "config_files": sorted(config)[:CLASS_CAP]}
