"""Ground truth cannot drift: every local expected (file, line) exists and the line holds its sink keyword."""

import json
from pathlib import Path

import pytest

from scanner import main

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "eval" / "dataset.json"
CASES = json.loads(DATASET.read_text())["cases"]
LOCAL = [c for c in CASES if "url" not in c]


@pytest.mark.parametrize("case", LOCAL, ids=[c["name"] for c in LOCAL])
def test_expected_lines_exist_and_hold_their_sink(case):
    target = ROOT / case["target"]
    assert target.is_dir(), case["target"]
    for e in case["expected"]:
        lines = (target / e["file"]).read_text().splitlines()
        assert e["line"] <= len(lines), f"{case['name']}: {e['file']}:{e['line']} past EOF"
        if "sink" in e:
            assert e["sink"] in lines[e["line"] - 1], f"{case['name']}: {e['file']}:{e['line']} lacks {e['sink']!r}"


def test_new_samples_cover_every_class_with_a_safe_neighbour():
    by_name = {c["name"]: c for c in CASES}
    assert {e["cwe"] for e in by_name["flaskshop"]["expected"]} == {"CWE-89", "CWE-78", "CWE-22", "CWE-918", "CWE-79"}
    assert {e["cwe"] for e in by_name["expressshop"]["expected"]} >= {"CWE-89", "CWE-78", "CWE-22", "CWE-601", "CWE-95"}
    assert by_name["nodegoat"]["url"].startswith("https://github.com/OWASP/NodeGoat")
    src = (ROOT / "samples/11-expressshop/server.js").read_text()
    assert "=> {" in src and "app.get(" in src  # inline arrow handlers, for the entry-point detector


def test_dry_validates_local_dataset(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(ROOT)
    local = {"cases": LOCAL}
    p = tmp_path / "ds.json"
    p.write_text(json.dumps(local))
    assert main.main(["eval", str(p), "--dry"]) == 0
    bad = {"cases": [{"name": "x", "target": "samples/01-hello", "expected": [{"cwe": "CWE-1", "file": "nope.go", "line": 1}]}]}
    p.write_text(json.dumps(bad))
    assert main.main(["eval", str(p), "--dry"]) == 1


def test_ensure_target_refuses_unsafe_urls_and_paths(tmp_path, monkeypatch):
    import pytest

    from scanner import main as m
    monkeypatch.chdir(tmp_path)
    calls = []
    monkeypatch.setattr(m.subprocess, "run", lambda argv, **kw: calls.append((argv, kw)))
    for url in ("ext::sh -c id", "file:///etc", "--upload-pack=id", "http://github.com/a/b", "git@github.com:a/b.git"):
        with pytest.raises(ValueError):
            m._ensure_target({"target": ".targets/x", "url": url})
    with pytest.raises(ValueError):
        m._ensure_target({"target": str(tmp_path / "elsewhere"), "url": "https://github.com/OWASP/NodeGoat"})
    m._ensure_target({"target": ".targets/NodeGoat", "url": "https://github.com/OWASP/NodeGoat"})
    argv, kw = calls[0]
    assert argv[:5] == ["git", "clone", "--depth", "1", "--"] and kw["timeout"] and kw["env"]["GIT_TERMINAL_PROMPT"] == "0"
