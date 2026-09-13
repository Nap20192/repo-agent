"""Card 48: the scan target comes from the user's message — a local directory or a https://github.com/<owner>/<repo>
URL cloned on demand into .targets/ (adapter.git.clone, app.target.resolve_target)."""

import subprocess
from pathlib import Path

import pytest

from scanner.adapter import git
from scanner.app.target import resolve_target


def test_clone_only_github_https_and_only_into_targets(tmp_path, monkeypatch):
    calls = []

    def fake_run(cmd, **kw):
        calls.append((cmd, kw))
        Path(cmd[-1]).mkdir(parents=True)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    dest = git.clone("https://github.com/Nap20192/bakery", into=tmp_path / ".targets")
    assert dest == tmp_path / ".targets" / "Nap20192-bakery" and dest.is_dir()
    cmd, kw = calls[0]
    assert cmd[:5] == ["git", "clone", "--depth", "1", "--"] and cmd[5] == "https://github.com/Nap20192/bakery"
    assert kw["env"]["GIT_TERMINAL_PROMPT"] == "0" and kw["check"] and kw["timeout"] == 300
    assert git.clone("https://github.com/Nap20192/bakery.git", into=tmp_path / ".targets") == dest and len(calls) == 1  # kept


@pytest.mark.parametrize("url", ["http://github.com/a/b", "https://gitlab.com/a/b", "ext::sh -c id", "file:///etc",
                                 "https://github.com/a/b/tree/main", "--upload-pack=x", "https://github.com/../x"])
def test_clone_refuses_everything_else(url, tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("must not run git"))
    with pytest.raises(ValueError):
        git.clone(url, into=tmp_path)


def test_resolve_target_path_url_prefix_and_errors(tmp_path, monkeypatch):
    d = tmp_path / "repo"
    d.mkdir()
    assert resolve_target(str(d)) == d.resolve()
    assert resolve_target(f"scan target: {d}") == d.resolve()  # the CLI's own message shape
    assert resolve_target(f"  {d}\n") == d.resolve()
    monkeypatch.setattr(git, "clone", lambda url, into=Path(".targets"): tmp_path / "cloned")
    assert resolve_target("https://github.com/o/r") == tmp_path / "cloned"
    with pytest.raises(ValueError, match="directory nor a https://github.com"):
        resolve_target("hello there")
    with pytest.raises(ValueError, match="directory nor a https://github.com"):
        resolve_target(str(tmp_path / "missing"))
    with pytest.raises(ValueError, match="say which"):
        resolve_target("")
