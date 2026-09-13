"""Scanner and shell subprocess output is decoded as UTF-8 with replacement — never the Windows cp1252 default, which
killed the reader thread on a 0x81 byte from semgrep and turned its stdout into None (card 50)."""

import sys

import pytest

from scanner.adapter.scanners import osv, process
from scanner.adapter.tools.code.shell import run_shell

EMIT = [sys.executable, "-c", "import sys; sys.stdout.buffer.write(bytes([0x81, 0xFF]) + b' ok ' + bytes([0xD0, 0xBF]))"]  # invalid cp1252 + valid utf-8


def test_run_cmd_survives_non_cp1252_bytes(tmp_path):
    assert process.run_cmd(EMIT, tmp_path).endswith(" ok п")


def test_shell_tool_survives_non_cp1252_bytes(tmp_path):
    out = run_shell(tmp_path, " ".join(f'"{a}"' if " " in a else a for a in EMIT))
    assert out["exit_code"] == 0 and "ok" in out["output"]


def test_osv_decodes_utf8(tmp_path, monkeypatch):
    seen = {}

    def fake_run(cmd, **kw):
        seen.update(kw)
        raise RuntimeError("stop here")

    (tmp_path / "go.mod").write_text("module t\n")
    monkeypatch.setattr(osv.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError):
        osv.run(tmp_path)
    assert seen["encoding"] == "utf-8" and seen["errors"] == "replace"
