"""Static dominance check for the Critic: does a control line dominate the sink line?"""

from pathlib import Path

import pytest

from scanner.adapter.dominance import check, make_check_dominance
from scanner.core.ports import Symbol

GO = """package main

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if !valid(name) {
		http.Error(w, "bad", 400)
		return
	}
	q := prepare(name)
	rows, _ := db.Query(q, name)
	_ = rows
}

func other() {
	x := clean("a")
	_ = x
}
"""

GO_BRANCHES = """package main

func h(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if strict {
		name = sanitize(name)
	} else {
		name = strings.TrimSpace(name)
	}
	db.Query("SELECT " + name)
	for i := 0; i < 3; i++ {
		db.Exec("x" + name)
	}
	name = escape(name)
}
"""

PY = """import subprocess


def ping(host):
    if not host.isalnum():
        raise ValueError("bad host")
    cmd = "ping -c1 " + host
    return subprocess.check_output(cmd, shell=True)


def read(path):
    try:
        path = normalize(path)
    except ValueError:
        path = "default"
    return open(path).read()


def loop(items):
    items = [clean(i) for i in items]
    for i in items:
        run(i)
"""

JS = """function render(req, res) {
  const q = req.query.q;
  if (!q) { return res.status(400).send("no"); }
  const safe = escapeHtml(q);
  res.send("<div>" + safe + "</div>");
}
"""


def lines(src):
    return src.splitlines()


def test_parameterized_control_before_sink_dominates():
    r = check(lines(GO), "go", sink_line=10, control_line=9)
    assert r["dominates"] and r["function"] == "handler" and r["control_depth"] == r["sink_depth"]


def test_guard_clause_dominates_even_when_nested():
    r = check(lines(GO), "go", sink_line=10, control_line=6)  # inside `if !valid { ... return }`
    assert r["dominates"] and r["guard"]


def test_control_in_skippable_if_does_not_dominate():
    r = check(lines(GO_BRANCHES), "go", sink_line=10, control_line=6)
    assert not r["dominates"] and r["control_depth"] > r["sink_depth"]


def test_control_in_else_branch_does_not_dominate():
    r = check(lines(GO_BRANCHES), "go", sink_line=10, control_line=8)
    assert not r["dominates"] and "else" in r["reason"]


def test_control_after_sink_does_not_dominate():
    r = check(lines(GO_BRANCHES), "go", sink_line=10, control_line=14)
    assert not r["dominates"] and "after" in r["reason"]


def test_control_in_other_function_does_not_dominate():
    r = check(lines(GO), "go", sink_line=10, control_line=15)
    assert not r["dominates"] and "function" in r["reason"]


def test_control_before_loop_dominates_sink_inside_loop():
    r = check(lines(GO_BRANCHES), "go", sink_line=12, control_line=4)
    assert r["dominates"]


def test_python_guard_and_except_branch():
    src = lines(PY)
    assert check(src, "python", sink_line=8, control_line=6)["dominates"]  # raise-guard before sink
    assert check(src, "python", sink_line=8, control_line=7)["dominates"]  # plain statement before sink
    r = check(src, "python", sink_line=16, control_line=15)  # `path = "default"` inside except
    assert not r["dominates"] and "except" in r["reason"]
    assert check(src, "python", sink_line=22, control_line=20)["dominates"]  # before the loop


def test_js_guard_with_res_status_send():
    src = lines(JS)
    assert check(src, "javascript", sink_line=5, control_line=3)["dominates"]
    assert check(src, "javascript", sink_line=5, control_line=4)["dominates"]


def test_symbols_from_index_define_function_ranges():
    syms = [Symbol(name="handler", kind="function", file="m.go", line=3, end_line=12),
            Symbol(name="other", kind="function", file="m.go", line=14, end_line=17)]
    r = check(lines(GO), "go", sink_line=10, control_line=15, symbols=syms)
    assert not r["dominates"] and r["function"] == "handler"


def test_tool_factory_confines_paths_and_never_raises(tmp_path):
    (tmp_path / "m.go").write_text(GO)

    class Idx:
        def symbols(self, file):
            raise RuntimeError("no index")

    tool = make_check_dominance(tmp_path, Idx())
    assert tool("m.go", 10, 9)["dominates"] is True
    assert tool("../etc/passwd", 1, 1)["status"] == "error"
    assert tool("m.go", 999, 1)["status"] == "error"
    assert tool.__doc__ and "dominates" in tool.__doc__


@pytest.mark.parametrize("bad", [("m.go", 0, 1), ("m.go", 1, 0)])
def test_bad_lines(tmp_path, bad):
    (tmp_path / "m.go").write_text(GO)
    assert make_check_dominance(tmp_path, None)(*bad)["status"] == "error"


def test_unknown_language_falls_back_to_braces(tmp_path):
    p = tmp_path / "x.php"
    p.write_text("<?php\nfunction f($a) {\n  $a = clean($a);\n  run($a);\n}\n")
    assert make_check_dominance(Path(tmp_path), None)("x.php", 4, 3)["dominates"]


def test_check_dominance_refuses_huge_files(tmp_path, monkeypatch):
    from scanner.adapter import fs
    from scanner.adapter.dominance import make_check_dominance
    (tmp_path / "big.go").write_text("package main\n" + "x" * 100)
    monkeypatch.setattr(fs, "FILE_CAP", 50)
    out = make_check_dominance(tmp_path, None)("big.go", 2, 1)
    assert out["status"] == "error" and "larger" in out["reason"]
