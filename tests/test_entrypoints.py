"""fs confinement and the per-language detector table."""

from scanner.adapter import fs
from scanner.adapter.entrypoints import DETECTORS, entry_points


def test_detectors_cover_every_language():
    assert set(DETECTORS) == set(fs.LANG_EXT.values())


def test_inside_rejects_symlink_escape(tmp_path):
    (tmp_path / "secret").write_text("x")
    t = tmp_path / "t"
    t.mkdir()
    (t / "ok.py").write_text("print(1)\n")
    (t / "link.py").symlink_to(tmp_path / "secret")
    assert fs.inside(t, "ok.py") is not None
    assert fs.inside(t, "link.py") is None and fs.inside(t, "../secret") is None
    assert [p.name for p in fs.files(t)] == ["ok.py"]


def test_entry_points_dispatch_per_language(tmp_path):
    (tmp_path / "a.go").write_text('func main() { http.HandleFunc("/x", h) }\n')
    (tmp_path / "b.py").write_text('@app.route("/y")\ndef y():\n    pass\n')
    (tmp_path / "c.js").write_text('app.get("/z", (req, res) => res.send(1));\n')
    (tmp_path / "d.php").write_text("<?php echo $_GET['q'];\n")
    got = {(c.file, c.line, c.symbol, tuple(c.route)) for c in entry_points(tmp_path)}
    assert got == {("a.go", 1, "h", ()), ("b.py", 2, "y", ()), ("c.js", 1, "", ("GET /z",)), ("d.php", 1, "", ("d.php",))}
