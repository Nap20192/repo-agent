"""recon: deterministic sinks/auth/config inventory (Shannon pre-recon-code deliverables, no model)."""

from pathlib import Path

from scanner.adapter import recon
from scanner.core import Candidate

SAMPLE_JS = Path("samples/11-expressshop")
SAMPLE_GO = Path("samples/02-vulnshop")

JS = """const { exec } = require("child_process");
app.get("/s", isLoggedIn, (req, res) => {
  db.query("SELECT * FROM u WHERE n = '" + req.query.n + "'");
  res.send("<b>" + req.query.n + "</b>");
  fetch(req.body.url);
  res.sendFile(path.join(ROOT, req.query.f));
  eval(req.body.expr);
  res.redirect(req.query.next);
  User.find({ $where: "this.name == '" + req.query.n + "'" });
  const re = new RegExp(req.query.pat);
});
app.use(passport.authenticate("local"));
"""
PY = """from django.contrib.auth.decorators import login_required
@login_required
def v(request):
    cursor.execute("SELECT %s" % request.GET["q"])
    requests.get(request.GET["u"])
    open(os.path.join(BASE, request.GET["f"]))
    exec(request.POST["code"])
    re.compile(request.GET["p"])
    return render_template_string(request.GET["t"])
"""
GO = """package main
func h(w http.ResponseWriter, r *http.Request) {
	rows, _ := db.Query("SELECT 1 WHERE n = '" + name + "'")
	out, _ := exec.Command("sh", "-c", "ping "+host).Output()
	http.Get(userURL)
	os.Open(filepath.Join(root, r.URL.Query().Get("f")))
	http.Redirect(w, r, r.URL.Query().Get("to"), 302)
}
"""


def _target(tmp_path: Path) -> Path:
    (tmp_path / "app.js").write_text(JS)
    (tmp_path / "views.py").write_text(PY)
    (tmp_path / "main.go").write_text(GO)
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "env.js").write_text("module.exports = {}")
    (tmp_path / "Dockerfile").write_text("FROM node")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "x.test.js").write_text("eval(req.body.x); res.redirect(req.query.u);")
    return tmp_path


def test_sinks_per_class_with_file_line(tmp_path):
    m = recon.recon(_target(tmp_path), [Candidate(kind="entry", file="app.js", line=2, symbol="", route=["GET /s"])], ["javascript", "python", "go"])
    assert set(m) == {"sources", "sinks", "auth", "config_files"}
    assert set(m["sinks"]) == {"injection", "xss", "ssrf", "path", "eval", "redirect", "nosql", "regex"}
    s = m["sinks"]
    assert "app.js:3" in s["injection"] and "views.py:4" in s["injection"] and "main.go:3" in s["injection"]
    assert "app.js:4" in s["xss"] and "views.py:9" in s["xss"]
    assert "app.js:5" in s["ssrf"] and "views.py:5" in s["ssrf"] and "main.go:5" in s["ssrf"]
    assert "app.js:6" in s["path"] and "views.py:6" in s["path"] and "main.go:6" in s["path"]
    assert "app.js:7" in s["eval"] and "views.py:7" in s["eval"] and "main.go:4" in s["eval"]
    assert "app.js:8" in s["redirect"] and "main.go:7" in s["redirect"]
    assert "app.js:9" in s["nosql"]
    assert "app.js:10" in s["regex"] and "views.py:8" in s["regex"]
    assert m["sources"][0].file == "app.js"


def test_auth_guards_and_config_files_and_test_exclusion(tmp_path):
    m = recon.recon(_target(tmp_path), [], ["javascript", "python"])
    auth = " ".join(m["auth"])
    assert "app.js:2: isLoggedIn" in auth and "app.js:12: passport.authenticate" in auth and "views.py:2: login_required" in auth
    assert m["config_files"] == ["Dockerfile", "app.js", "config/env.js", "package.json"]
    assert not any(v.startswith("tests/") for vs in m["sinks"].values() for v in vs)  # fixtures never inventoried


def test_caps_and_never_raises(tmp_path, monkeypatch):
    (tmp_path / "big.js").write_text("\n".join("eval(x)" for _ in range(300)))
    monkeypatch.setattr(recon, "CLASS_CAP", 50)
    m = recon.recon(tmp_path, [], ["javascript"])
    assert len(m["sinks"]["eval"]) == 50
    assert recon.recon(tmp_path / "missing", [], ["javascript"])["sinks"]["eval"] == []  # no target → empty, no raise


def test_samples_have_known_sinks():
    if SAMPLE_JS.exists():
        s = recon.recon(SAMPLE_JS, [], ["javascript"])["sinks"]
        assert "server.js:13" in s["injection"] and "server.js:24" in s["eval"] and "server.js:32" in s["path"]
    if SAMPLE_GO.exists():
        s = recon.recon(SAMPLE_GO, [], ["go"])["sinks"]
        assert "main.go:22" in s["injection"] and "main.go:30" in s["eval"]
