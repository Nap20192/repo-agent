// expressshop — eval sample: vulnerable handlers next to safe neighbours; named and inline handlers.
const express = require("express");
const path = require("path");
const { exec, execFile } = require("child_process");
const db = require("./db");

const app = express();
app.use(express.json());
const ROOT = path.resolve(__dirname, "public");
const SAFE_HOSTS = new Set(["example.com"]);

function search(req, res) { // CWE-89: string-built query
  db.query("SELECT id FROM users WHERE name = '" + req.query.name + "'", (e, rows) => res.json(rows));
}

function searchSafe(req, res) { // parameterized — control
  db.query("SELECT id FROM users WHERE name = ?", [req.query.name], (e, rows) => res.json(rows));
}

app.get("/search", search);
app.get("/search_safe", searchSafe);

app.get("/ping", (req, res) => { // CWE-78: shell command from user input (inline handler)
  exec("ping -c1 " + req.query.host, (e, out) => res.send(out));
});

app.get("/ping_safe", (req, res) => { // argv, no shell — control
  execFile("ping", ["-c1", String(req.query.host)], (e, out) => res.send(out));
});

app.get("/file", (req, res) => { // CWE-22: user-controlled path under the public root
  res.sendFile(path.join(ROOT, req.query.f));
});

app.get("/file_safe", (req, res) => { // resolve + prefix check — control
  const p = path.resolve(ROOT, String(req.query.f));
  if (!p.startsWith(ROOT + path.sep)) return res.status(403).end();
  res.sendFile(p);
});

app.get("/go", (req, res) => { // CWE-601: open redirect
  res.redirect(req.query.next);
});

app.get("/go_safe", (req, res) => { // relative paths only — control
  const next = String(req.query.next || "/");
  res.redirect(next.startsWith("/") && !next.startsWith("//") ? next : "/");
});

app.post("/calc", (req, res) => { // CWE-95: eval on request body
  res.json({ total: eval(req.body.expr) });
});

app.post("/calc_safe", (req, res) => { // numeric parse — control
  res.json({ total: Number(req.body.expr) });
});

app.get("/fetch_safe", (req, res) => { // allow-listed host — control for SSRF
  const host = String(req.query.host);
  if (!SAFE_HOSTS.has(host)) return res.status(403).end();
  res.redirect("https://" + host + "/status");
});

app.listen(3000);
