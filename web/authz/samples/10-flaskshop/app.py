"""flaskshop — eval sample: five vulnerable handlers, each next to a safe neighbour that does the same job."""

import os
import shlex
import sqlite3
import subprocess

import requests
from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)
DB = sqlite3.connect(":memory:", check_same_thread=False)
FILES = os.path.realpath("/srv/files")
ALLOWED_HOSTS = {"api.example.com"}


@app.route("/search")
def search():  # CWE-89: user input concatenated into SQL
    name = request.args.get("name", "")
    rows = DB.execute("SELECT id FROM users WHERE name = '" + name + "'").fetchall()
    return str(rows)


@app.route("/search_safe")
def search_safe():  # parameterized — control
    name = request.args.get("name", "")
    rows = DB.execute("SELECT id FROM users WHERE name = ?", (name,)).fetchall()
    return str(rows)


@app.route("/ping")
def ping():  # CWE-78: user input in a shell command
    host = request.args.get("host", "")
    return subprocess.check_output("ping -c1 " + host, shell=True)


@app.route("/ping_safe")
def ping_safe():  # argv, no shell, quoted — control
    host = request.args.get("host", "")
    return subprocess.check_output(["ping", "-c1", shlex.quote(host)])


@app.route("/read")
def read():  # CWE-22: user-controlled path joined under the base dir
    name = request.args.get("f", "")
    with open(os.path.join(FILES, name)) as fh:
        return fh.read()


@app.route("/read_safe")
def read_safe():  # realpath + prefix check — control
    name = request.args.get("f", "")
    path = os.path.realpath(os.path.join(FILES, name))
    if not path.startswith(FILES + os.sep):
        return "forbidden", 403
    with open(path) as fh:
        return fh.read()


@app.route("/fetch")
def fetch():  # CWE-918: user-controlled URL fetched server-side
    url = request.args.get("url", "")
    return requests.get(url, timeout=3).text


@app.route("/fetch_safe")
def fetch_safe():  # allow-listed host — control
    host = request.args.get("host", "")
    if host not in ALLOWED_HOSTS:
        return "forbidden", 403
    return requests.get(f"https://{host}/status", timeout=3).text


@app.route("/hello")
def hello():  # CWE-79: user input reflected into HTML
    name = request.args.get("name", "")
    return "<h1>Hello " + name + "</h1>"


@app.route("/hello_safe")
def hello_safe():  # escaped — control
    name = request.args.get("name", "")
    return "<h1>Hello " + escape(name) + "</h1>"


if __name__ == "__main__":
    app.run()
