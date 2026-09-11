// Command govulnlab is a deliberately vulnerable Go web app — a test target for
// the bugfinder pipeline. Each handler is one CWE class from the v1 specialist
// set {89,78,22,918,79}, with a safe sibling or two so the verifier's
// false-positive resistance is exercised. Do NOT deploy — every "vuln" route is
// intentionally exploitable.
package main

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// db is left nil on purpose — the static analyzer only needs the call shapes,
// the app is never actually run.
var db *sql.DB

const baseDir = "/srv/files"

func main() {
	http.HandleFunc("/search", searchHandler)   // CWE-89 SQLi (vuln)
	http.HandleFunc("/search/safe", safeSearch) // CWE-89 safe (parameterized)
	http.HandleFunc("/ping", pingHandler)       // CWE-78 command injection (vuln)
	http.HandleFunc("/file", fileHandler)       // CWE-22 path traversal (vuln)
	http.HandleFunc("/file/safe", safeFile)     // CWE-22 safe (clean + prefix)
	http.HandleFunc("/fetch", fetchHandler)     // CWE-918 SSRF (vuln)
	http.HandleFunc("/greet", greetHandler)     // CWE-79 reflected XSS (vuln)
	http.ListenAndServe(":8080", nil)
}

// CWE-89: user input concatenated into the SQL string.
func searchHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, err := db.Query("SELECT id, email FROM users WHERE name = '" + name + "'")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	fmt.Fprintln(w, "ok")
}

// CWE-89 safe: bound parameter, no string building.
func safeSearch(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, err := db.Query("SELECT id, email FROM users WHERE name = $1", name)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	fmt.Fprintln(w, "ok")
}

// CWE-78: user input concatenated into a shell command.
func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, err := exec.Command("sh", "-c", "ping -c1 "+host).Output()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(out)
}

// CWE-22: user path joined to a base with no containment check — ".." escapes.
func fileHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("f")
	data, err := os.ReadFile(filepath.Join(baseDir, name))
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	w.Write(data)
}

// CWE-22 safe: clean, then confirm the result stays under baseDir.
func safeFile(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("f")
	clean := filepath.Clean(filepath.Join(baseDir, name))
	if !strings.HasPrefix(clean, baseDir+string(os.PathSeparator)) {
		http.Error(w, "forbidden", 403)
		return
	}
	data, err := os.ReadFile(clean)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	w.Write(data)
}

// CWE-918: server fetches an attacker-controlled URL, no allowlist.
func fetchHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

// CWE-79: reflected user input written into an HTML response unescaped.
func greetHandler(w http.ResponseWriter, r *http.Request) {
	name, _ := url.QueryUnescape(r.URL.Query().Get("name"))
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<html><body><h1>Hello, %s!</h1></body></html>", name)
}
