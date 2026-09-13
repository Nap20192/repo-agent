package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

var db *sql.DB

func main() {
	http.HandleFunc("/search", searchHandler) // SQL injection
	http.HandleFunc("/ping", pingHandler)      // command injection
	http.HandleFunc("/safe", safeHandler)      // parameterized — control
	_ = http.ListenAndServe(":8080", nil)
}

// searchHandler concatenates user input into a SQL query — CWE-89.
func searchHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, _ := db.Query("SELECT id FROM users WHERE name = '" + name + "'")
	_ = rows
	fmt.Fprintln(w, "ok")
}

// pingHandler passes user input to a shell — CWE-78.
func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, _ := exec.Command("sh", "-c", "ping -c1 "+host).Output()
	_, _ = w.Write(out)
}

// safeHandler uses a parameterized query — no injection.
func safeHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, _ := db.Query("SELECT id FROM users WHERE name = $1", name)
	_ = rows
	fmt.Fprintln(w, "ok")
}
