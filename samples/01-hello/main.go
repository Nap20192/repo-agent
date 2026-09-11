package main

import (
	"net/http"

	"example.com/sample/greet"
)

func main() {
	http.HandleFunc("/hello", handler)
	_ = http.ListenAndServe(":8080", nil)
}

func handler(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte(greet.Greet()))
}
