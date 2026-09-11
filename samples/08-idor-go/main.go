// Образец IDOR: getOrder отдаёт чужой заказ по id, getMyOrder — контроль с проверкой владения.
package main

import (
	"encoding/json"
	"net/http"
)

type Order struct {
	ID     string
	UserID string
}

var orders = map[string]Order{
	"1": {ID: "1", UserID: "alice"},
	"2": {ID: "2", UserID: "bob"},
}

// currentUser — «сессия»: кто вызывает, берём из заголовка.
func currentUser(r *http.Request) string {
	return r.Header.Get("X-User")
}

func fetchOrder(id string) (Order, bool) {
	o, ok := orders[id]
	return o, ok
}

// getOrder — IDOR: id из запроса, владение не проверяется.
func getOrder(w http.ResponseWriter, r *http.Request) {
	order, ok := fetchOrder(r.URL.Query().Get("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	json.NewEncoder(w).Encode(order)
}

// getMyOrder — безопасный сосед: тот же fetch, но заказ сверяется с пользователем сессии.
func getMyOrder(w http.ResponseWriter, r *http.Request) {
	order, ok := fetchOrder(r.URL.Query().Get("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	if order.UserID != currentUser(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	json.NewEncoder(w).Encode(order)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/order", getOrder)
	mux.HandleFunc("/my/order", getMyOrder)
	http.ListenAndServe(":8080", mux)
}
