package main

import "net/http"

func main() {
	http.HandleFunc("/health", healthHandler)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte(formatStatus("ok")))
	_ = r
}

func formatStatus(status string) string {
	return status
}

func unusedReconciler() string {
	return "stale"
}
