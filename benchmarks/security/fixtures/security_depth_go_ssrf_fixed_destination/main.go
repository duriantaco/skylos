package main
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) { http.Get("https://api.example.com/health") }
func main() {}
