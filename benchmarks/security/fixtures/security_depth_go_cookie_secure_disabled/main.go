package main
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) { http.SetCookie(w, &http.Cookie{Name: "sid", Value: r.FormValue("value"), Secure: false, HttpOnly: true}) }
func main() {}
