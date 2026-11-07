package main
import ("fmt"; "html"; "net/http")
func handle(w http.ResponseWriter, r *http.Request) { w.Header().Set("Content-Type", "text/html"); fmt.Fprint(w, html.EscapeString(r.FormValue("body"))) }
func main() {}
