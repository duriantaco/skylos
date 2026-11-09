package main
import ("fmt"; "net/http")
func handle(w http.ResponseWriter, r *http.Request) { w.Header().Set("Content-Type", "text/html"); fmt.Fprint(w, r.FormValue("body")) }
func main() {}
