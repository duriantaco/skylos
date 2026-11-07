package demo
import ("net/http")
func H(w http.ResponseWriter, r *http.Request) { http.Get("http://" + r.FormValue("host")) }
