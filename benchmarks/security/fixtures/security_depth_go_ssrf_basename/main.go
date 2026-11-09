package demo
import ("net/http"; "path/filepath")
func H(w http.ResponseWriter, r *http.Request) { http.Get("http://" + filepath.Base(r.FormValue("host"))) }
