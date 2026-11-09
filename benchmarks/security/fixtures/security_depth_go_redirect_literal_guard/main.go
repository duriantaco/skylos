package demo
import ("net/http")
func H(w http.ResponseWriter, r *http.Request) { dest := r.FormValue("next"); if dest != "/home" { return }; http.Redirect(w, r, dest, 302) }
