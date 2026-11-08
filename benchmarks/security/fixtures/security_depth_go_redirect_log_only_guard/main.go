package demo
import ("net/http"; "log")
func H(w http.ResponseWriter, r *http.Request) { dest := r.FormValue("next"); if dest == "/home" { log.Print("home") }; http.Redirect(w, r, dest, 302) }
