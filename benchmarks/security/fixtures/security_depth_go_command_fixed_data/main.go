package demo
import ("net/http"; "os/exec")
func H(w http.ResponseWriter, r *http.Request) { exec.Command("/usr/bin/printf", "%s", r.FormValue("value")).Run() }
