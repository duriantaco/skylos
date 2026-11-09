package main
import ("net/http"; "os")
func handler(w http.ResponseWriter, r *http.Request) {
  read := os.ReadFile; read(r.FormValue("path"))
}
func main() {}
