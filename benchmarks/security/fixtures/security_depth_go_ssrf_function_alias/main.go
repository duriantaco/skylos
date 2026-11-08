package main
import ("net/http")
func handler(w http.ResponseWriter, r *http.Request) {
  fetch := http.Get; fetch(r.FormValue("url"))
}
func main() {}
