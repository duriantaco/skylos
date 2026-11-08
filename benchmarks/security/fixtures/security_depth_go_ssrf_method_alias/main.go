package main
import ("net/http")
func handler(w http.ResponseWriter, r *http.Request) {
  c := &http.Client{}; fetch := c.Get; fetch(r.FormValue("url"))
}
func main() {}
