package main
import ("net/http")
type Request = http.Request
func handler(w http.ResponseWriter, r *Request) {
  http.Get(r.FormValue("url"))
}
func main() {}
