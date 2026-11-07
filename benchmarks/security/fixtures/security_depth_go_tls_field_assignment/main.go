package main
import ("net/http"; "crypto/tls")
func handler(w http.ResponseWriter, r *http.Request) {
  cfg := &tls.Config{}; cfg.InsecureSkipVerify = true; _ = cfg
}
func main() {}
