package main
import ("crypto/tls"; "net/http")
func client() *http.Client { return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: false}}} }
func main() {}
