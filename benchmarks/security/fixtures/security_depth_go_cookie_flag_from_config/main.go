package main

import "net/http"

type settings struct{ TLS bool }

func remember(w http.ResponseWriter, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: token, Path: "/", Secure: secure, HttpOnly: true})
}

func refresh(w http.ResponseWriter, r *http.Request, cfg settings) {
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: r.FormValue("value"), Secure: cfg.TLS, HttpOnly: true})
	http.SetCookie(w, &http.Cookie{Name: "seen", Value: "1", Secure: r.TLS != nil, HttpOnly: true})
}

func main() {}
