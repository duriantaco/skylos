package main

import "net/http"

func remember(w http.ResponseWriter, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: token, Path: "/", Secure: secure, HttpOnly: false})
}

func main() {}
