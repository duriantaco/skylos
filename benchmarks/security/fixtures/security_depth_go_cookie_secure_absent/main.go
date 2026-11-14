package main

import "net/http"

func remember(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: r.FormValue("value"), Path: "/", HttpOnly: true})
}

func main() {}
