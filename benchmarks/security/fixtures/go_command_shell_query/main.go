package main

import (
	"net/http"
	"os/exec"
)

func checkout(w http.ResponseWriter, r *http.Request) {
	branch := r.URL.Query().Get("branch")
	_ = exec.Command("sh", "-c", "git checkout "+branch).Run()
}
