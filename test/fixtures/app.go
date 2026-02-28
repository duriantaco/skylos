package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

// BAD: Hardcoded secret
const API_KEY = "sk-1234567890abcdef1234567890abcdef"

// BAD: SQL injection
func getUser(db *sql.DB, id string) {
	db.Query("SELECT * FROM users WHERE id = '" + id + "'")
}

// BAD: Command injection
func runCmd(input string) {
	exec.Command("sh", "-c", input).Run()
}

// BAD: Path traversal
func readFile(name string) {
	os.ReadFile("/data/" + name)
}

// BAD: SSRF
func fetch(url string) {
	http.Get(url)
}

// BAD: Weak crypto
func hash(s string) {
	md5.Sum([]byte(s))
}

// DEAD CODE - never called
func unusedFunc() {
	fmt.Println("never used")
}

var unusedVar = "dead"

func main() {
	fmt.Println("test")
}
