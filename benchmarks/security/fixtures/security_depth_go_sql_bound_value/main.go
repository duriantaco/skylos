package main
import ("database/sql"; "net/http")
func handle(db *sql.DB, w http.ResponseWriter, r *http.Request) { db.Query("SELECT * FROM users WHERE name = ?", r.FormValue("name")) }
func main() {}
