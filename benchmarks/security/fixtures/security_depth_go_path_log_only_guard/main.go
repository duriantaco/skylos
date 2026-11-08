package demo
import ("net/http"; "path/filepath"; "os"; "log")
func H(w http.ResponseWriter, r *http.Request) { name := r.FormValue("name"); if !filepath.IsLocal(name) { log.Print("unsafe") }; os.ReadFile(filepath.Join("/srv/files", name)) }
