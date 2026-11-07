package demo
import ("net/http"; "path/filepath"; "os")
func H(w http.ResponseWriter, r *http.Request) { name := r.FormValue("name"); if !filepath.IsLocal(name) { return }; os.ReadFile(filepath.Join("/srv/files", name)) }
