package review
import (
"net/http"
"os"
"path/filepath"
)
func Handler(w http.ResponseWriter,r *http.Request) {
name := r.FormValue("name"); { name := r.FormValue("inner"); if !filepath.IsLocal(name) {return} }; os.ReadFile(filepath.Join("/srv/files",name))
}
