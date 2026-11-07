package review
import (
"net/http"
"os"
"path/filepath"
)
func Handler(w http.ResponseWriter,r *http.Request) {
name := r.FormValue("name"); local := false; name,local = r.FormValue("replacement"),filepath.IsLocal(name); if !local {return}; os.ReadFile(filepath.Join("/srv/files",name))
}
