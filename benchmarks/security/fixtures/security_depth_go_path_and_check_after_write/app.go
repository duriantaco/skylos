package review
import (
"net/http"
"os"
"path/filepath"
)
func overwrite(dst *string, value string) bool { *dst = value; return true }
func Handler(w http.ResponseWriter,r *http.Request) {
name := r.FormValue("name"); if overwrite(&name,r.FormValue("replacement")) && filepath.IsLocal(name) { os.ReadFile(filepath.Join("/srv/files",name)) }
}
