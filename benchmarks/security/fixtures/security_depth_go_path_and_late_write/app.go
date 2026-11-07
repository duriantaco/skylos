package review
import (
"net/http"
"os"
"path/filepath"
)
func overwrite(dst *string, value string) bool { *dst = value; return true }
func Handler(w http.ResponseWriter,r *http.Request) {
name := r.FormValue("name"); if filepath.IsLocal(name) && overwrite(&name,r.FormValue("replacement")) { os.ReadFile(filepath.Join("/srv/files",name)) }
}
