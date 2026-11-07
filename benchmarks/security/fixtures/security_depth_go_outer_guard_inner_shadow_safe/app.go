package review
import (
"net/http"
"os"
"path/filepath"
"fmt"
)
func Handler(w http.ResponseWriter,r *http.Request) {
name := r.FormValue("name"); if !filepath.IsLocal(name) {return}; { name := r.FormValue("inner"); fmt.Print(name) }; os.ReadFile(filepath.Join("/srv/files",name))
}
