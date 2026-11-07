package probe
import ("net/http"; "os"; "path/filepath"; "strings")
var root="/srv/files/"
func Handle(w http.ResponseWriter,r *http.Request) {name:=filepath.Clean(r.FormValue("name"));if !strings.HasPrefix(name,root) {return};os.ReadFile(name)}
