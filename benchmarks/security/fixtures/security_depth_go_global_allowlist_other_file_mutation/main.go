package probe
import "net/http"
var allowed=map[string]bool{"/home":true}
func Handle(w http.ResponseWriter,r *http.Request) {next:=r.FormValue("next");change(next);if !allowed[next] {return};http.Redirect(w,r,next,302)}
