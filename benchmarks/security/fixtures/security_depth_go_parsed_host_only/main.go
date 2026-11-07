package probe
import ("net/http"; "net/url")
func Handle(w http.ResponseWriter,r *http.Request) {next:=r.FormValue("next");u,err:=url.Parse(next);if err!=nil || u.Host!="" {return};http.Redirect(w,r,next,302)}
