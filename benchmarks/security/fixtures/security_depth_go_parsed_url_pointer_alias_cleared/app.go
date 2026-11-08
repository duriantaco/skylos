package review
import (
"net/http"
"net/url"
)
func Handler(w http.ResponseWriter,r *http.Request) {
next := r.FormValue("next"); u,err := url.Parse(next); if err != nil {return}; alias := u; alias.Host=""; alias.Scheme=""; if u.Host!="" || u.Scheme!="" {return}; http.Redirect(w,r,next,302)
}
