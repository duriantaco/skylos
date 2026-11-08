package review
import (
"net/http"
)
func overwrite(dst *string, value string) bool { *dst = value; return true }
func Handler(w http.ResponseWriter,r *http.Request) {
next := r.FormValue("next"); if next == "/home" && overwrite(&next,r.FormValue("replacement")) { http.Redirect(w,r,next,302) }
}
