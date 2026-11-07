package analyzer

import "testing"

// These source contracts were independently labelled before their first scans.
func TestGuardProofReviewRegressions(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		rule  string
		safe  bool
	}{
		{"path-and-late-write", map[string]string{"main.go": `package review
import (
"net/http"
"os"
"path/filepath"
)
func overwrite(dst *string, value string) bool { *dst = value; return true }
func Handler(w http.ResponseWriter,r *http.Request) {
name := r.FormValue("name"); if filepath.IsLocal(name) && overwrite(&name,r.FormValue("replacement")) { os.ReadFile(filepath.Join("/srv/files",name)) }
}
`}, "SKY-G215", false},
		{"path-and-check-after-write", map[string]string{"main.go": `package review
import (
"net/http"
"os"
"path/filepath"
)
func overwrite(dst *string, value string) bool { *dst = value; return true }
func Handler(w http.ResponseWriter,r *http.Request) {
name := r.FormValue("name"); if overwrite(&name,r.FormValue("replacement")) && filepath.IsLocal(name) { os.ReadFile(filepath.Join("/srv/files",name)) }
}
`}, "SKY-G215", true},
		{"redirect-and-late-write", map[string]string{"main.go": `package review
import (
"net/http"
)
func overwrite(dst *string, value string) bool { *dst = value; return true }
func Handler(w http.ResponseWriter,r *http.Request) {
next := r.FormValue("next"); if next == "/home" && overwrite(&next,r.FormValue("replacement")) { http.Redirect(w,r,next,302) }
}
`}, "SKY-G220", false},
		{"redirect-and-check-after-write", map[string]string{"main.go": `package review
import (
"net/http"
)
func overwrite(dst *string, value string) bool { *dst = value; return true }
func Handler(w http.ResponseWriter,r *http.Request) {
next := r.FormValue("next"); if overwrite(&next,r.FormValue("replacement")) && next == "/home" { http.Redirect(w,r,next,302) }
}
`}, "SKY-G220", true},
		{"parallel-old-check-new-value", map[string]string{"main.go": `package review
import (
"net/http"
"os"
"path/filepath"
)
func Handler(w http.ResponseWriter,r *http.Request) {
name := r.FormValue("name"); local := false; name,local = r.FormValue("replacement"),filepath.IsLocal(name); if !local {return}; os.ReadFile(filepath.Join("/srv/files",name))
}
`}, "SKY-G215", false},
		{"parallel-same-value-check", map[string]string{"main.go": `package review
import (
"net/http"
"os"
"path/filepath"
)
func Handler(w http.ResponseWriter,r *http.Request) {
name := r.FormValue("name"); local := false; name,local = name,filepath.IsLocal(name); if !local {return}; os.ReadFile(filepath.Join("/srv/files",name))
}
`}, "SKY-G215", true},
		{"parsed-url-pointer-alias-cleared", map[string]string{"main.go": `package review
import (
"net/http"
"net/url"
)
func Handler(w http.ResponseWriter,r *http.Request) {
next := r.FormValue("next"); u,err := url.Parse(next); if err != nil {return}; alias := u; alias.Host=""; alias.Scheme=""; if u.Host!="" || u.Scheme!="" {return}; http.Redirect(w,r,next,302)
}
`}, "SKY-G220", false},
		{"parsed-url-unmodified", map[string]string{"main.go": `package review
import (
"net/http"
"net/url"
)
func Handler(w http.ResponseWriter,r *http.Request) {
next := r.FormValue("next"); u,err := url.Parse(next); if err != nil || u.Host!="" || u.Scheme!="" {return}; http.Redirect(w,r,next,302)
}
`}, "SKY-G220", true},
		{"inner-shadow-guard-outer-unsafe", map[string]string{"main.go": `package review
import (
"net/http"
"os"
"path/filepath"
)
func Handler(w http.ResponseWriter,r *http.Request) {
name := r.FormValue("name"); { name := r.FormValue("inner"); if !filepath.IsLocal(name) {return} }; os.ReadFile(filepath.Join("/srv/files",name))
}
`}, "SKY-G215", false},
		{"outer-guard-inner-shadow-safe", map[string]string{"main.go": `package review
import (
"net/http"
"os"
"path/filepath"
"fmt"
)
func Handler(w http.ResponseWriter,r *http.Request) {
name := r.FormValue("name"); if !filepath.IsLocal(name) {return}; { name := r.FormValue("inner"); fmt.Print(name) }; os.ReadFile(filepath.Join("/srv/files",name))
}
`}, "SKY-G215", true},
		{"parsed-host-only", map[string]string{"main.go": `package probe
import ("net/http"; "net/url")
func Handle(w http.ResponseWriter,r *http.Request) {next:=r.FormValue("next");u,err:=url.Parse(next);if err!=nil || u.Host!="" {return};http.Redirect(w,r,next,302)}
`}, "SKY-G220", false},
		{"parsed-host-and-scheme", map[string]string{"main.go": `package probe
import ("net/http"; "net/url")
func Handle(w http.ResponseWriter,r *http.Request) {next:=r.FormValue("next");u,err:=url.Parse(next);if err!=nil || u.Host!="" || u.Scheme!="" {return};http.Redirect(w,r,next,302)}
`}, "SKY-G220", true},
		{"global-allowlist-other-file-mutation", map[string]string{"policy.go": `package probe
func change(value string){allowed[value]=true}
`, "main.go": `package probe
import "net/http"
var allowed=map[string]bool{"/home":true}
func Handle(w http.ResponseWriter,r *http.Request) {next:=r.FormValue("next");change(next);if !allowed[next] {return};http.Redirect(w,r,next,302)}
`}, "SKY-G220", false},
		{"global-boundary-other-file-mutation", map[string]string{"policy.go": `package probe
func init(){root="/"}
`, "main.go": `package probe
import ("net/http"; "os"; "path/filepath"; "strings")
var root="/srv/files/"
func Handle(w http.ResponseWriter,r *http.Request) {name:=filepath.Clean(r.FormValue("name"));if !strings.HasPrefix(name,root) {return};os.ReadFile(name)}
`}, "SKY-G215", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var want []string
			if !tc.safe {
				want = []string{"HIGH"}
			}
			assertSeverities(t, severitiesFor(t, tc.files, tc.rule), want)
		})
	}
}
