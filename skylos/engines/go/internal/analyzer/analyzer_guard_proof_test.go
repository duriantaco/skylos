package analyzer

import "testing"

const guardProofPrelude = `package main
import (
    "database/sql"
    "fmt"
    "net/http"
    "net/url"
    "os"
    "os/exec"
    "path"
    "path/filepath"
    "strings"
)
var db *sql.DB
var root = "/srv/files"
var allowed = map[string]bool{"/home": true}
`

func TestPathSanitizersDoNotSanitizeOtherSinks(t *testing.T) {
	cases := []struct {
		name, body, rule string
		want             []string
	}{
		{"basename program", `func H(w http.ResponseWriter, r *http.Request) { exec.Command(filepath.Base(r.FormValue("bin")), "-c", r.FormValue("script")).Run() }`, "SKY-G212", []string{"CRITICAL"}},
		{"basename program through local", `func H(w http.ResponseWriter, r *http.Request) { bin := filepath.Base(r.FormValue("bin")); exec.Command(bin).Run() }`, "SKY-G212", []string{"CRITICAL"}},
		{"basename shell command", `func H(w http.ResponseWriter, r *http.Request) { exec.Command("sh", "-c", filepath.Base(r.FormValue("script"))).Run() }`, "SKY-G212", []string{"CRITICAL"}},
		{"basename host", `func H(w http.ResponseWriter, r *http.Request) { http.Get("http://" + filepath.Base(r.FormValue("host"))) }`, "SKY-G216", []string{"CRITICAL"}},
		{"path basename host through helper", `func fetch(host string) { http.Get("http://" + host) }; func H(w http.ResponseWriter, r *http.Request) { host := path.Base(r.FormValue("host")); fetch(host) }`, "SKY-G216", []string{"CRITICAL"}},
		{"basename SQL text", `func H(w http.ResponseWriter, r *http.Request) { db.Query("SELECT * FROM users WHERE name='" + filepath.Base(r.FormValue("name")) + "'") }`, "SKY-G211", []string{"CRITICAL"}},
		{"basename redirect host", `func H(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "http://" + filepath.Base(r.FormValue("host")), 302) }`, "SKY-G220", []string{"HIGH"}},
		{"basename path", `func H(w http.ResponseWriter, r *http.Request) { os.ReadFile(filepath.Join(root, filepath.Base(r.FormValue("name")))) }`, "SKY-G215", nil},
		{"basename path through local", `func H(w http.ResponseWriter, r *http.Request) { name := filepath.Base(r.FormValue("name")); os.ReadFile(filepath.Join(root, name)) }`, "SKY-G215", nil},
		{"basename path through helper", `func read(name string) { os.ReadFile(filepath.Join(root, name)) }; func H(w http.ResponseWriter, r *http.Request) { read(filepath.Base(r.FormValue("name"))) }`, "SKY-G215", nil},
		{"fixed executable separate data", `func H(w http.ResponseWriter, r *http.Request) { exec.Command("/usr/bin/printf", "%s", filepath.Base(r.FormValue("data"))).Run() }`, "SKY-G212", nil},
		{"fixed URL host", `func H(w http.ResponseWriter, r *http.Request) { http.Get("https://example.com/" + filepath.Base(r.FormValue("name"))) }`, "SKY-G216", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertSeverities(t, severitiesFor(t, map[string]string{"main.go": guardProofPrelude + tc.body}, tc.rule), tc.want)
		})
	}
}

func TestRequestPathGuardsNeedDominatingProof(t *testing.T) {
	cases := []struct {
		name, body string
		safe       bool
	}{
		{"logging check", `name := r.FormValue("name"); if !filepath.IsLocal(name) { fmt.Print("unsafe") }; os.ReadFile(filepath.Join(root, name))`, false},
		{"check after sink", `name := r.FormValue("name"); os.ReadFile(filepath.Join(root, name)); if !filepath.IsLocal(name) { return }`, false},
		{"wrong branch", `name := r.FormValue("name"); if filepath.IsLocal(name) { return }; os.ReadFile(filepath.Join(root, name))`, false},
		{"reassignment", `name := r.FormValue("name"); if !filepath.IsLocal(name) { return }; name = r.FormValue("other"); os.ReadFile(filepath.Join(root, name))`, false},
		{"conditional reassign", `name := r.FormValue("name"); if !filepath.IsLocal(name) { return }; if r.FormValue("change") != "" { name = r.FormValue("other") }; os.ReadFile(filepath.Join(root, name))`, false},
		{"wrong variable", `name := r.FormValue("name"); other := r.FormValue("other"); if !filepath.IsLocal(other) { return }; os.ReadFile(filepath.Join(root, name))`, false},
		{"request receiver not a value proof", `if !filepath.IsLocal(r.FormValue("name")) { return }; os.ReadFile(r.FormValue("other"))`, false},
		{"unrelated closure", `name := r.FormValue("name"); _ = func() { if !filepath.IsLocal(name) { return } }; os.ReadFile(filepath.Join(root, name))`, false},
		{"closure overwrites checked value", `name := r.FormValue("name"); if !filepath.IsLocal(name) { return }; change := func() { name = r.FormValue("other") }; change(); os.ReadFile(filepath.Join(root, name))`, false},
		{"prefix sibling directory", `p := filepath.Join(root, r.FormValue("name")); if !strings.HasPrefix(p, root) { return }; os.ReadFile(p)`, false},
		{"prefix before cleaning", `p := root + "/" + r.FormValue("name"); if !strings.HasPrefix(p, root + "/") { return }; os.ReadFile(p)`, false},
		{"prefix check logs", `p := filepath.Join(root, r.FormValue("name")); if !strings.HasPrefix(p, root + "/") { fmt.Print("unsafe") }; os.ReadFile(p)`, false},
		{"relative error ignored", `p := filepath.Join(root, r.FormValue("name")); rel, _ := filepath.Rel(root, p); if strings.HasPrefix(rel, "..") { return }; os.ReadFile(p)`, false},
		{"relative check logs", `p := filepath.Join(root, r.FormValue("name")); rel, err := filepath.Rel(root, p); if err != nil || strings.HasPrefix(rel, "..") { fmt.Print("unsafe") }; os.ReadFile(p)`, false},
		{"OR does not require local", `name := r.FormValue("name"); if filepath.IsLocal(name) || r.FormValue("flag") != "" { os.ReadFile(filepath.Join(root,name)) }`, false},
		{"guarded value changed by helper", `name := r.FormValue("name"); if !filepath.IsLocal(name) { return }; os.ReadFile(strings.ReplaceAll(name,"safe","../secret"))`, false},
		{"traversal appended after guard", `name := r.FormValue("name"); if !filepath.IsLocal(name) { return }; os.ReadFile(filepath.Join(root,name,"../../secret"))`, false},
		{"address escapes after guard", `name := r.FormValue("name"); if !filepath.IsLocal(name) { return }; fmt.Print(&name); os.ReadFile(filepath.Join(root,name))`, false},
		{"guard in loop may never run", `name := r.FormValue("name"); for r.FormValue("flag") != "" { if !filepath.IsLocal(name) { return } }; os.ReadFile(filepath.Join(root,name))`, false},
		{"guard in deferred closure", `name := r.FormValue("name"); defer func() { if !filepath.IsLocal(name) { return } }(); os.ReadFile(filepath.Join(root,name))`, false},
		{"fake IsLocal provider", `name := r.FormValue("name"); filepath := struct{IsLocal func(string)bool}{func(string)bool{return true}}; if !filepath.IsLocal(name) { return }; os.ReadFile(name)`, false},
		{"fake prefix provider", `p := filepath.Join(root,r.FormValue("name")); strings := struct{HasPrefix func(string,string)bool}{func(string,string)bool{return true}}; if !strings.HasPrefix(p,root+"/") { return }; os.ReadFile(p)`, false},
		{"tainted directory boundary", `p := filepath.Join(root,r.FormValue("name")); base := r.FormValue("root")+"/"; if !strings.HasPrefix(p,base) { return }; os.ReadFile(p)`, false},
		{"boolean proof made before write", `name := r.FormValue("name"); local := filepath.IsLocal(name); name=r.FormValue("other"); if !local {return}; os.ReadFile(filepath.Join(root,name))`, false},
		{"true rejection", `name := r.FormValue("name"); if !filepath.IsLocal(name) { return }; os.ReadFile(filepath.Join(root, name))`, true},
		{"sink in passing branch", `name := r.FormValue("name"); if filepath.IsLocal(name) { os.ReadFile(filepath.Join(root, name)) }`, true},
		{"else rejection", `name := r.FormValue("name"); if filepath.IsLocal(name) {} else { return }; os.ReadFile(filepath.Join(root, name))`, true},
		{"constant fallback", `name := r.FormValue("name"); if !filepath.IsLocal(name) { name = "default.txt" }; os.ReadFile(filepath.Join(root, name))`, true},
		{"separator prefix", `p := filepath.Join(root, r.FormValue("name")); if !strings.HasPrefix(p, root + "/") { return }; os.ReadFile(p)`, true},
		{"relative rejection", `p := filepath.Join(root, r.FormValue("name")); rel, err := filepath.Rel(root, p); if err != nil || strings.HasPrefix(rel, "..") { return }; os.ReadFile(p)`, true},
		{"boolean guard alias", `name := r.FormValue("name"); local := filepath.IsLocal(name); if !local { return }; os.ReadFile(filepath.Join(root, name))`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := "func H(w http.ResponseWriter, r *http.Request) { " + tc.body + " }"
			var want []string
			if !tc.safe {
				want = []string{"HIGH"}
			}
			assertSeverities(t, severitiesFor(t, map[string]string{"main.go": guardProofPrelude + body}, "SKY-G215"), want)
		})
	}
}

func TestRedirectGuardsNeedDominatingProof(t *testing.T) {
	cases := []struct {
		name, body string
		safe       bool
	}{
		{"logging comparison", `next := r.FormValue("next"); if next == "/home" { fmt.Print("home") }; http.Redirect(w, r, next, 302)`, false},
		{"check after sink", `next := r.FormValue("next"); http.Redirect(w, r, next, 302); if next != "/home" { return }`, false},
		{"wrong branch", `next := r.FormValue("next"); if next == "/home" { return }; http.Redirect(w, r, next, 302)`, false},
		{"reassignment", `next := r.FormValue("next"); if next != "/home" { return }; next = r.FormValue("other"); http.Redirect(w, r, next, 302)`, false},
		{"unrelated index", `next := r.FormValue("next"); values := map[string]bool{}; if values[next] { fmt.Print("found") }; http.Redirect(w, r, next, 302)`, false},
		{"tainted allowlist", `next := r.FormValue("next"); allowed := map[string]bool{r.FormValue("allow"): true}; if !allowed[next] { return }; http.Redirect(w, r, next, 302)`, false},
		{"mutable literal allowlist", `next := r.FormValue("next"); list := map[string]bool{"/home":true}; list[r.FormValue("allow")] = true; if !list[next] { return }; http.Redirect(w, r, next, 302)`, false},
		{"parsed host logs", `next := r.FormValue("next"); u, err := url.Parse(next); if err != nil || u.Host != "" { fmt.Print("unsafe") }; http.Redirect(w, r, next, 302)`, false},
		{"IsAbs alone permits network path", `next := r.FormValue("next"); u, _ := url.Parse(next); if u.IsAbs() { return }; http.Redirect(w, r, next, 302)`, false},
		{"unrelated closure", `next := r.FormValue("next"); _ = func() { if next != "/home" { return } }; http.Redirect(w, r, next, 302)`, false},
		{"aliased mutable allowlist", `next := r.FormValue("next"); list := map[string]bool{"/home":true}; alias:=list; alias[next]=true; if !list[next] {return}; http.Redirect(w,r,next,302)`, false},
		{"checked value changed by helper", `next := r.FormValue("next"); if next!="/home" {return}; http.Redirect(w,r,strings.ReplaceAll(next,"/home",r.FormValue("other")),302)`, false},
		{"fake slash provider", `next := r.FormValue("next"); strings:=struct{HasPrefix func(string,string)bool}{func(string,string)bool{return true}}; if !strings.HasPrefix(next,"/") || strings.HasPrefix(next,"//") {return}; http.Redirect(w,r,next,302)`, false},
		{"shadowed panic returns", `next:=r.FormValue("next"); panic:=func(string){}; if next!="/home" {panic("reject")}; http.Redirect(w,r,next,302)`, false},
		{"true literal rejection", `next := r.FormValue("next"); if next != "/home" { return }; http.Redirect(w, r, next, 302)`, true},
		{"sink in passing branch", `next := r.FormValue("next"); if next == "/home" { http.Redirect(w, r, next, 302) }`, true},
		{"literal fallback", `next := r.FormValue("next"); if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") { next = "/" }; http.Redirect(w, r, next, 302)`, true},
		{"single slash rejecting guard", `next := r.FormValue("next"); if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") { return }; http.Redirect(w, r, next, 302)`, true},
		{"literal map allowlist", `next := r.FormValue("next"); if !allowed[next] { return }; http.Redirect(w, r, next, 302)`, true},
		{"parsed host rejection alone permits scheme", `next := r.FormValue("next"); u, err := url.Parse(next); if err != nil || u.Host != "" { return }; http.Redirect(w, r, next, 302)`, false},
		{"parsed host and scheme rejection", `next := r.FormValue("next"); u, err := url.Parse(next); if err != nil || u.Host != "" || u.Scheme!="" { return }; http.Redirect(w, r, next, 302)`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := "func H(w http.ResponseWriter, r *http.Request) { " + tc.body + " }"
			var want []string
			if !tc.safe {
				want = []string{"HIGH"}
			}
			assertSeverities(t, severitiesFor(t, map[string]string{"main.go": guardProofPrelude + body}, "SKY-G220"), want)
		})
	}
}

func TestCleanedAbsolutePathsStayUnderJoinedBase(t *testing.T) {
	cases := []struct {
		name, body string
		safe       bool
	}{
		{"rooted arbitrary input", `name:=r.FormValue("name");os.ReadFile(filepath.Join(root,filepath.Clean("/"+name)))`, true},
		{"native HTTP URL path", `p:=filepath.Join(root,filepath.Clean(r.URL.Path));if !strings.HasPrefix(p,root){return};os.ReadFile(p)`, true},
		{"native URL pointer alias", `u:=r.URL;os.ReadFile(filepath.Join(root,filepath.Clean(u.Path)))`, true},
		{"native receiver alias", `alias:=r;os.ReadFile(filepath.Join(root,filepath.Clean(alias.URL.Path)))`, true},
		{"arbitrary form input remains relative", `p:=filepath.Join(root,filepath.Clean(r.FormValue("name")));if !strings.HasPrefix(p,root){return};os.ReadFile(p)`, false},
		{"visible URL Path mutation", `r.URL.Path=r.FormValue("name");os.ReadFile(filepath.Join(root,filepath.Clean(r.URL.Path)))`, false},
		{"URL pointer alias mutation", `u:=r.URL;u.Path=r.FormValue("name");os.ReadFile(filepath.Join(root,filepath.Clean(r.URL.Path)))`, false},
		{"receiver alias mutation", `alias:=r;alias.URL.Path=r.FormValue("name");os.ReadFile(filepath.Join(root,filepath.Clean(r.URL.Path)))`, false},
		{"URL replacement", `r.URL=&url.URL{Path:r.FormValue("name")};os.ReadFile(filepath.Join(root,filepath.Clean(r.URL.Path)))`, false},
		{"request helper escape", `rewriteRequest(r);os.ReadFile(filepath.Join(root,filepath.Clean(r.URL.Path)))`, false},
		{"URL helper escape", `rewriteURL(r.URL);os.ReadFile(filepath.Join(root,filepath.Clean(r.URL.Path)))`, false},
		{"URL helper in assignment", `value:=rewriteURL(r.URL);_ = value;os.ReadFile(filepath.Join(root,filepath.Clean(r.URL.Path)))`, false},
		{"URL helper in declaration", `var value=rewriteURL(r.URL);_ = value;os.ReadFile(filepath.Join(root,filepath.Clean(r.URL.Path)))`, false},
		{"Clean result not used", `_ = filepath.Clean(r.URL.Path);os.ReadFile(filepath.Join(root,r.URL.Path))`, false},
		{"unsafe sibling after absolute Clean", `os.ReadFile(filepath.Join(root,filepath.Clean("/"+r.FormValue("name")),"../../secret"))`, false},
		{"empty base is not a directory boundary", `os.ReadFile(filepath.Join("",filepath.Clean("/"+r.FormValue("name"))))`, false},
		{"filesystem root is not a restricted boundary", `os.ReadFile(filepath.Join("/",filepath.Clean("/"+r.FormValue("name"))))`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var want []string
			if !tc.safe {
				want = []string{"HIGH"}
			}
			helpers := `func rewriteRequest(r *http.Request){r.URL.Path="../files-secret"};func rewriteURL(u *url.URL)string{u.Path="../files-secret";return "changed"};`
			assertSeverities(t, severitiesFor(t, map[string]string{"main.go": guardProofPrelude + helpers + "func H(w http.ResponseWriter,r *http.Request){" + tc.body + "}"}, "SKY-G215"), want)
		})
	}
}
