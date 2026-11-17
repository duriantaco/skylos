package analyzer

import "testing"

func TestCapturedNativeSinksAndLookalikes(t *testing.T) {
	cases := []struct {
		name, imports, extra, body, rule string
		want                             bool
	}{
		{"http function capture", `"net/http"`, "", `fetch:=http.Get; fetch(r.FormValue("url"))`, "SKY-G216", true},
		{"http capture fixed URL", `"net/http"`, "", `fetch:=http.Get; fetch("https://example.test/status")`, "SKY-G216", false},
		{"http method capture", `"net/http"`, "", `client:=&http.Client{}; fetch:=client.Get; fetch(r.FormValue("url"))`, "SKY-G216", true},
		{"source-owned method", `"net/http"`, `type local struct{};func (local) Get(s string){}`, `client:=local{}; fetch:=client.Get; fetch(r.FormValue("url"))`, "SKY-G216", false},
		{"package shadow", `"net/http"`, `type local struct{};func (local) Get(s string){}`, `http:=local{}; fetch:=http.Get; fetch(r.FormValue("url"))`, "SKY-G216", false},
		{"command capture", `"net/http";"os/exec"`, "", `launch:=exec.Command; launch("sh","-c",r.FormValue("cmd")).Run()`, "SKY-G212", true},
		{"command argv data", `"net/http";"os/exec"`, "", `launch:=exec.Command; launch("printf","%s",r.FormValue("cmd")).Run()`, "SKY-G212", false},
		{"path capture", `"net/http";"os"`, "", `read:=os.ReadFile; read(r.FormValue("path"))`, "SKY-G215", true},
		{"path capture fixed file", `"net/http";"os"`, "", `read:=os.ReadFile; read("/srv/public/info")`, "SKY-G215", false},
		{"native request alias", `"net/http"`, `type Request = http.Request`, `http.Get(r.FormValue("url"))`, "SKY-G216", true},
		{"native chained request alias", `"net/http"`, `type Original = http.Request;type Request = Original`, `http.Get(r.FormValue("url"))`, "SKY-G216", true},
		{"defined request lookalike", `"net/http"`, `type Request struct{};func (*Request) FormValue(s string)string{return "https://example.test"}`, `http.Get(r.FormValue("url"))`, "SKY-G216", false},
		{"TLS field assignment", `"net/http";"crypto/tls"`, "", `cfg:=&tls.Config{};cfg.InsecureSkipVerify=true`, "SKY-G210", true},
		{"TLS shadowed boolean", `"net/http";"crypto/tls"`, "", `true:=false;cfg:=&tls.Config{};cfg.InsecureSkipVerify=true`, "SKY-G210", false},
		{"TLS field false", `"net/http";"crypto/tls"`, "", `cfg:=&tls.Config{};cfg.InsecureSkipVerify=false`, "SKY-G210", false},
		{"TLS source-owned field", `"net/http"`, `type local struct{InsecureSkipVerify bool}`, `cfg:=&local{};cfg.InsecureSkipVerify=true`, "SKY-G210", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := "http.Request"
			if tc.name == "native request alias" || tc.name == "native chained request alias" || tc.name == "defined request lookalike" {
				request = "Request"
			}
			source := "package app\nimport(" + tc.imports + ")\n" + tc.extra + "\nfunc handler(w http.ResponseWriter,r *" + request + "){ " + tc.body + " }\n"
			found := false
			for _, rule := range analyzeGoSource(t, source) {
				if rule == tc.rule {
					found = true
				}
			}
			if found != tc.want {
				t.Fatalf("%s present=%v want=%v", tc.rule, found, tc.want)
			}
		})
	}
}
