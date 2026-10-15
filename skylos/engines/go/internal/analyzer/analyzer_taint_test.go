package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

const taintPrelude = `package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"

	"github.com/gin-gonic/gin"
)

type Config struct {
	URL  string
	Name string
}

var cfg Config
var flagURL = flag.String("url", "", "")

var _ = json.Marshal
var _ = fmt.Sprintf
var _ = net.Dial
var _ = os.Args
var _ = exec.Command
var _ *gin.Context

`

// ruleSeverities returns rule -> severities for one source file.
func ruleSeverities(t *testing.T, body string) map[string][]string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte(taintPrelude+body), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := New().AnalyzeDir(root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, finding := range findings {
		if finding.RuleID == "SKY-G212" || finding.RuleID == "SKY-G216" {
			got[finding.RuleID] = append(got[finding.RuleID], finding.Severity)
		}
	}
	return got
}

// Untrusted input (an incoming request or network data) reaching the URL or
// the command is reported.
func TestUntrustedInputReachesSSRFAndCommandSinks(t *testing.T) {
	cases := map[string]struct {
		body string
		rule string
		want string
	}{
		"X1 query to http.Get": {
			"func h(w http.ResponseWriter, r *http.Request) { http.Get(r.URL.Query().Get(\"u\")) }\n",
			"SKY-G216", "CRITICAL"},
		"X2 form value to sh -c": {
			"func h(w http.ResponseWriter, r *http.Request) { exec.Command(\"sh\", \"-c\", r.FormValue(\"cmd\")).Run() }\n",
			"SKY-G212", "CRITICAL"},
		"X3 form value as program": {
			"func h(w http.ResponseWriter, r *http.Request) { exec.Command(r.FormValue(\"bin\")).Run() }\n",
			"SKY-G212", "CRITICAL"},
		"X4 propagated through locals": {
			"func h(w http.ResponseWriter, r *http.Request) {\n\tu := r.FormValue(\"u\")\n\ttarget := \"http://\" + u + \"/x\"\n\thttp.NewRequest(\"GET\", target, nil)\n}\n",
			"SKY-G216", "CRITICAL"},
		"X5 decoded body": {
			"func h(w http.ResponseWriter, r *http.Request) {\n\tvar p struct{ URL string }\n\tjson.NewDecoder(r.Body).Decode(&p)\n\thttp.Get(p.URL)\n}\n",
			"SKY-G216", "CRITICAL"},
		"X6 same-file helper": {
			"func fetch(u string) { http.Get(u) }\n\nfunc h(w http.ResponseWriter, r *http.Request) { fetch(r.URL.Query().Get(\"u\")) }\n",
			"SKY-G216", "CRITICAL"},
		"X7 gin context": {
			"func h(c *gin.Context) { http.Get(c.Query(\"u\")) }\n",
			"SKY-G216", "CRITICAL"},
		"X8 network connection": {
			"func serve(conn net.Conn) {\n\tbuf := make([]byte, 512)\n\tn, _ := conn.Read(buf)\n\thttp.Get(string(buf[:n]))\n}\n",
			"SKY-G216", "CRITICAL"},
		"handler closure": {
			"func main() {\n\thttp.HandleFunc(\"/\", func(w http.ResponseWriter, r *http.Request) {\n\t\thttp.Get(r.Header.Get(\"X-Target\"))\n\t})\n}\n",
			"SKY-G216", "CRITICAL"},
		"N7 untainted variable in a shell": {
			"func run() { exec.Command(\"sh\", \"-c\", \"echo \"+cfg.Name).Run() }\n",
			"SKY-G212", "HIGH"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := ruleSeverities(t, tc.body)
			if len(got[tc.rule]) != 1 || got[tc.rule][0] != tc.want {
				t.Fatalf("want one %s %s, got %v", tc.want, tc.rule, got)
			}
		})
	}
}

// The program's own inputs (its binary, flags, config, loopback or fixed
// hosts) and argv without a shell are not SSRF or command injection.
func TestProgramInputsAreNotSSRFOrCommandInjection(t *testing.T) {
	cases := map[string]string{
		"N1 re-exec self":             "func run() { exec.Command(os.Args[0], \"run\").Run() }\n",
		"N2 os.Executable":            "func run() { self, _ := os.Executable(); exec.Command(self, \"version\").Run() }\n",
		"N3 argv without shell":       "func h(w http.ResponseWriter, r *http.Request) { exec.Command(\"git\", \"log\", r.FormValue(\"ref\")).Run() }\n",
		"N4 config URL":               "func run() { http.Get(cfg.URL) }\n",
		"N4 flag URL":                 "func run() { http.Get(*flagURL) }\n",
		"N4 untainted param":          "func run(target string) { http.NewRequest(\"GET\", target, nil) }\n\nfunc main() { run(cfg.URL) }\n",
		"N5 loopback":                 "func run(port int) { http.Get(fmt.Sprintf(\"http://localhost:%d/x\", port)) }\n",
		"N6 fixed host":               "func h(w http.ResponseWriter, r *http.Request) { http.Get(\"https://api.example.com/users/\" + r.FormValue(\"id\")) }\n",
		"N6 fixed host via local":     "func h(w http.ResponseWriter, r *http.Request) {\n\tu := fmt.Sprintf(\"https://api.example.com/users/%s\", r.FormValue(\"id\"))\n\thttp.Get(u)\n}\n",
		"N8 constant shell":           "func run() { exec.Command(\"sh\", \"-c\", \"uptime\").Run() }\n",
		"N9 request context":          "func h(w http.ResponseWriter, r *http.Request) { http.NewRequestWithContext(r.Context(), \"GET\", cfg.URL, nil) }\n",
		"map lookup with request key": "var upstreams = map[string]string{\"a\": \"http://a.internal\"}\n\nfunc h(w http.ResponseWriter, r *http.Request) { http.Get(upstreams[r.FormValue(\"name\")]) }\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if got := ruleSeverities(t, body); len(got) != 0 {
				t.Fatalf("unexpected findings %v", got)
			}
		})
	}
}

// A host-looking prefix without a delimiter does not fix the host:
// "https://api.example.com" + "@evil.example" changes it.
func TestUndelimitedHostPrefixStaysSSRF(t *testing.T) {
	got := ruleSeverities(t, "func h(w http.ResponseWriter, r *http.Request) { http.Get(\"https://api.example.com\" + r.FormValue(\"p\")) }\n")
	if len(got["SKY-G216"]) != 1 {
		t.Fatalf("want SKY-G216, got %v", got)
	}
}
