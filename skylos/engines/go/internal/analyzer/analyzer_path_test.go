package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

const pathPrelude = `package main

import (
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/gin-gonic/gin"
)

type Config struct{ Path string }

var cfg Config
var flagFile = flag.String("file", "", "")
var root = "/srv/files"

var _ = filepath.Join
var _ = strings.HasPrefix
var _ = os.Open
var _ unsafe.Pointer
var _ *gin.Context

`

func findingsByRule(t *testing.T, body string) map[string][]string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(pathPrelude+body), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := New().AnalyzeDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, finding := range findings {
		got[finding.RuleID] = append(got[finding.RuleID], finding.Severity)
	}
	return got
}

func TestUntrustedPathsAreTraversal(t *testing.T) {
	cases := map[string]string{
		"P1 query to ReadFile":              "func h(w http.ResponseWriter, r *http.Request) { os.ReadFile(r.URL.Query().Get(\"f\")) }\n",
		"P2 ServeFile join":                 "func h(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, filepath.Join(root, r.URL.Path)) }\n",
		"P3 local then join":                "func h(w http.ResponseWriter, r *http.Request) {\n\tname := r.FormValue(\"n\")\n\tf, _ := os.Open(filepath.Join(root, name))\n\tdefer f.Close()\n}\n",
		"P4 gin param":                      "func h(c *gin.Context) { os.ReadFile(c.Param(\"file\")) }\n",
		"P9 prefix check on uncleaned path": "func h(w http.ResponseWriter, r *http.Request) {\n\tp := root + \"/\" + r.FormValue(\"n\")\n\tif !strings.HasPrefix(p, root) {\n\t\treturn\n\t}\n\tos.ReadFile(p)\n}\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			got := findingsByRule(t, body)
			if len(got["SKY-G215"]) != 1 || got["SKY-G215"][0] != "HIGH" {
				t.Fatalf("want one HIGH SKY-G215, got %v", got)
			}
		})
	}
}

func TestGuardedSanitisedAndProgramPathsAreNotTraversal(t *testing.T) {
	cases := map[string]string{
		"P5 clean and prefix": "func h(w http.ResponseWriter, r *http.Request) {\n\tp := filepath.Join(root, filepath.Clean(r.URL.Path))\n\tif !strings.HasPrefix(p, root) {\n\t\treturn\n\t}\n\tos.ReadFile(p)\n}\n",
		"P6 rel dot-dot":      "func h(w http.ResponseWriter, r *http.Request) {\n\tp := filepath.Join(root, r.FormValue(\"n\"))\n\trel, err := filepath.Rel(root, p)\n\tif err != nil || strings.HasPrefix(rel, \"..\") {\n\t\treturn\n\t}\n\tos.ReadFile(p)\n}\n",
		"P7 is local":         "func h(w http.ResponseWriter, r *http.Request) {\n\tname := r.FormValue(\"n\")\n\tif !filepath.IsLocal(name) {\n\t\treturn\n\t}\n\tos.ReadFile(filepath.Join(root, name))\n}\n",
		"P8 base":             "func h(w http.ResponseWriter, r *http.Request) { os.ReadFile(filepath.Join(root, filepath.Base(r.FormValue(\"n\")))) }\n",
		"P10 config":          "func run() { os.ReadFile(cfg.Path) }\n",
		"P10 flag":            "func run() { os.ReadFile(*flagFile) }\n",
		"P10 os.Args":         "func run() { os.ReadFile(os.Args[1]) }\n",
		"P10 temp file":       "func run() { tmp, _ := os.CreateTemp(\"\", \"x\"); tmp.Close(); os.Remove(tmp.Name()) }\n",
		"P10 parameter":       "func load(name string) ([]byte, error) { return os.ReadFile(name) }\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if got := findingsByRule(t, body); len(got["SKY-G215"]) != 0 {
				t.Fatalf("unexpected SKY-G215 %v", got)
			}
		})
	}
}

func TestReliabilitySeveritiesAndPrecision(t *testing.T) {
	cases := map[string]struct {
		body string
		rule string
		want []string
	}{
		"R1 deferred close":                  {"func run(p string) { f, _ := os.Open(p); defer f.Close() }\n", "SKY-G260", nil},
		"R1 explicit close":                  {"func run(p string) { f, _ := os.Open(p); buf := make([]byte, 1); f.Read(buf); f.Close() }\n", "SKY-G260", nil},
		"R1 returned":                        {"func run(p string) (*os.File, error) { f, err := os.Open(p); return f, err }\n", "SKY-G260", nil},
		"R1 returned wrapped":                {"type holder struct{ f *os.File }\n\nfunc run(p string) holder { f, _ := os.Open(p); return holder{f} }\n", "SKY-G260", nil},
		"R1 deferred closure":                {"func run(p string) { f, _ := os.Open(p); defer func() { _ = f.Close() }() }\n", "SKY-G260", nil},
		"R2 never closed":                    {"func run(p string) { f, _ := os.Open(p); buf := make([]byte, 1); f.Read(buf) }\n", "SKY-G260", []string{"MEDIUM"}},
		"R3 defer in loop":                   {"func run(ps []string) {\n\tfor _, p := range ps {\n\t\tf, _ := os.Open(p)\n\t\tdefer f.Close()\n\t}\n}\n", "SKY-G203", []string{"MEDIUM"}},
		"R4 defer then break":                {"func run(ps []string) {\n\tfor _, p := range ps {\n\t\tf, err := os.Open(p)\n\t\tif err != nil {\n\t\t\tcontinue\n\t\t}\n\t\tdefer f.Close()\n\t\tbreak\n\t}\n}\n", "SKY-G203", nil},
		"R4 defer then return":               {"func run(ps []string) {\n\tfor _, p := range ps {\n\t\tf, _ := os.Open(p)\n\t\tdefer f.Close()\n\t\treturn\n\t}\n}\n", "SKY-G203", nil},
		"R4 break only exits the inner loop": {"func run(groups [][]string) {\n\tfor _, ps := range groups {\n\t\tfor _, p := range ps {\n\t\t\tf, _ := os.Open(p)\n\t\t\tdefer f.Close()\n\t\t\tbreak\n\t\t}\n\t}\n}\n", "SKY-G203", []string{"MEDIUM"}},
		"R5 unsafe":                          {"func run(b []byte) uintptr { return uintptr(unsafe.Pointer(&b[0])) }\n", "SKY-G206", []string{"LOW"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := findingsByRule(t, tc.body)[tc.rule]
			if len(got) != len(tc.want) {
				t.Fatalf("want %v for %s, got %v", tc.want, tc.rule, got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("want %v for %s, got %v", tc.want, tc.rule, got)
				}
			}
		})
	}
}
