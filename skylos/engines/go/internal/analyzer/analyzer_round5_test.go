package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

const redirectSQLPrelude = `package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type Config struct{ HomeURL string }

var cfg Config
var db *sql.DB
var allowed = map[string]bool{"/home": true}

var _ = context.Background
var _ = fmt.Sprintf
var _ = url.Parse
var _ = strings.HasPrefix
var _ tls.Config

`

func severitiesFor(t *testing.T, files map[string]string, rule string) []string {
	t.Helper()
	dir := t.TempDir()
	for name, source := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	findings, err := New().AnalyzeDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, finding := range findings {
		if finding.RuleID == rule {
			got = append(got, finding.Severity)
		}
	}
	return got
}

func assertSeverities(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("want %v, got %v", want, got)
		}
	}
}

func TestOpenRedirectNeedsUntrustedOrigin(t *testing.T) {
	cases := map[string]struct {
		body string
		want []string
	}{
		"Z1 query param":                  {"func h(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, r.URL.Query().Get(\"next\"), 302) }\n", []string{"HIGH"}},
		"Z2 single slash check":           {"func h(w http.ResponseWriter, r *http.Request) {\n\tnext := r.FormValue(\"next\")\n\tif !strings.HasPrefix(next, \"/\") || strings.HasPrefix(next, \"//\") {\n\t\tnext = \"/\"\n\t}\n\thttp.Redirect(w, r, next, 302)\n}\n", nil},
		"Z3 parsed host check":            {"func h(w http.ResponseWriter, r *http.Request) {\n\tnext := r.FormValue(\"next\")\n\tu, err := url.Parse(next)\n\tif err != nil || u.Host != \"\" {\n\t\treturn\n\t}\n\thttp.Redirect(w, r, next, 302)\n}\n", nil},
		"Z4 allowlist":                    {"func h(w http.ResponseWriter, r *http.Request) {\n\tnext := r.FormValue(\"next\")\n\tif !allowed[next] {\n\t\treturn\n\t}\n\thttp.Redirect(w, r, next, 302)\n}\n", nil},
		"Z5 query only":                   {"func h(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, \"/login?next=\"+r.URL.Path, 302) }\n", nil},
		"Z5 appended query":               {"func redirect(w http.ResponseWriter, r *http.Request, to string) {\n\tfor strings.HasPrefix(to, \"//\") {\n\t\tto = strings.TrimPrefix(to, \"/\")\n\t}\n\tif r.URL.RawQuery != \"\" {\n\t\tto += \"?\" + r.URL.RawQuery\n\t}\n\thttp.Redirect(w, r, to, 308)\n}\n", nil},
		"Z6 config":                       {"func h(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, cfg.HomeURL, 302) }\n", nil},
		"Z7 host header":                  {"func h(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, \"https://\"+r.Host+\"/x\", 302) }\n", []string{"HIGH"}},
		"Sprintf with query after verb":   {"func h(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, fmt.Sprintf(\"%s?x=1\", r.FormValue(\"next\")), 302) }\n", []string{"HIGH"}},
		"Sprintf with verb only in query": {"func h(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, fmt.Sprintf(\"/login?next=%s\", r.URL.Path), 302) }\n", nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := severitiesFor(t, map[string]string{"main.go": redirectSQLPrelude + tc.body}, "SKY-G220")
			assertSeverities(t, got, tc.want)
		})
	}
}

func TestSQLInjectionSeverityFollowsTheSource(t *testing.T) {
	cases := map[string]struct {
		body string
		want []string
	}{
		"Q1 request concat":        {"func h(w http.ResponseWriter, r *http.Request) { db.Query(\"SELECT * FROM t WHERE id = \" + r.FormValue(\"id\")) }\n", []string{"CRITICAL"}},
		"Q2 context sprintf":       {"func h(w http.ResponseWriter, r *http.Request) { db.QueryContext(context.Background(), fmt.Sprintf(\"SELECT * FROM t WHERE n = '%s'\", r.FormValue(\"q\"))) }\n", []string{"CRITICAL"}},
		"Q3 placeholder":           {"func h(w http.ResponseWriter, r *http.Request) { db.Query(\"SELECT * FROM t WHERE id = ?\", r.FormValue(\"id\")) }\n", nil},
		"Q4 constant":              {"func run() { db.Query(\"SELECT 1\") }\n", nil},
		"Q4 constant concat":       {"func run() { db.Query(\"SELECT * \" + \"FROM t\") }\n", nil},
		"Q5 unproven string-built": {"func byTable(table string) { db.Query(\"SELECT * FROM \" + table) }\n", []string{"HIGH"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := severitiesFor(t, map[string]string{"main.go": redirectSQLPrelude + tc.body}, "SKY-G211")
			assertSeverities(t, got, tc.want)
		})
	}
}

const insecureTLS = "var tlsConfig = &tls.Config{InsecureSkipVerify: true}\n"

func TestTLSVerificationOffInTestSupportCode(t *testing.T) {
	cases := map[string]struct {
		source string
		want   []string
	}{
		"T1 test helper": {"package harness\n\nimport (\n\t\"crypto/tls\"\n\t\"testing\"\n)\n\n" + insecureTLS +
			"\nfunc NewHarness(t testing.TB) *tls.Config { t.Helper(); return tlsConfig }\n", nil},
		"T2 production": {"package main\n\nimport \"crypto/tls\"\n\n" + insecureTLS, []string{"HIGH"}},
		"T3 production using testing.Testing": {"package main\n\nimport (\n\t\"crypto/tls\"\n\t\"testing\"\n)\n\n" + insecureTLS +
			"\nfunc inTest() bool { return testing.Testing() }\n", []string{"HIGH"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := severitiesFor(t, map[string]string{"harness.go": tc.source}, "SKY-G210")
			assertSeverities(t, got, tc.want)
		})
	}
}
