package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSSHHostKeyConfiguration(t *testing.T) {
	cases := []struct {
		name, declaration, body string
		want                    bool
	}{
		{"configured callback", "", "var config = &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey()}", true},
		{"assigned callback", "", "func settings() { cfg := &ssh.ClientConfig{}; cfg.HostKeyCallback = ssh.InsecureIgnoreHostKey() }", true},
		{"local callback alias", "", "func settings() { cb := ssh.InsecureIgnoreHostKey(); _ = &ssh.ClientConfig{HostKeyCallback: cb} }", true},
		{"fixed host key", "", "func settings(key ssh.PublicKey) { _ = &ssh.ClientConfig{HostKeyCallback: ssh.FixedHostKey(key)} }", false},
		{"unused callback", "", "var callback = ssh.InsecureIgnoreHostKey()", false},
		{"native config alias", "type Config = ssh.ClientConfig", "var cfg = Config{HostKeyCallback: ssh.InsecureIgnoreHostKey()}", true},
		{"local type shadows native alias", "type Config = ssh.ClientConfig", "func settings() { type Config struct { HostKeyCallback ssh.HostKeyCallback }; _ = Config{HostKeyCallback: ssh.InsecureIgnoreHostKey()} }", false},
		{"test support package", "", "func settings(t *testing.T) { _ = &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey()} }", false},
		{"own configuration", "type Config struct { HostKeyCallback ssh.HostKeyCallback }", "var cfg = Config{HostKeyCallback: ssh.InsecureIgnoreHostKey()}", false},
	}
	for _, scenario := range cases {
		t.Run(scenario.name, func(t *testing.T) {
			source := "package app\nimport (ssh \"golang.org/x/crypto/ssh\"; \"testing\")\n" + scenario.declaration + "\n" + scenario.body + "\n"
			root := t.TempDir()
			path := filepath.Join(root, "transport.go")
			if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			findings, err := New().AnalyzeDir(root)
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, finding := range findings {
				if finding.RuleID == "SKY-D380" {
					count++
					if filepath.Base(finding.File) != "transport.go" || finding.Line != 4 {
						t.Fatalf("wrong location: %+v", finding)
					}
				}
			}
			if count > 1 || (count == 1) != scenario.want {
				t.Fatalf("got %d SSH findings, wanted positive=%v", count, scenario.want)
			}
		})
	}
}

func TestSamePackageTransportFlow(t *testing.T) {
	cases := []struct {
		name, call, otherPackage string
		want                     bool
	}{
		{"split handler and requester", "retrieve(r.FormValue(\"url\"))", "app", true},
		{"fixed destination", "retrieve(\"https://example.invalid/view/\" + r.FormValue(\"id\"))", "app", false},
		{"local shadow", "retrieve := func(_ string) {}; retrieve(r.FormValue(\"url\"))", "app", false},
		{"different package", "retrieve(r.FormValue(\"url\"))", "other", false},
	}
	for _, scenario := range cases {
		t.Run(scenario.name, func(t *testing.T) {
			root := t.TempDir()
			files := map[string]string{
				"handler.go":  "package app\nimport h \"net/http\"\nfunc handle(r *h.Request) { " + scenario.call + " }\n",
				"retrieve.go": "package " + scenario.otherPackage + "\nimport transport \"net/http\"\nfunc retrieve(raw string) {\n    transport.Get(raw)\n}\n",
			}
			for path, source := range files {
				if err := os.WriteFile(filepath.Join(root, path), []byte(source), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			findings, err := New().AnalyzeDir(root)
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, finding := range findings {
				if finding.RuleID == "SKY-G216" {
					count++
					if filepath.Base(finding.File) != "retrieve.go" || finding.Line != 4 {
						t.Fatalf("wrong location: %+v", finding)
					}
				}
			}
			if count > 1 || (count == 1) != scenario.want {
				t.Fatalf("got %d SSRF findings, wanted positive=%v", count, scenario.want)
			}
		})
	}
}

func TestGoTransportReportsPhysicalSourceLocations(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"handler.go":  "//line virtual-handler.go:200\npackage app\nimport \"net/http\"\nfunc handle(r *http.Request) { retrieve(r.FormValue(\"url\")) }\n",
		"retrieve.go": "//line virtual-retrieve.go:300\npackage app\nimport \"net/http\"\nfunc retrieve(raw string) {\n    http.Get(raw)\n}\n",
	}
	for name, source := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	findings, err := New().AnalyzeDir(root)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, finding := range findings {
		if finding.RuleID == "SKY-G216" {
			count++
			if finding.File != filepath.Join(root, "retrieve.go") || finding.Line != 5 {
				t.Fatalf("wrong physical source location: %+v", finding)
			}
		}
	}
	if count != 1 {
		t.Fatalf("got %d cross-file SSRF findings, wanted one", count)
	}
	scoped, err := New().AnalyzeDirScoped(root, map[string]bool{
		filepath.Join(root, "retrieve.go"): true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range scoped {
		if finding.RuleID == "SKY-G216" {
			t.Fatalf("excluded caller supplied taint: %+v", finding)
		}
	}
}

func TestSSHConfigAliasRespectsPackageAndBuildScope(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"base.go":     "package app\nimport \"golang.org/x/crypto/ssh\"\ntype Config = ssh.ClientConfig\n",
		"cfg.go":      "package app\nimport \"golang.org/x/crypto/ssh\"\nvar cfg = Config{HostKeyCallback: ssh.InsecureIgnoreHostKey()}\n",
		"excluded.go": "//go:build skylos_test_alias_inactive\n\npackage app\ntype Config = struct { HostKeyCallback any }\n",
		"other.go":    "//go:build skylos_test_alias_inactive\n\npackage other\ntype Config = struct { HostKeyCallback any }\n",
	}
	for name, source := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	findings, err := New().AnalyzeDir(root)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, finding := range findings {
		if finding.RuleID == "SKY-D380" {
			count++
			if finding.File != filepath.Join(root, "cfg.go") || finding.Line != 3 {
				t.Fatalf("wrong source location: %+v", finding)
			}
		}
	}
	if count != 1 {
		t.Fatalf("got %d SSH findings, wanted one", count)
	}
}
