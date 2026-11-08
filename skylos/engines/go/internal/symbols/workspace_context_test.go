package symbols

import (
	"os"
	"path/filepath"
	"testing"
)

func writeWorkspaceProject(t *testing.T, root string, liveCycle, methodValue bool) {
	t.Helper()
	writeTestFile(t, root, "go.work", "go 1.22\nuse (\n ./application\n ./provider\n)\n")
	writeTestFile(t, root, "application/go.mod", "module example.com/application\n\ngo 1.22\n")
	writeTestFile(t, root, "provider/go.mod", "module example.com/provider\n\ngo 1.22\n")
	invocation := "bridge.Invoke(callback)"
	api := "func Invoke(callback func()) { callback() }"
	if methodValue {
		invocation = "var value bridge.Box[int]; invoke := value.Invoke; invoke(callback)"
		api = "type Box[T any] struct{}\nfunc (Box[T]) Invoke(callback func()) { callback() }"
	}
	callback := ""
	if liveCycle {
		callback = "alpha()"
	}
	writeTestFile(t, root, "application/main.go", "package main\nimport bridge \"example.com/provider/bridge\"\nfunc main() { "+invocation+" }\nfunc callback() { "+callback+" }\nfunc alpha() { beta() }\nfunc beta() { alpha() }\nfunc orphan() {}\n")
	writeTestFile(t, root, "provider/bridge/api.go", "package differentName\n"+api+"\n")
}

func assertWorkspaceStates(t *testing.T, root string, complete, liveCycle bool) {
	t.Helper()
	result, err := Extract(root)
	if err != nil {
		t.Fatal(err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, definition := range result.Defs {
		if definition.File == filepath.Join(resolvedRoot, "application/main.go") {
			states[definition.Name] = definition.Reachability
		}
	}
	for _, name := range []string{"alpha", "beta", "orphan", "main", "callback"} {
		want := ""
		if complete {
			want = "unreachable"
			if name == "main" || name == "callback" || (liveCycle && (name == "alpha" || name == "beta")) {
				want = "reachable"
			}
		}
		if got, exists := states["application."+name]; !exists || got != want {
			t.Errorf("%s reachability=%q (exists %v), want %q", name, got, exists, want)
		}
	}
}

func TestWorkspaceSourceContextFindsDeadCycles(t *testing.T) {
	t.Setenv("GOWORK", "")
	for _, liveCycle := range []bool{false, true} {
		for _, methodValue := range []bool{false, true} {
			root := t.TempDir()
			writeWorkspaceProject(t, root, liveCycle, methodValue)
			assertWorkspaceStates(t, root, true, liveCycle)
		}
	}
}

func TestWorkspaceSourceContextAcceptsExplicitSelectedFile(t *testing.T) {
	root := t.TempDir()
	writeWorkspaceProject(t, root, false, false)
	t.Setenv("GOWORK", filepath.Join(root, "go.work"))
	assertWorkspaceStates(t, root, true, false)
}

func TestWorkspaceSourceContextKeepsUnknownContextsConservative(t *testing.T) {
	cases := []struct {
		name string
		edit func(*testing.T, string)
	}{
		{"off", func(t *testing.T, root string) { t.Setenv("GOWORK", "off") }},
		{"other active workspace", func(t *testing.T, root string) { t.Setenv("GOWORK", filepath.Join(t.TempDir(), "go.work")) }},
		{"relative active workspace", func(t *testing.T, root string) { t.Setenv("GOWORK", "go.work") }},
		{"unknown directive", func(t *testing.T, root string) {
			writeTestFile(t, root, "go.work", "go 1.22\nuse (\n ./application\n ./provider\n)\nunknown opaque\n")
		}},
		{"unmodeled replacement", func(t *testing.T, root string) {
			writeTestFile(t, root, "go.work", "go 1.22\nuse (\n ./application\n ./provider\n)\nreplace example.com/provider => ./different\n")
		}},
		{"duplicate module", func(t *testing.T, root string) {
			writeTestFile(t, root, "provider/go.mod", "module example.com/application\n\ngo 1.22\n")
		}},
		{"duplicate use", func(t *testing.T, root string) {
			writeTestFile(t, root, "go.work", "go 1.22\nuse (\n ./application\n ./provider\n ./provider\n)\n")
		}},
		{"missing provider use", func(t *testing.T, root string) { writeTestFile(t, root, "go.work", "go 1.22\nuse ./application\n") }},
		{"provider module metadata missing", func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, "provider/go.mod")); err != nil {
				t.Fatal(err)
			}
		}},
		{"provider unknown module metadata", func(t *testing.T, root string) {
			writeTestFile(t, root, "provider/go.mod", "module example.com/provider\n\ngo 1.22\nunknown opaque\n")
		}},
		{"provider duplicate module metadata", func(t *testing.T, root string) {
			writeTestFile(t, root, "provider/go.mod", "module example.com/provider\nmodule example.com/wrong\n\ngo 1.22\n")
		}},
		{"workspace go version older than module", func(t *testing.T, root string) {
			writeTestFile(t, root, "provider/go.mod", "module example.com/provider\n\ngo 1.24\n")
		}},
		{"invalid workspace version", func(t *testing.T, root string) {
			writeTestFile(t, root, "go.work", "go 1.022\nuse (\n ./application\n ./provider\n)\n")
		}},
		{"standard library module collision", func(t *testing.T, root string) {
			writeTestFile(t, root, "provider/go.mod", "module fmt\n\ngo 1.22\n")
			writeTestFile(t, root, "application/main.go", "package main\nimport bridge \"fmt/bridge\"\nfunc main() { bridge.Invoke(callback) }\nfunc callback() {}\nfunc alpha() { beta() }\nfunc beta() { alpha() }\nfunc orphan() {}\n")
		}},
		{"invalid required version", func(t *testing.T, root string) {
			writeTestFile(t, root, "provider/go.mod", "module example.com/provider\n\ngo 1.22\nrequire example.com/unused vbogus\n")
		}},
		{"invalid semver suffix", func(t *testing.T, root string) {
			writeTestFile(t, root, "provider/go.mod", "module example.com/provider\n\ngo 1.22\nrequire example.com/unused v1.2.3garbage\n")
		}},
		{"future workspace version", func(t *testing.T, root string) {
			writeTestFile(t, root, "go.work", "go 1.99\nuse (\n ./application\n ./provider\n)\n")
		}},
		{"future toolchain", func(t *testing.T, root string) {
			writeTestFile(t, root, "go.work", "go 1.22\ntoolchain go1.99.0\nuse (\n ./application\n ./provider\n)\n")
		}},
		{"new syntax in older module", func(t *testing.T, root string) {
			writeTestFile(t, root, "provider/bridge/api.go", "package differentName\nfunc Invoke(callback func()) { for range func(yield func() bool) { yield() } { callback() } }\n")
		}},
		{"provider type error", func(t *testing.T, root string) {
			writeTestFile(t, root, "provider/bridge/api.go", "package differentName\nfunc Invoke(callback func()) { missing() }\n")
		}},
		{"provider conflicting build variants", func(t *testing.T, root string) {
			writeTestFile(t, root, "provider/bridge/variant_linux.go", "package differentName\nfunc Invoke(callback func()) { callback() }\n")
		}},
		{"provider assembly", func(t *testing.T, root string) {
			writeTestFile(t, root, "provider/bridge/native.s", "// opaque native consumer\n")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GOWORK", "")
			root := t.TempDir()
			writeWorkspaceProject(t, root, false, false)
			tc.edit(t, root)
			assertWorkspaceStates(t, root, false, false)
		})
	}
}

func TestWorkspaceSourceContextUsesEachModuleLanguageVersion(t *testing.T) {
	if !validGoVersion("1.23") {
		t.Skip("Go 1.23 syntax requires a supporting host toolchain")
	}
	t.Setenv("GOWORK", "")
	root := t.TempDir()
	writeWorkspaceProject(t, root, false, false)
	writeTestFile(t, root, "go.work", "go 1.23\nuse (\n ./application\n ./provider\n)\n")
	writeTestFile(t, root, "provider/go.mod", "module example.com/provider\n\ngo 1.23\n")
	writeTestFile(t, root, "provider/bridge/api.go", "package differentName\nfunc Invoke(callback func()) { for range func(yield func() bool) { yield() } { callback() } }\n")
	assertWorkspaceStates(t, root, true, false)
}

func TestWorkspaceRequiredVersionIdentity(t *testing.T) {
	for _, tc := range []struct {
		path, version string
		valid         bool
	}{
		{"example.com/provider", "v0.0.0", true},
		{"example.com/provider", "v1.2.3-pre.0", true},
		{"example.com/provider/v2", "v2.1.0", true},
		{"gopkg.in/yaml.v3", "v3.0.1", true},
		{"example.com/provider", "v2.1.0+incompatible", true},
		{"example.com/provider", "vbogus", false},
		{"example.com/provider", "v1.2.3garbage", false},
		{"example.com/provider", "v1.02.3", false},
		{"example.com/provider", "v1.2.3-01", false},
		{"example.com/provider", "v1.2.3+opaque", false},
		{"example.com/provider/v2", "v1.2.3", false},
		{"gopkg.in/yaml.v3", "v2.0.1", false},
	} {
		t.Run(tc.path+tc.version, func(t *testing.T) {
			if got := canonicalRequiredVersion(tc.path, tc.version); got != tc.valid {
				t.Fatalf("got%v want%v", got, tc.valid)
			}
		})
	}
}
