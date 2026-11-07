package symbols

import "testing"

func TestModuleDirectiveAllowsQuotedPathsAndTrailingComments(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "go.mod", "module\t\"example.com/demo\" // source module\n\ngo 1.22\n")
	writeTestFile(t, root, "api.go", "package demo\nimport \"example.com/demo/provider\"\nfunc API() { provider.Touch() }\nfunc alpha() { beta() }\nfunc beta() { alpha() }\n")
	writeTestFile(t, root, "provider/api.go", "package provider\nfunc Touch() {}\n")
	if got := readModulePath(root); got != "example.com/demo" {
		t.Fatalf("module path = %q", got)
	}
	result, err := Extract(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, def := range result.Defs {
		if (def.Name == "alpha" || def.Name == "beta") && def.Reachability != "unreachable" {
			t.Errorf("%s state = %q", def.Name, def.Reachability)
		}
	}
}

func TestProjectImportsUseCompleteIndexedModulePackages(t *testing.T) {
	cases := []struct {
		name   string
		files  map[string]string
		states map[string]string
	}{
		{
			name: "transitive aliases preserve callbacks and expose private cycles",
			files: map[string]string{
				"main.go": `package main
import service "example.com/demo/service"
func main() { service.Invoke(callback) }
func callback() {}
func alpha() { beta() }
func beta() { alpha() }
`,
				"service/service.go": `package service
import backend "example.com/demo/provider"
func Invoke(callback func()) { backend.Invoke(callback) }
`,
				"provider/provider.go": "package provider\nfunc Invoke(callback func()) { callback() }\n",
			},
			states: map[string]string{"main": "reachable", "callback": "reachable", "alpha": "unreachable", "beta": "unreachable", "service.Invoke": "reachable", "provider.Invoke": "reachable"},
		},
		{
			name: "imported package name need not match its directory",
			files: map[string]string{
				"main.go":         "package main\nimport \"example.com/demo/provider\"\nfunc main() { actual.Touch(callback) }\nfunc callback() {}\nfunc alpha() { beta() }\nfunc beta() { alpha() }\n",
				"provider/api.go": "package actual\nfunc Touch(callback func()) { callback() }\n",
			},
			states: map[string]string{"main": "reachable", "callback": "reachable", "alpha": "unreachable", "beta": "unreachable", "provider.Touch": "reachable"},
		},
		{
			name: "imported generic method values retain their declaration",
			files: map[string]string{
				"main.go": `package main
import "example.com/demo/provider"
func main() { var box provider.Box[int]; callback := box.Reset; callback() }
func alpha() { beta() }
func beta() { alpha() }
`,
				"provider/provider.go": "package provider\ntype Box[T any] struct{}\nfunc (b *Box[T]) Reset() {}\n",
			},
			states: map[string]string{"main": "reachable", "alpha": "unreachable", "beta": "unreachable", "provider.Box.Reset": "reachable"},
		},
		{
			name: "invalid provider leaves importing package unknown",
			files: map[string]string{
				"main.go":              "package main\nimport \"example.com/demo/provider\"\nfunc main() { provider.Touch() }\nfunc alpha() { beta() }\nfunc beta() { alpha() }\n",
				"provider/provider.go": "package provider\nfunc Touch() { notDefined() }\n",
			},
			states: map[string]string{"main": "", "alpha": "", "beta": "", "provider.Touch": ""},
		},
		{
			name: "assembly provider cannot establish a closed project API",
			files: map[string]string{
				"main.go":          "package main\nimport \"example.com/demo/provider\"\nfunc main() { provider.Touch() }\nfunc alpha() { beta() }\nfunc beta() { alpha() }\n",
				"provider/api.go":  "package provider\nfunc Touch() {}\n",
				"provider/entry.s": "// Native assembly may refer to private functions.\n",
			},
			states: map[string]string{"main": "", "alpha": "", "beta": ""},
		},
		{
			name: "linkname provider cannot establish a closed project API",
			files: map[string]string{
				"main.go":         "package main\nimport \"example.com/demo/provider\"\nfunc main() { provider.Touch() }\nfunc alpha() { beta() }\nfunc beta() { alpha() }\n",
				"provider/api.go": "package provider\n//go:linkname hidden example.com/demo.alpha\nfunc hidden() {}\nfunc Touch() {}\n",
			},
			states: map[string]string{"main": "", "alpha": "", "beta": ""},
		},
		{
			name: "unsafe provider cannot establish a closed project API",
			files: map[string]string{
				"main.go":         "package main\nimport \"example.com/demo/provider\"\nfunc main() { provider.Touch() }\nfunc alpha() { beta() }\nfunc beta() { alpha() }\n",
				"provider/api.go": "package provider\nimport _ \"unsafe\"\nfunc Touch() {}\n",
			},
			states: map[string]string{"main": "", "alpha": "", "beta": ""},
		},
		{
			name: "project import cycles are not partial type proofs",
			files: map[string]string{
				"main.go":       "package main\nimport \"example.com/demo/first\"\nfunc main() { first.Touch() }\nfunc unused() {}\n",
				"first/api.go":  "package first\nimport \"example.com/demo/second\"\nfunc Touch() { second.Touch() }\n",
				"second/api.go": "package second\nimport \"example.com/demo/first\"\nfunc Touch() { first.Touch() }\n",
			},
			states: map[string]string{"main": "", "unused": "", "first.Touch": "", "second.Touch": ""},
		},
		{
			name: "nested module is not imported as parent module source",
			files: map[string]string{
				"main.go":         "package main\nimport \"example.com/demo/provider\"\nfunc main() { provider.Touch() }\nfunc unused() {}\n",
				"provider/go.mod": "module example.com/separate\n\ngo 1.22\n",
				"provider/api.go": "package provider\nfunc Touch() {}\n",
			},
			states: map[string]string{"main": "", "unused": ""},
		},
		{
			name: "excluded testdata source is not an import proof",
			files: map[string]string{
				"main.go":                "package main\nimport \"example.com/demo/testdata/provider\"\nfunc main() { provider.Touch() }\nfunc unused() {}\n",
				"testdata/provider/a.go": "package provider\nfunc Touch() {}\n",
			},
			states: map[string]string{"main": "", "unused": ""},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeTestFile(t, root, "go.mod", "module example.com/demo\n\ngo 1.22\n")
			for name, source := range tc.files {
				writeTestFile(t, root, name, source)
			}
			result, err := Extract(root)
			if err != nil {
				t.Fatal(err)
			}
			for name, state := range tc.states {
				found := false
				for _, def := range result.Defs {
					if def.Name == name {
						found = true
						if def.Reachability != state {
							t.Errorf("%s state = %q, want %q", name, def.Reachability, state)
						}
					}
				}
				if !found {
					t.Errorf("missing %s", name)
				}
			}
		})
	}
}

func TestPrivateTestHelpersRequireCompletePackageReachability(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "go.mod", "module example.com/demo\n\ngo 1.22\n")
	writeTestFile(t, root, "api.go", "package demo\nfunc production() {}\n")
	writeTestFile(t, root, "api_test.go", `package demo
import "testing"
var callbacks = []func(){registered}
func registered() {}
func TestValue(t *testing.T) { live(); production() }
func TestMain(m *testing.M) { setup() }
func BenchmarkValue(b *testing.B) { bench() }
func FuzzValue(f *testing.F) { fuzz() }
func ExampleValue() { example() }
func live() { leaf() }
func leaf() {}
func setup() {}
func bench() {}
func fuzz() {}
func example() {}
func alpha() { beta() }
func beta() { alpha() }
func stale() {}
type suite struct{}
func (suite) hook() { hookDependency() }
func hookDependency() {}
`)
	result, err := Extract(root)
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, def := range result.Defs {
		states[def.Name] = def.Reachability
	}
	for _, name := range []string{"registered", "production", "live", "leaf", "setup", "bench", "fuzz", "example", "hookDependency"} {
		if states[name] != "reachable" {
			t.Errorf("live test consumer %s = %q", name, states[name])
		}
	}
	for _, name := range []string{"alpha", "beta", "stale"} {
		if states[name] != "unreachable" {
			t.Errorf("unused test helper %s = %q", name, states[name])
		}
	}
	for _, name := range []string{"TestValue", "TestMain", "BenchmarkValue", "FuzzValue", "ExampleValue", "suite.hook"} {
		if _, ok := states[name]; ok {
			t.Errorf("test entry or unknown method hook %s became a dead-code candidate", name)
		}
	}
}

func TestUnresolvedTestsAndExternalTestPackagesKeepPriorDefinitionScope(t *testing.T) {
	for _, external := range []bool{false, true} {
		root := t.TempDir()
		writeTestFile(t, root, "go.mod", "module example.com/demo\n\ngo 1.22\n")
		writeTestFile(t, root, "api.go", "package demo\nfunc API() {}\n")
		source := "package demo\nimport \"example.invalid/framework\"\nfunc helper() { framework.Run() }\n"
		if external {
			source = "package demo_test\nfunc helper() {}\n"
		}
		writeTestFile(t, root, "api_test.go", source)
		result, err := Extract(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, def := range result.Defs {
			if def.Name == "helper" {
				t.Errorf("unproven/external test helper became a candidate: %+v", def)
			}
		}
	}
}
