package symbols

import (
	"os"
	"path/filepath"
	"testing"
)

const localReplacementMain = `package main
import bridge "example.com/provider/bridge"
func main() { bridge.Invoke(callback) }
func callback() {}
func alpha() { beta() }
func beta() { alpha() }
func orphan() {}
`

func writeLocalReplacementProject(t *testing.T, root string, mod string) {
	t.Helper()
	writeTestFile(t, root, "go.mod", mod)
	writeTestFile(t, root, "main.go", localReplacementMain)
	writeTestFile(t, root, "local/provider/go.mod", "module example.com/provider\n\ngo 1.22\n")
	writeTestFile(t, root, "local/provider/bridge/api.go", "package differentName\nfunc Invoke(callback func()) { callback() }\n")
}

func assertLocalReplacementStates(t *testing.T, root string, complete bool) {
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
		if definition.File == filepath.Join(resolvedRoot, "main.go") {
			states[definition.Name] = definition.Reachability
		}
	}
	for _, name := range []string{"alpha", "beta", "orphan", "main", "callback"} {
		want := ""
		if complete {
			want = "unreachable"
			if name == "main" || name == "callback" {
				want = "reachable"
			}
		}
		if got, exists := states[name]; !exists || got != want {
			t.Errorf("%s reachability=%q (exists %v), want %q", name, got, exists, want)
		}
	}
}

func TestLocalReplacementAllowsIndexedSourceTypeProof(t *testing.T) {
	for _, module := range []string{
		"module example.com/application\n\ngo 1.22\nrequire example.com/provider v0.0.0\nreplace example.com/provider => ./local/provider\n",
		"module example.com/application\n\ngo 1.22\ntoolchain go1.22.0\nrequire example.com/provider v0.0.0\nreplace example.com/provider => ./local/provider\n",
		"module \"example.com/application\" // application\n\ngo 1.22\nrequire (\n example.com/provider v0.0.0 // dependency\n)\nreplace (\n example.com/provider => \"./local/provider\" // already scanned\n)\n",
	} {
		t.Run(module, func(t *testing.T) {
			root := t.TempDir()
			writeLocalReplacementProject(t, root, module)
			assertLocalReplacementStates(t, root, true)
		})
	}
}

func TestLocalReplacementKeepsUnknownModuleContextsConservative(t *testing.T) {
	const prefix = "module example.com/application\n\ngo 1.22\n"
	const required = "require example.com/provider v0.0.0\n"
	cases := []struct {
		name, mod string
		edit      func(*testing.T, string)
	}{
		{"unknown metadata directive", prefix + required + "replace example.com/provider => ./local/provider\nnot_a_go_directive forbidden\n", nil},
		{"unknown empty metadata block", prefix + required + "replace example.com/provider => ./local/provider\nnot_a_go_directive (\n)\n", nil},
		{"replacement without a selected dependency", prefix + "replace example.com/provider => ./local/provider\n", nil},
		{"version specific replacement", prefix + required + "replace example.com/provider v0.0.0 => ./local/provider\n", nil},
		{"remote replacement", prefix + required + "replace example.com/provider => example.com/fork v0.0.0\n", nil},
		{"conflicting replacements", prefix + required + "replace example.com/provider => ./local/provider\nreplace example.com/provider => ./other\n", nil},
		{"version override prevents unversioned inference", prefix + required + "replace example.com/provider => ./local/provider\nreplace example.com/provider v0.0.0 => example.com/remote v0.0.1\n", nil},
		{"duplicate module identity", prefix + "module example.com/second\n" + required + "replace example.com/provider => ./local/provider\n", nil},
		{"duplicate required dependency", prefix + required + required + "replace example.com/provider => ./local/provider\n", nil},
		{"unterminated metadata block", prefix + required + "replace (\n example.com/provider => ./local/provider\n", nil},
		{"invalid metadata quote", prefix + required + "replace example.com/provider => \"./local/provider\n", nil},
		{"nested module without a replacement", prefix + required, nil},
		{"target module identity mismatch", prefix + required + "replace example.com/provider => ./local/provider\n", func(t *testing.T, root string) {
			writeTestFile(t, root, "local/provider/go.mod", "module example.com/other\n\ngo 1.22\n")
		}},
		{"invalid dependency source", prefix + required + "replace example.com/provider => ./local/provider\n", func(t *testing.T, root string) {
			writeTestFile(t, root, "local/provider/bridge/api.go", "package bridge\nfunc Invoke(callback func()) { undefinedName() }\n")
		}},
		{"assembly dependency source", prefix + required + "replace example.com/provider => ./local/provider\n", func(t *testing.T, root string) {
			writeTestFile(t, root, "local/provider/bridge/native.s", "// assembly may use private code\n")
		}},
		{"excluded dependency", prefix + required + "replace example.com/provider => ./testdata/provider\n", func(t *testing.T, root string) {
			writeTestFile(t, root, "testdata/provider/go.mod", "module example.com/provider\n\ngo 1.22\n")
			writeTestFile(t, root, "testdata/provider/bridge/api.go", "package bridge\nfunc Invoke(callback func()) { callback() }\n")
		}},
		{"workspace overrides are not inferred", prefix + required + "replace example.com/provider => ./local/provider\n", func(t *testing.T, root string) {
			t.Setenv("GOWORK", "")
			writeTestFile(t, root, "go.work", "go 1.22\nuse .\nreplace example.com/provider => ./other\n")
		}},
		{"explicit workspace context remains unknown", prefix + required + "replace example.com/provider => ./local/provider\n", func(t *testing.T, root string) { t.Setenv("GOWORK", filepath.Join(root, "different.work")) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeLocalReplacementProject(t, root, tc.mod)
			if tc.edit != nil {
				tc.edit(t, root)
			}
			assertLocalReplacementStates(t, root, false)
		})
	}
}

func TestLocalReplacementResolvesGenericMethodValues(t *testing.T) {
	root := t.TempDir()
	writeLocalReplacementProject(t, root, "module example.com/application\n\ngo 1.22\nrequire example.com/provider v0.0.0\nreplace example.com/provider => ./local/provider\n")
	writeTestFile(t, root, "main.go", `package main
import bridge "example.com/provider/bridge"
func main() { var value bridge.Box[int]; invoke := value.Invoke; invoke(callback) }
func callback() {}
func alpha() { beta() }
func beta() { alpha() }
func orphan() {}
`)
	writeTestFile(t, root, "local/provider/bridge/api.go", "package differentName\ntype Box[T any] struct{}\nfunc (Box[T]) Invoke(callback func()) { callback() }\n")
	assertLocalReplacementStates(t, root, true)
}

func TestLocalReplacementCannotReachSiblingSource(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "selected")
	writeLocalReplacementProject(t, root, "module example.com/application\n\ngo 1.22\nrequire example.com/provider v0.0.0\nreplace example.com/provider => ../outside\n")
	writeTestFile(t, base, "outside/go.mod", "module example.com/provider\n\ngo 1.22\n")
	writeTestFile(t, base, "outside/bridge/api.go", "package differentName\nfunc Invoke(callback func()) { callback() }\n")
	assertLocalReplacementStates(t, root, false)
}

func TestLocalReplacementRejectsSymlinkMetadataAndSources(t *testing.T) {
	const module = "module example.com/application\n\ngo 1.22\nrequire example.com/provider v0.0.0\nreplace example.com/provider => ./local/provider\n"
	for _, name := range []string{"go.mod", "source"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeLocalReplacementProject(t, root, module)
			path := filepath.Join(root, "local/provider/go.mod")
			if name == "source" {
				path = filepath.Join(root, "local/provider/bridge/api.go")
			}
			bytes, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(target, bytes, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			assertLocalReplacementStates(t, root, false)
		})
	}
}
