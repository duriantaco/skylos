package symbols

import (
	"go/build"
	"go/importer"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func sdkAPISnapshot(pkg *types.Package) []string {
	var rows []string
	q := func(p *types.Package) string { return p.Path() }
	for _, name := range pkg.Scope().Names() {
		object := pkg.Scope().Lookup(name)
		row := name + ":" + types.TypeString(object.Type(), q)
		if value, ok := object.(*types.Const); ok {
			row += "=" + value.Val().ExactString()
		}
		if _, ok := object.(*types.TypeName); ok {
			row += " underlying=" + types.TypeString(object.Type().Underlying(), q)
			for _, typ := range []types.Type{object.Type(), types.NewPointer(object.Type())} {
				methods := types.NewMethodSet(typ)
				for index := 0; index < methods.Len(); index++ {
					m := methods.At(index)
					row += " method=" + m.Obj().Name() + ":" + types.TypeString(m.Type(), q)
				}
			}
		}
		rows = append(rows, row)
	}
	sort.Strings(rows)
	return rows
}

func TestHostSDKAPIParity(t *testing.T) {
	ensureHostBuildContext()
	reference := importer.ForCompiler(token.NewFileSet(), "source", nil)
	candidate := newHostStdlibImporter(token.NewFileSet())
	for _, path := range []string{"fmt", "io", "net/http", "testing", "archive/zip", "os/exec"} {
		t.Run(path, func(t *testing.T) {
			expected, err := reference.Import(path)
			if err != nil {
				t.Fatal(err)
			}
			got, err := candidate.Import(path)
			if err != nil {
				t.Fatal(err)
			}
			a, b := sdkAPISnapshot(expected), sdkAPISnapshot(got)
			if !reflect.DeepEqual(a, b) {
				old, new := map[string]bool{}, map[string]bool{}
				for _, x := range a {
					old[x] = true
				}
				for _, x := range b {
					new[x] = true
				}
				for _, x := range a {
					if !new[x] {
						t.Errorf("missing %s", x)
					}
				}
				for _, x := range b {
					if !old[x] {
						t.Errorf("extra %s", x)
					}
				}
			}
		})
	}
}

func TestHostSDKContextsDoNotLeakCachedTypes(t *testing.T) {
	root := t.TempDir()
	for name, source := range map[string]string{
		"src/base/api.go":                          "package base\nimport dep \"outside.test/dep\"\nimport hidden \"internal/hidden\"\ntype Value = dep.Value\ntype Sealed = hidden.Value\n",
		"src/vendor/outside.test/dep/api.go":       "package dep\ntype Value struct { Number int }\n",
		"src/internal/hidden/api.go":               "package hidden\ntype Value struct { Value int }\n",
		"src/group/vendor/outside.test/dep/api.go": "package dep\ntype Value string\n",
		"src/group/client/api.go":                  "package client\nimport dep \"outside.test/dep\"\ntype Value = dep.Value\n",
	} {
		writeTestFile(t, root, name, source)
	}
	context := build.Default
	context.GOROOT = root
	imp := newSDKSourceImporter(token.NewFileSet(), context)
	if _, err := imp.Import("base"); err != nil {
		t.Fatal(err)
	}
	if _, err := imp.Import("outside.test/dep"); err == nil {
		t.Fatal("SDK vendor escaped into target import")
	}
	if _, err := imp.Import("internal/hidden"); err == nil {
		t.Fatal("SDK internal cache escaped into target import")
	}
	if _, err := imp.Import("group/client"); err == nil {
		t.Fatal("nested vendor context used a global cached provider")
	}
	if _, err := imp.Import("base"); err != nil {
		t.Fatal("unsupported vendor context poisoned a distinct safe import", err)
	}
}

func TestHostSDKKeepsInitializersAndGenericAPIs(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "src/values/api.go", `package values
const Count=3
type Alias = int
var Entries = [...]int{1,2,3}
var Factory = func() [2]string {return [2]string{"a","b"}}
var Built = Factory()
func Identity[T any](v T) T {return v}
func implementation() int {return nonexistentBodyName()}
`)
	context := build.Default
	context.GOROOT = root
	imp := newSDKSourceImporter(token.NewFileSet(), context)
	pkg, err := imp.Import("values")
	if err != nil {
		t.Fatal(err)
	}
	if got := pkg.Scope().Lookup("Count").(*types.Const).Val().ExactString(); got != "3" {
		t.Fatal(got)
	}
	if got := types.TypeString(pkg.Scope().Lookup("Entries").Type(), nil); got != "[3]int" {
		t.Fatal(got)
	}
	if got := types.TypeString(pkg.Scope().Lookup("Built").Type(), nil); got != "[2]string" {
		t.Fatal(got)
	}
	if signature := pkg.Scope().Lookup("Identity").Type().(*types.Signature); signature.TypeParams().Len() != 1 {
		t.Fatal(signature)
	}
}

func TestHostSDKReadsPackageMetadataOnce(t *testing.T) {
	ensureHostBuildContext()
	context := build.Default
	loads := map[string]int{}
	context.ReadDir = func(dir string) ([]fs.FileInfo, error) {
		loads[dir]++
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		infos := make([]fs.FileInfo, 0, len(entries))
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				return nil, err
			}
			infos = append(infos, info)
		}
		return infos, nil
	}
	imp := newSDKSourceImporter(token.NewFileSet(), context)
	for _, path := range []string{"fmt", "io", "fmt", "io"} {
		first, err := imp.Import(path)
		if err != nil {
			t.Fatal(err)
		}
		again, err := imp.Import(path)
		if err != nil || first != again {
			t.Fatal("package identity changed", path, err)
		}
	}
	for dir, count := range loads {
		if count != 1 {
			t.Fatalf("%s metadata loaded %d times", dir, count)
		}
	}
	if len(loads) < 2 {
		t.Fatal("test did not inspect actual SDK source")
	}
}

func TestHostSDKRootAndArchitectureContextStaySeparate(t *testing.T) {
	roots := []string{t.TempDir(), t.TempDir()}
	for index, root := range roots {
		kind := "int"
		if index == 1 {
			kind = "string"
		}
		writeTestFile(t, root, "src/values/api.go", "package values\nimport \"unsafe\"\ntype Value "+kind+"\nconst Word=unsafe.Sizeof(uintptr(0))\n")
	}
	var packages []*types.Package
	for _, arm := range []struct{ root, arch, want string }{
		{roots[0], "amd64", "8"}, {roots[0], "386", "4"}, {roots[1], "amd64", "8"},
	} {
		context := build.Default
		context.GOROOT = arm.root
		context.GOARCH = arm.arch
		pkg, err := newSDKSourceImporter(token.NewFileSet(), context).Import("values")
		if err != nil {
			t.Fatal(err)
		}
		if got := pkg.Scope().Lookup("Word").(*types.Const).Val().ExactString(); got != arm.want {
			t.Fatalf("%s word=%s want%s", arm.arch, got, arm.want)
		}
		packages = append(packages, pkg)
	}
	if packages[0] == packages[1] || packages[0] == packages[2] {
		t.Fatal("package identity crossed SDK context")
	}
	if got := types.TypeString(packages[2].Scope().Lookup("Value").Type().Underlying(), nil); got != "string" {
		t.Fatal(got)
	}
}

func TestHostSDKSourceRootSymlinkPreservesPackageContainment(t *testing.T) {
	root, source, outside := t.TempDir(), t.TempDir(), t.TempDir()
	writeTestFile(t, source, "values/api.go", "package values\ntype Value int\n")
	writeTestFile(t, outside, "api.go", "package escaped\ntype Value string\n")
	if err := os.Symlink(source, filepath.Join(root, "src")); err != nil {
		t.Skipf("requires host SDK source symlinks: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(source, "escaped")); err != nil {
		t.Fatal(err)
	}
	context := build.Default
	context.GOROOT = root
	imp := newSDKSourceImporter(token.NewFileSet(), context)
	if _, err := imp.Import("values"); err != nil {
		t.Fatal("configured SDK source root is unreadable", err)
	}
	if _, err := imp.Import("escaped"); err == nil {
		t.Fatal("package symlink escaped the configured SDK source root")
	}
}
