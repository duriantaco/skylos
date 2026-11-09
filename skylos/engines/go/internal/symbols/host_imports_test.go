package symbols

import (
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"testing"
)

func TestHostStdlibImporterLoadsSourceWithSymlinkedToolchain(t *testing.T) {
	imp := newHostStdlibImporter(token.NewFileSet()).(*hostStdlibImporter)
	if !validHostGOROOT(imp.root) {
		t.Fatal("the engine test's host Go standard library is unavailable")
	}
	link := filepath.Join(t.TempDir(), "host-go")
	if err := os.Symlink(imp.root, link); err != nil {
		t.Skipf("toolchain symlinks unavailable: %v", err)
	}
	imp.root = link
	pkg, err := imp.Import("strconv")
	if err != nil {
		t.Fatal(err)
	}
	if !pkg.Complete() || pkg.Scope().Lookup("Itoa") == nil {
		t.Fatal("source fallback must provide the real complete strconv API")
	}
	if again, err := imp.Import("strconv"); err != nil || again != pkg {
		t.Fatal("repeated imports must preserve package object identity")
	}
	for _, name := range []string{"../outside", "/tmp/outside", "example.invalid/target", "strconv/../fmt"} {
		if _, err := imp.Import(name); err == nil {
			t.Errorf("untrusted/noncanonical import %q was accepted", name)
		}
	}
}

func TestHostStdlibImporterMissingToolchainDoesNotInventTypes(t *testing.T) {
	imp := &hostStdlibImporter{cache: map[string]*types.Package{}}
	if _, err := imp.Import("testing"); err == nil {
		t.Fatal("a missing host toolchain cannot provide type evidence")
	}
}
