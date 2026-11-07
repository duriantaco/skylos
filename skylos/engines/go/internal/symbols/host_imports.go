package symbols

import (
	"context"
	"fmt"
	"go/build"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

var hostContextOnce sync.Once
var targetBuildContext = build.Default

// A trimmed standalone binary has no embedded GOROOT. Discover an installed
// host toolchain before using go/build; never ask the scanned module to choose
// a toolchain or resolve dependencies. All Extract callers pass this once gate.
func ensureHostBuildContext() {
	hostContextOnce.Do(func() {
		defer func() {
			// Preserve target build-tag selection while keeping the source
			// importer entirely static: its host-library context must never
			// invoke cgo or a C compiler to discover an API.
			targetBuildContext = build.Default
			build.Default.CgoEnabled = false
		}()
		candidates := []string{build.Default.GOROOT, runtime.GOROOT()}
		goBin, err := exec.LookPath("go")
		if err == nil {
			if resolved, resolveErr := filepath.EvalSymlinks(goBin); resolveErr == nil {
				candidates = append(candidates, filepath.Dir(filepath.Dir(resolved)))
			}
		}
		for _, candidate := range candidates {
			if validHostGOROOT(candidate) {
				build.Default.GOROOT, _ = filepath.EvalSymlinks(candidate)
				return
			}
		}
		if err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, goBin, "env", "GOROOT")
		cmd.Dir = os.TempDir()
		cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOENV=off")
		if output, cmdErr := cmd.Output(); cmdErr == nil {
			candidate := strings.TrimSpace(string(output))
			if validHostGOROOT(candidate) {
				build.Default.GOROOT, _ = filepath.EvalSymlinks(candidate)
			}
		}
	})
}

func validHostGOROOT(root string) bool {
	if root == "" || !filepath.IsAbs(root) {
		return false
	}
	info, err := os.Stat(filepath.Join(root, "src", "builtin", "builtin.go"))
	return err == nil && info.Mode().IsRegular()
}

type hostStdlibImporter struct {
	source types.Importer
	root   string
	cache  map[string]*types.Package
}

func newHostStdlibImporter(fset *token.FileSet) types.Importer {
	ensureHostBuildContext()
	return &hostStdlibImporter{
		source: newSDKSourceImporter(fset, build.Default),
		root:   build.Default.GOROOT,
		cache:  map[string]*types.Package{},
	}
}

func (i *hostStdlibImporter) Import(importPath string) (*types.Package, error) {
	if importPath == "unsafe" {
		return types.Unsafe, nil
	}
	if cached := i.cache[importPath]; cached != nil {
		return cached, nil
	}
	// Only trusted host standard-library files can be imported. Missing module
	// dependencies remain unknown; neither Go nor package scripts run on them.
	if i.root == "" || importPath == "." || path.IsAbs(importPath) || path.Clean(importPath) != importPath || strings.HasPrefix(importPath, "../") {
		return nil, fmt.Errorf("no host standard-library package for %q", importPath)
	}
	sourceRoot, err := filepath.EvalSymlinks(filepath.Join(i.root, "src"))
	if err != nil {
		return nil, fmt.Errorf("no host standard-library package for %q", importPath)
	}
	dir, err := filepath.EvalSymlinks(filepath.Join(sourceRoot, filepath.FromSlash(importPath)))
	if err != nil || !isPathWithinRoot(sourceRoot, dir) {
		return nil, fmt.Errorf("no host standard-library package for %q", importPath)
	}
	// Load host source directly. The export importer can run go list -export and
	// build a cold cache before returning; static analysis must not incur that
	// build cost. cgo or unsupported source fails the complete-check guard.
	pkg, err := i.source.Import(importPath)
	if err == nil && pkg.Complete() {
		i.cache[importPath] = pkg
	}
	return pkg, err
}
