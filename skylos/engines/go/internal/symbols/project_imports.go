package symbols

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// projectSourceImporter only loads packages already present in the source scan.
// It never follows go.mod replacements, discovers dependencies through Go, or
// reads source outside the current module. Incomplete imports invalidate the
// caller's full type-check proof instead of inventing a package API.
type projectSourceImporter struct {
	host       types.Importer
	fset       *token.FileSet
	root       string
	modulePath string
	files      map[string][]*ast.File
	cache      map[string]*types.Package
	failures   map[string]error
	loading    map[string]bool
	remaining  int
}

func newProjectSourceImporter(root, modulePath string, fset *token.FileSet, files []reachabilityFile, host types.Importer) types.Importer {
	imp := &projectSourceImporter{
		host: host, fset: fset, root: root, modulePath: modulePath,
		files: map[string][]*ast.File{}, cache: map[string]*types.Package{},
		failures: map[string]error{}, loading: map[string]bool{}, remaining: 512,
	}
	if modulePath == "" || path.Clean(modulePath) != modulePath || strings.ContainsAny(modulePath, "\\\" \t\r\n") || path.IsAbs(modulePath) {
		imp.modulePath = ""
		return imp
	}
	for _, file := range files {
		if strings.HasSuffix(file.path, "_test.go") {
			continue
		}
		importPath := packageImportPath(modulePath, file.pkgDir, file.file.Name.Name)
		imp.files[importPath] = append(imp.files[importPath], file.file)
	}
	return imp
}

func (i *projectSourceImporter) Import(importPath string) (*types.Package, error) {
	if i.modulePath == "" || (importPath != i.modulePath && !strings.HasPrefix(importPath, i.modulePath+"/")) {
		return i.host.Import(importPath)
	}
	if pkg := i.cache[importPath]; pkg != nil {
		return pkg, nil
	}
	if err := i.failures[importPath]; err != nil {
		return nil, err
	}
	if i.loading[importPath] {
		return nil, fmt.Errorf("project import cycle through %q", importPath)
	}
	if i.remaining <= 0 {
		return nil, fmt.Errorf("project import budget exhausted")
	}
	if path.Clean(importPath) != importPath || strings.ContainsAny(importPath, "\\\" \t\r\n") {
		return nil, fmt.Errorf("noncanonical project import %q", importPath)
	}
	rel := strings.TrimPrefix(strings.TrimPrefix(importPath, i.modulePath), "/")
	dir := filepath.Join(i.root, filepath.FromSlash(rel))
	if !isPathWithinRoot(i.root, dir) || !i.sameModule(dir) {
		return nil, fmt.Errorf("project import %q crosses the scanned module", importPath)
	}
	files := i.files[importPath]
	if len(files) == 0 || files[0].Name.Name == "main" {
		return nil, fmt.Errorf("no indexed importable project package %q", importPath)
	}
	if packageHasAssembly(dir) || opaqueProjectAPI(files) {
		return nil, fmt.Errorf("project package %q has opaque native consumers", importPath)
	}
	// Alternate build files are deliberately kept together, as in the local
	// reachability proof. Conflicting variants fail rather than hiding consumers.
	for _, file := range files {
		if file.Name.Name != files[0].Name.Name {
			return nil, fmt.Errorf("ambiguous package declarations for %q", importPath)
		}
	}
	i.remaining--
	i.loading[importPath] = true
	defer delete(i.loading, importPath)
	conf := types.Config{Importer: i, Error: func(error) {}}
	pkg, err := conf.Check(importPath, i.fset, files, nil)
	if err != nil || !pkg.Complete() {
		if err == nil {
			err = fmt.Errorf("incomplete project package %q", importPath)
		}
		i.failures[importPath] = err
		return nil, err
	}
	i.cache[importPath] = pkg
	return pkg, nil
}

func opaqueProjectAPI(files []*ast.File) bool {
	for _, file := range files {
		for _, imported := range file.Imports {
			name, err := strconv.Unquote(imported.Path.Value)
			if err != nil || name == "C" || name == "unsafe" {
				return true
			}
		}
		for _, group := range file.Comments {
			for _, comment := range group.List {
				if strings.HasPrefix(comment.Text, "//go:linkname ") {
					return true
				}
			}
		}
	}
	return false
}

func (i *projectSourceImporter) sameModule(dir string) bool {
	for current := dir; isPathWithinRoot(i.root, current); current = filepath.Dir(current) {
		info, err := os.Lstat(filepath.Join(current, "go.mod"))
		if err == nil {
			return current == i.root && info.Mode().IsRegular()
		}
		if !os.IsNotExist(err) || current == i.root {
			return false
		}
	}
	return false
}
