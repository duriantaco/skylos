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
// A direct local replacement can supply module identity only when its source
// is already indexed inside the scan. No Go dependency discovery is performed.
type projectSourceImporter struct {
	host           types.Importer
	fset           *token.FileSet
	root           string
	modulePath     string
	files          map[string][]*ast.File
	dirs           map[string]string
	modules        map[string]string
	goVersions     map[string]string
	ambiguous      map[string]bool
	cache          map[string]*types.Package
	failures       map[string]error
	loading        map[string]bool
	remaining      int
	sourceFiles    map[string]bool
	incompleteDirs map[string]bool
}

func newProjectSourceImporter(root, modulePath string, fset *token.FileSet, files []reachabilityFile, host types.Importer) types.Importer {
	imp := &projectSourceImporter{
		host: host, fset: fset, root: root, modulePath: modulePath,
		files: map[string][]*ast.File{}, cache: map[string]*types.Package{},
		failures: map[string]error{}, loading: map[string]bool{}, remaining: 512,
		dirs: map[string]string{}, ambiguous: map[string]bool{},
	}
	if modulePath != "" && (path.Clean(modulePath) != modulePath || strings.ContainsAny(modulePath, "\\\" \t\r\n") || path.IsAbs(modulePath)) {
		imp.modulePath = ""
		return imp
	}
	if modules, versions, active := workspaceSourceModules(root); active {
		imp.goVersions = versions
		imp.modules = modules
		if len(modules) == 0 && modulePath != "" {
			imp.modules = map[string]string{root: modulePath}
		}
	} else if modulePath != "" {
		imp.modules = localReplacementModules(root, modulePath)
	}
	for _, file := range files {
		if strings.HasSuffix(file.path, "_test.go") {
			continue
		}
		importPath, known := imp.packagePath(file.pkgDir, file.file.Name.Name)
		if !known {
			continue
		}
		dir := filepath.Dir(file.path)
		if previous := imp.dirs[importPath]; previous != "" && previous != dir {
			imp.ambiguous[importPath] = true
		}
		imp.dirs[importPath] = dir
		imp.files[importPath] = append(imp.files[importPath], file.file)
	}
	return imp
}

func (i *projectSourceImporter) Import(importPath string) (*types.Package, error) {
	dir := i.dirs[importPath]
	if dir == "" && (i.modulePath == "" || (importPath != i.modulePath && !strings.HasPrefix(importPath, i.modulePath+"/"))) {
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
	if dir == "" || i.ambiguous[importPath] || !isPathWithinRoot(i.root, dir) || !i.sameModule(dir) {
		return nil, fmt.Errorf("project import %q crosses the scanned module", importPath)
	}
	files := i.files[importPath]
	if i.incompleteDirs[dir] {
		return nil, fmt.Errorf("project package %q has source outside the admitted scope", importPath)
	}
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
	conf := types.Config{Importer: i, Error: func(error) {}, GoVersion: i.languageVersionForDirectory(dir)}
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
	_, _, known := i.moduleForDirectory(dir)
	return known
}

func (i *projectSourceImporter) moduleForDirectory(dir string) (string, string, bool) {
	for current := dir; isPathWithinRoot(i.root, current); current = filepath.Dir(current) {
		info, err := os.Lstat(filepath.Join(current, "go.mod"))
		if err == nil {
			prefix := i.modules[current]
			return current, prefix, prefix != "" && info.Mode().IsRegular()
		}
		if !os.IsNotExist(err) || current == i.root {
			break
		}
	}
	return "", "", false
}

func (i *projectSourceImporter) packagePath(pkgDir, pkgName string) (string, bool) {
	if i.modulePath == "" && len(i.modules) == 0 {
		return packageImportPath("", pkgDir, pkgName), true
	}
	dir := filepath.Join(i.root, filepath.FromSlash(pkgDir))
	base, prefix, known := i.moduleForDirectory(dir)
	if !known {
		return "", false
	}
	rel, err := filepath.Rel(base, dir)
	if err != nil {
		return "", false
	}
	return packageImportPath(prefix, filepath.ToSlash(rel), pkgName), true
}

func (i *projectSourceImporter) objectPackageDirectory(importPath string) string {
	dir := i.dirs[importPath]
	if dir == "" || i.ambiguous[importPath] {
		return ""
	}
	rel, err := filepath.Rel(i.root, dir)
	if err != nil || !isPathWithinRoot(i.root, dir) {
		return ""
	}
	return filepath.ToSlash(rel)
}

func (i *projectSourceImporter) languageVersionForDirectory(dir string) string {
	if len(i.goVersions) == 0 {
		return ""
	}
	base, _, known := i.moduleForDirectory(dir)
	if !known {
		return ""
	}
	return i.goVersions[base]
}
