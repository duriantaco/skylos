package symbols

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// sdkSourceImporter reads real host SDK declarations. Its cache is consulted
// before rebuilding package metadata, including for recursive SDK imports.
// Target files and their function bodies never enter this importer.
type sdkSourceImporter struct {
	fset         *token.FileSet
	context      build.Context
	sourceRoot   string
	packages     map[string]*types.Package
	failures     map[string]error
	loading      map[string]bool
	packageLoads int
	parsedFiles  int
	callerScopes map[string]bool
}

func newSDKSourceImporter(fset *token.FileSet, context build.Context) *sdkSourceImporter {
	context.CgoEnabled = false
	root := ""
	if filepath.IsAbs(context.GOROOT) {
		if resolved, err := filepath.EvalSymlinks(context.GOROOT); err == nil {
			context.GOROOT = resolved
			// A configured SDK may expose its source through a symlink while
			// retaining a separate (or guarded) bin directory. Containment is
			// relative to that resolved SDK source, not its lexical parent.
			root, _ = filepath.EvalSymlinks(filepath.Join(resolved, "src"))
		}
	}
	return &sdkSourceImporter{fset: fset, context: context, sourceRoot: root, packages: map[string]*types.Package{}, failures: map[string]error{}, loading: map[string]bool{}, callerScopes: map[string]bool{}}
}

func (i *sdkSourceImporter) Import(importPath string) (*types.Package, error) {
	return i.ImportFrom(importPath, "", 0)
}

func (i *sdkSourceImporter) ImportFrom(importPath, sourceDir string, mode types.ImportMode) (*types.Package, error) {
	if importPath == "unsafe" {
		return types.Unsafe, nil
	}
	if i.sourceRoot == "" || mode != 0 || importPath == "" || path.Clean(importPath) != importPath || path.IsAbs(importPath) || strings.HasPrefix(importPath, "../") || strings.ContainsAny(importPath, "\\\x00\" \t\r\n") || strings.HasPrefix(importPath, "vendor/") {
		return nil, fmt.Errorf("unsupported host SDK import %q", importPath)
	}
	sdkCaller := false
	if sourceDir != "" {
		if resolved, err := filepath.EvalSymlinks(sourceDir); err == nil {
			sourceDir = resolved
			sdkCaller = isPathWithinRoot(i.sourceRoot, sourceDir)
		}
	}
	if sdkCaller {
		allowed, cached := i.callerScopes[sourceDir]
		if !cached {
			allowed = true
			for current := sourceDir; current != i.sourceRoot; current = filepath.Dir(current) {
				if _, err := os.Stat(filepath.Join(current, "vendor")); err == nil || !os.IsNotExist(err) {
					allowed = false
					break
				}
			}
			i.callerScopes[sourceDir] = allowed
		}
		if !allowed {
			return nil, fmt.Errorf("nested host SDK vendor context is unsupported")
		}
	}
	key := importPath
	// Go's SDK vendor tree is visible only to SDK source, not target imports.
	if strings.Contains(strings.Split(importPath, "/")[0], ".") {
		if !sdkCaller {
			return nil, fmt.Errorf("external package %q is not a host SDK API", importPath)
		}
		key = "vendor/" + importPath
	}
	if sdkCaller && key == importPath {
		if _, err := os.Stat(filepath.Join(i.sourceRoot, "vendor", filepath.FromSlash(importPath))); err == nil || !os.IsNotExist(err) {
			return nil, fmt.Errorf("host SDK vendor override of a standard path is unsupported")
		}
	}
	if n := strings.LastIndex("/"+key, "/internal/"); n >= 0 {
		parent := strings.TrimPrefix(("/" + key)[:n], "/")
		if !sdkCaller || !isPathWithinRoot(filepath.Join(i.sourceRoot, filepath.FromSlash(parent)), sourceDir) {
			return nil, fmt.Errorf("host internal package %q is outside its source boundary", importPath)
		}
	}
	if pkg := i.packages[key]; pkg != nil {
		return pkg, nil
	}
	if err := i.failures[key]; err != nil {
		return nil, err
	}
	if i.loading[key] {
		return nil, fmt.Errorf("host SDK import cycle through %q", key)
	}
	if i.packageLoads >= 512 {
		return nil, fmt.Errorf("host SDK import budget exhausted")
	}
	dir, err := filepath.EvalSymlinks(filepath.Join(i.sourceRoot, filepath.FromSlash(key)))
	if err != nil || !isPathWithinRoot(i.sourceRoot, dir) {
		return nil, fmt.Errorf("no contained host SDK package %q", key)
	}
	i.packageLoads++
	i.loading[key] = true
	defer delete(i.loading, key)
	descriptor, err := i.context.ImportDir(dir, 0)
	if err != nil {
		i.failures[key] = err
		return nil, err
	}
	if len(descriptor.CgoFiles) != 0 || len(descriptor.GoFiles) == 0 || descriptor.Name == "main" {
		return nil, fmt.Errorf("host SDK package %q requires unsupported source", key)
	}
	files := make([]*ast.File, 0, len(descriptor.GoFiles))
	for _, name := range descriptor.GoFiles {
		filename := filepath.Join(dir, name)
		info, err := os.Lstat(filename)
		if err != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("host SDK file is not regular")
		}
		file, err := parser.ParseFile(i.fset, filename, nil, parser.SkipObjectResolution)
		if err != nil {
			i.failures[key] = err
			return nil, err
		}
		i.parsedFiles++
		// IgnoreFuncBodies already excludes these implementations from API proof.
		// Drop them before recursive imports to avoid retaining their full ASTs.
		for _, declaration := range file.Decls {
			if fn, ok := declaration.(*ast.FuncDecl); ok {
				if fn.Body != nil {
					fn.Body = &ast.BlockStmt{Lbrace: fn.Body.Lbrace, Rbrace: fn.Body.Rbrace}
				}
			}
		}
		files = append(files, file)
	}
	config := types.Config{Importer: i, IgnoreFuncBodies: true, Sizes: types.SizesFor(i.context.Compiler, i.context.GOARCH), Error: func(error) {}}
	pkg, err := config.Check(key, i.fset, files, nil)
	if err != nil || pkg == nil || !pkg.Complete() {
		if err == nil {
			err = fmt.Errorf("incomplete host SDK package %q", key)
		}
		i.failures[key] = err
		return nil, err
	}
	i.packages[key] = pkg
	return pkg, nil
}
