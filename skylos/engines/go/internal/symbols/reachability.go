package symbols

import (
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
)

type reachabilityFile struct {
	file   *ast.File
	path   string
	pkgDir string
}

// markFunctionReachability adds proof only for packages that fully type-check.
// The graph follows declaration uses, including function values, rather than
// counting text references from dead functions as roots. Local objects with the
// same spelling as a package function therefore cannot keep that function live.
// It deliberately keeps the legacy reference evidence when imports, build
// variants or other type errors prevent a complete package proof.
func markFunctionReachability(result *Result, files []reachabilityFile, fset *token.FileSet, modulePath string, importer types.Importer) {
	packages := map[string][]reachabilityFile{}
	for _, file := range files {
		key := file.pkgDir + "\x00" + file.file.Name.Name
		packages[key] = append(packages[key], file)
	}
	defsByFile := map[string][]*Def{}
	allNames := map[string]bool{}
	for i := range result.Defs {
		def := &result.Defs[i]
		defsByFile[def.File] = append(defsByFile[def.File], def)
		allNames[def.Name] = true
	}
	preciseFiles := map[string]bool{}
	preciseRefs := []Ref{}
	for _, pkgFiles := range packages {
		packageDefs := map[string]*Def{}
		for _, file := range pkgFiles {
			for _, def := range defsByFile[file.path] {
				packageDefs[def.Name] = def
			}
		}
		refs, complete := markPackageFunctionReachability(packageDefs, pkgFiles, fset, modulePath, importer, allNames)
		if complete {
			preciseRefs = append(preciseRefs, refs...)
			for _, file := range pkgFiles {
				preciseFiles[file.path] = true
			}
		}
	}
	refs := []Ref{}
	for _, ref := range result.Refs {
		if !preciseFiles[ref.File] {
			refs = append(refs, ref)
		}
	}
	result.Refs = append(refs, preciseRefs...)
}

func markPackageFunctionReachability(defs map[string]*Def, files []reachabilityFile, fset *token.FileSet, modulePath string, importer types.Importer, allNames map[string]bool) ([]Ref, bool) {
	if len(files) == 0 || packageHasAssembly(filepath.Dir(files[0].path)) {
		return nil, false
	}
	if project, ok := importer.(*projectSourceImporter); ok && project.incompleteDirs[filepath.Dir(files[0].path)] {
		return nil, false
	}
	info := &types.Info{
		Defs: map[*ast.Ident]types.Object{},
		Uses: map[*ast.Ident]types.Object{},
	}
	conf := types.Config{Importer: importer, Error: func(error) {}}
	if project, ok := importer.(*projectSourceImporter); ok {
		conf.GoVersion = project.languageVersionForDirectory(filepath.Dir(files[0].path))
	}
	asts := make([]*ast.File, 0, len(files))
	for _, file := range files {
		asts = append(asts, file.file)
	}
	importPath := packageImportPath(modulePath, files[0].pkgDir, files[0].file.Name.Name)
	if project, ok := importer.(*projectSourceImporter); ok {
		var known bool
		importPath, known = project.packagePath(files[0].pkgDir, files[0].file.Name.Name)
		if !known {
			return nil, false
		}
	}
	checkedPkg, err := conf.Check(importPath, fset, asts, info)
	if err != nil {
		return nil, false
	}

	objects := map[types.Object]string{}
	for _, object := range info.Defs {
		if object != nil && object.Parent() == checkedPkg.Scope() {
			name := qname(files[0].pkgDir, object.Name())
			if defs[name] != nil {
				objects[object] = name
			}
		}
	}
	roots := map[string]bool{}
	edges := map[string]map[string]bool{}
	owners := map[*ast.FuncDecl]string{}
	for _, file := range files {
		generated := generatedReachabilityFile(file)
		isTest := strings.HasSuffix(file.path, "_test.go")
		for _, decl := range file.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			name := typedCallerName(fn, file.pkgDir)
			owners[fn] = name
			if object := info.Defs[fn.Name]; object != nil && defs[name] != nil {
				objects[object] = name
			}
			def := defs[name]
			if (isTest && (def == nil || !def.TestHelper)) || generated || fn.Body == nil || fn.Name.Name == "init" || (def != nil && def.IsExported) || hasExportDirective(fn) {
				roots[name] = true
			}
		}
	}
	preciseRefs := []Ref{}
	// Linkname can be declared separately from the function. Treat every valid
	// local name conservatively as an external entry point.
	for _, file := range files {
		for _, group := range file.file.Comments {
			for _, comment := range group.List {
				fields := strings.Fields(comment.Text)
				if len(fields) >= 2 && fields[0] == "//go:linkname" {
					roots[qname(file.pkgDir, fields[1])] = true
				}
			}
		}
	}
	for _, file := range files {
		for _, decl := range file.file.Decls {
			owner := ""
			if fn, ok := decl.(*ast.FuncDecl); ok {
				owner = owners[fn]
			}
			ast.Inspect(decl, func(node ast.Node) bool {
				if iface, ok := node.(*ast.InterfaceType); ok && iface.Methods != nil {
					// Private methods can be invoked through anonymous interfaces
					// without a selector whose object names the concrete method.
					// Retain possible implementations when the interface's owner
					// is live, matching the existing conservative named-interface
					// policy rather than pretending dispatch is a direct call.
					for _, field := range iface.Methods.List {
						for _, method := range field.Names {
							for name, def := range defs {
								if def.Type != "method" || !strings.HasSuffix(name, "."+method.Name) {
									continue
								}
								if owner == "" {
									roots[name] = true
								} else {
									if edges[owner] == nil {
										edges[owner] = map[string]bool{}
									}
									edges[owner][name] = true
								}
							}
						}
					}
				}
				ident, ok := node.(*ast.Ident)
				if !ok {
					return true
				}
				object := info.Uses[ident]
				if fn, ok := object.(*types.Func); ok {
					object = fn.Origin()
				}
				target := objects[object]
				if target == "" {
					target = projectObjectName(object, modulePath, allNames, importer)
				}
				if target == "" {
					return true
				}
				preciseRefs = append(preciseRefs, Ref{Name: target, File: file.path})
				if owner == "" {
					// Package initialization and function values in declarations
					// are roots even when their variable is not read elsewhere.
					roots[target] = true
				} else {
					if edges[owner] == nil {
						edges[owner] = map[string]bool{}
					}
					edges[owner][target] = true
				}
				return true
			})
		}
	}
	live := map[string]bool{}
	queue := make([]string, 0, len(roots))
	for root := range roots {
		queue = append(queue, root)
	}
	for len(queue) > 0 {
		current := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if live[current] {
			continue
		}
		live[current] = true
		for target := range edges[current] {
			queue = append(queue, target)
		}
	}
	for _, name := range owners {
		if def := defs[name]; def != nil {
			def.Reachability = "unreachable"
			if live[name] {
				def.Reachability = "reachable"
			}
		}
	}
	return preciseRefs, true
}

func projectObjectName(object types.Object, modulePath string, names map[string]bool, importer types.Importer) string {
	if object == nil || object.Pkg() == nil {
		return ""
	}
	pkgPath := object.Pkg().Path()
	dir := ""
	if project, ok := importer.(*projectSourceImporter); ok {
		dir = project.objectPackageDirectory(pkgPath)
	} else if pkgPath == modulePath || strings.HasPrefix(pkgPath, modulePath+"/") {
		dir = strings.TrimPrefix(strings.TrimPrefix(pkgPath, modulePath), "/")
		if dir == "" {
			dir = "."
		}
	}
	if dir == "" {
		return ""
	}
	name := ""
	if _, receiver := receiverNameFromMethod(object); receiver != "" {
		name = qname(dir, receiver, object.Name())
	} else if object.Parent() == object.Pkg().Scope() {
		name = qname(dir, object.Name())
	}
	if names[name] {
		return name
	}
	return ""
}

func packageHasAssembly(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return true
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".s") || strings.HasSuffix(entry.Name(), ".S") {
			return true
		}
	}
	return false
}

func generatedReachabilityFile(file reachabilityFile) bool {
	if strings.HasSuffix(file.path, ".pb.go") {
		return true
	}
	// Match the Python generated-file policy, including noncanonical headers.
	data, err := os.ReadFile(file.path)
	if err != nil {
		return false
	}
	if len(data) > 4096 {
		data = data[:4096]
	}
	prefix := strings.ToLower(string(data))
	return strings.Contains(prefix, "code generated") && strings.Contains(prefix, "do not edit")
}

func hasExportDirective(fn *ast.FuncDecl) bool {
	if fn.Doc != nil {
		for _, comment := range fn.Doc.List {
			if strings.HasPrefix(comment.Text, "//export ") {
				return true
			}
		}
	}
	return false
}
