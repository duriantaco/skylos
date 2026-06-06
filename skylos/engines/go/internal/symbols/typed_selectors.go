package symbols

import (
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type parsedPackage struct {
	files      []*ast.File
	fset       *token.FileSet
	importPath string
	pkgDir     string
}

func collectTypedSelectorRefs(
	root string,
	resolvedRoot string,
	modulePath string,
	pkgDirs map[string]string,
	defNames map[string]bool,
) ([]Ref, []CallPair) {
	packages := collectParsedPackages(root, resolvedRoot, modulePath)
	refs := []Ref{}
	calls := []CallPair{}

	for _, pkg := range packages {
		pkgRefs, pkgCalls := resolveTypedSelectors(pkg, modulePath, root, pkgDirs, defNames)
		refs = append(refs, pkgRefs...)
		calls = append(calls, pkgCalls...)
	}

	return refs, calls
}

func collectParsedPackages(root, resolvedRoot, modulePath string) []parsedPackage {
	fset := token.NewFileSet()
	packagesByKey := map[string]*parsedPackage{}

	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			name := info.Name()
			if defaultSkipDirs[name] || (strings.HasPrefix(name, ".") && name != ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		resolvedPath, resolveErr := filepath.EvalSymlinks(path)
		if resolveErr != nil || !isPathWithinRoot(resolvedRoot, resolvedPath) {
			return nil
		}
		if !matchesCurrentBuild(resolvedPath) {
			return nil
		}

		file, parseErr := parser.ParseFile(fset, resolvedPath, nil, 0)
		if parseErr != nil {
			return nil
		}

		pkgDir := pkgDirKey(root, resolvedPath)
		key := pkgDir + "\x00" + file.Name.Name
		pkg := packagesByKey[key]
		if pkg == nil {
			pkg = &parsedPackage{
				files:      []*ast.File{},
				fset:       fset,
				importPath: packageImportPath(modulePath, pkgDir, file.Name.Name),
				pkgDir:     pkgDir,
			}
			packagesByKey[key] = pkg
		}
		pkg.files = append(pkg.files, file)

		return nil
	})

	packages := []parsedPackage{}
	keys := make([]string, 0, len(packagesByKey))
	for key := range packagesByKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		packages = append(packages, *packagesByKey[key])
	}
	return packages
}

func matchesCurrentBuild(path string) bool {
	ok, err := build.Default.MatchFile(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return true
	}
	return ok
}

func packageImportPath(modulePath, pkgDir, pkgName string) string {
	if modulePath == "" {
		if pkgDir == "." {
			return pkgName
		}
		return pkgDir
	}
	if pkgDir == "." {
		return modulePath
	}
	return modulePath + "/" + pkgDir
}

func resolveTypedSelectors(
	pkg parsedPackage,
	modulePath string,
	root string,
	pkgDirs map[string]string,
	defNames map[string]bool,
) ([]Ref, []CallPair) {
	info := &types.Info{
		Selections: map[*ast.SelectorExpr]*types.Selection{},
		Uses:       map[*ast.Ident]types.Object{},
	}
	conf := types.Config{
		Importer: importer.Default(),
		Error: func(error) {
		},
	}
	_, _ = conf.Check(pkg.importPath, pkg.fset, pkg.files, info)
	if len(info.Selections) == 0 {
		return nil, nil
	}

	refs := []Ref{}
	calls := []CallPair{}

	for _, file := range pkg.files {
		for _, decl := range file.Decls {
			funcDecl, ok := decl.(*ast.FuncDecl)
			if !ok || funcDecl.Body == nil {
				continue
			}

			fileRefs, fileCalls := resolveFuncTypedSelectors(
				funcDecl,
				pkg,
				info,
				modulePath,
				root,
				pkgDirs,
				defNames,
			)
			refs = append(refs, fileRefs...)
			calls = append(calls, fileCalls...)
		}
	}

	return refs, calls
}

func resolveFuncTypedSelectors(
	funcDecl *ast.FuncDecl,
	pkg parsedPackage,
	info *types.Info,
	modulePath string,
	root string,
	pkgDirs map[string]string,
	defNames map[string]bool,
) ([]Ref, []CallPair) {
	callerName := typedCallerName(funcDecl, pkg.pkgDir)
	refs := []Ref{}
	calls := []CallPair{}

	ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			refName := typedSelectionName(node, info, pkg, modulePath, root, pkgDirs, defNames)
			if refName != "" {
				refs = append(refs, Ref{
					Name: refName,
					File: pkg.fset.Position(node.Pos()).Filename,
				})
			}
		case *ast.CallExpr:
			selector, ok := node.Fun.(*ast.SelectorExpr)
			if !ok {
				break
			}

			calleeName := typedSelectionName(selector, info, pkg, modulePath, root, pkgDirs, defNames)
			if calleeName != "" {
				calls = append(calls, CallPair{
					Caller: callerName,
					Callee: calleeName,
				})
			}
		}
		return true
	})

	return refs, calls
}

func typedCallerName(funcDecl *ast.FuncDecl, pkgDir string) string {
	if funcDecl.Recv != nil && len(funcDecl.Recv.List) > 0 {
		recv := receiverTypeName(funcDecl.Recv.List[0].Type)
		return qname(pkgDir, recv, funcDecl.Name.Name)
	}
	return qname(pkgDir, funcDecl.Name.Name)
}

func typedSelectionName(
	selector *ast.SelectorExpr,
	info *types.Info,
	pkg parsedPackage,
	modulePath string,
	root string,
	pkgDirs map[string]string,
	defNames map[string]bool,
) string {
	selection := info.Selections[selector]
	if selection == nil {
		return ""
	}
	if selection.Kind() != types.MethodVal && selection.Kind() != types.MethodExpr {
		return ""
	}

	receiverPkgPath, receiverName := receiverNameFromMethod(selection.Obj())
	if receiverName == "" {
		return ""
	}

	targetPkgDir := pkg.pkgDir
	if receiverPkgPath != "" && receiverPkgPath != pkg.importPath {
		resolvedPkgDir := resolveImportToPkgDir(receiverPkgPath, modulePath, root, pkgDirs)
		if resolvedPkgDir == "" {
			return ""
		}
		targetPkgDir = resolvedPkgDir
	}

	name := qname(targetPkgDir, receiverName, selection.Obj().Name())
	if !defNames[name] {
		return ""
	}
	return name
}

func receiverNameFromMethod(obj types.Object) (string, string) {
	fn, ok := obj.(*types.Func)
	if !ok {
		return "", ""
	}

	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return "", ""
	}

	return receiverNameFromType(sig.Recv().Type())
}

func receiverNameFromType(t types.Type) (string, string) {
	switch typ := t.(type) {
	case *types.Pointer:
		return receiverNameFromType(typ.Elem())
	case *types.Named:
		obj := typ.Obj()
		if obj == nil {
			return "", ""
		}
		pkg := obj.Pkg()
		pkgPath := ""
		if pkg != nil {
			pkgPath = pkg.Path()
		}
		return pkgPath, obj.Name()
	}
	return "", ""
}
