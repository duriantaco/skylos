package symbols

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

type Def struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	IsExported bool   `json:"is_exported"`
	Receiver   string `json:"receiver,omitempty"`
}

type Ref struct {
	Name string `json:"name"`
	File string `json:"file"`
}

type CallPair struct {
	Caller string `json:"caller"`
	Callee string `json:"callee"`
}

type Result struct {
	Defs      []Def      `json:"defs"`
	Refs      []Ref      `json:"refs"`
	CallPairs []CallPair `json:"call_pairs"`
}

var interfaceMethods = map[string]bool{
	"Read": true, "Write": true, "Close": true, "Error": true, "String": true,
	"ServeHTTP": true, "MarshalJSON": true, "UnmarshalJSON": true,
	"MarshalText": true, "UnmarshalText": true, "MarshalBinary": true, "UnmarshalBinary": true,
	"Less": true, "Len": true, "Swap": true,
	"Format": true, "GoString": true, "Scan": true,
	"Value": true,
}

var builtins = map[string]bool{
	"len": true, "cap": true, "make": true, "new": true, "append": true,
	"copy": true, "delete": true, "close": true, "panic": true, "recover": true,
	"print": true, "println": true, "complex": true, "real": true, "imag": true,
	"true": true, "false": true, "nil": true, "iota": true,
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true,
	"uintptr": true, "float32": true, "float64": true, "complex64": true, "complex128": true,
	"bool": true, "byte": true, "rune": true, "string": true, "error": true, "any": true,
}

var defaultSkipDirs = map[string]bool{
	".git": true, "vendor": true, "node_modules": true,
	"testdata": true, ".github": true,
}

func Extract(root string) (*Result, error) {
	fset := token.NewFileSet()
	result := &Result{}

	modulePath := readModulePath(root)

	pkgDirs := map[string]string{}
	if modulePath != "" {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				name := info.Name()
				if defaultSkipDirs[name] || (strings.HasPrefix(name, ".") && name != ".") {
					return filepath.SkipDir
				}
				rel, _ := filepath.Rel(root, path)
				if rel == "." {
					pkgDirs[modulePath] = path
				} else {
					pkgDirs[modulePath+"/"+filepath.ToSlash(rel)] = path
				}
			}
			return nil
		})
	}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
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
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		isTest := strings.HasSuffix(path, "_test.go")

		file, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return nil
		}

		importMap := map[string]string{}
		for _, imp := range file.Imports {
			impPath := strings.Trim(imp.Path.Value, `"`)
			if imp.Name != nil {
				if imp.Name.Name == "_" {
					continue
				}
				importMap[imp.Name.Name] = impPath
			} else {
				parts := strings.Split(impPath, "/")
				importMap[parts[len(parts)-1]] = impPath
			}
		}

		pkgDir := pkgDirKey(root, path)
		isMainPkg := file.Name.Name == "main"

		if !isTest {
			for _, decl := range file.Decls {
				switch d := decl.(type) {
				case *ast.FuncDecl:
					name := d.Name.Name
					defType := "function"
					receiver := ""

					if d.Recv != nil && len(d.Recv.List) > 0 {
						defType = "method"
						receiver = receiverTypeName(d.Recv.List[0].Type)
					}

					var qn string
					if receiver != "" {
						qn = qname(pkgDir, receiver, name)
					} else {
						qn = qname(pkgDir, name)
					}

					exported := isExportedName(name, isMainPkg)
					if name == "main" || name == "init" {
						exported = true
					}
					if interfaceMethods[name] {
						exported = true
					}

					result.Defs = append(result.Defs, Def{
						Name:       qn,
						Type:       defType,
						File:       path,
						Line:       fset.Position(d.Pos()).Line,
						IsExported: exported,
						Receiver:   receiver,
					})

				case *ast.GenDecl:
					for _, spec := range d.Specs {
						switch s := spec.(type) {
						case *ast.ValueSpec:
							defType := "variable"
							if d.Tok == token.CONST {
								defType = "constant"
							}
							for _, ident := range s.Names {
								if ident.Name == "_" {
									continue
								}
								result.Defs = append(result.Defs, Def{
									Name:       qname(pkgDir, ident.Name),
									Type:       defType,
									File:       path,
									Line:       fset.Position(ident.Pos()).Line,
									IsExported: isExportedName(ident.Name, isMainPkg),
								})
							}
						case *ast.TypeSpec:
							result.Defs = append(result.Defs, Def{
								Name:       qname(pkgDir, s.Name.Name),
								Type:       "type",
								File:       path,
								Line:       fset.Position(s.Name.Pos()).Line,
								IsExported: isExportedName(s.Name.Name, isMainPkg),
							})

							// Emit refs for embedded struct fields.
							if st, ok := s.Type.(*ast.StructType); ok && st.Fields != nil {
								for _, field := range st.Fields.List {
									if len(field.Names) == 0 {
										embName := typeExprName(field.Type)
										if embName != "" {
											result.Refs = append(result.Refs, Ref{
												Name: qname(pkgDir, embName),
												File: path,
											})
										}
									}
								}
							}
						}
					}
				}
			}
		}

		for _, decl := range file.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range genDecl.Specs {
				switch s := spec.(type) {
				case *ast.ValueSpec:
					if s.Type != nil {
						walkExprForRefs(s.Type, pkgDir, importMap, modulePath, root, pkgDirs, path, result)
					}
					for _, val := range s.Values {
						walkExprForRefs(val, pkgDir, importMap, modulePath, root, pkgDirs, path, result)
					}
				case *ast.TypeSpec:
					walkExprForRefs(s.Type, pkgDir, importMap, modulePath, root, pkgDirs, path, result)
				}
			}
		}

		for _, decl := range file.Decls {
			funcDecl, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if funcDecl.Type != nil {
				if funcDecl.Type.Params != nil {
					for _, field := range funcDecl.Type.Params.List {
						walkExprForRefs(field.Type, pkgDir, importMap, modulePath, root, pkgDirs, path, result)
					}
				}
				if funcDecl.Type.Results != nil {
					for _, field := range funcDecl.Type.Results.List {
						walkExprForRefs(field.Type, pkgDir, importMap, modulePath, root, pkgDirs, path, result)
					}
				}
			}
		}

		for _, decl := range file.Decls {
			funcDecl, ok := decl.(*ast.FuncDecl)
			if !ok || funcDecl.Body == nil {
				continue
			}

			var callerName string
			if funcDecl.Recv != nil && len(funcDecl.Recv.List) > 0 {
				recv := receiverTypeName(funcDecl.Recv.List[0].Type)
				callerName = qname(pkgDir, recv, funcDecl.Name.Name)
			} else {
				callerName = qname(pkgDir, funcDecl.Name.Name)
			}

			ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.Ident:
					name := node.Name
					if name == "_" || builtins[name] {
						break
					}
					if _, isImport := importMap[name]; isImport {
						break
					}
					result.Refs = append(result.Refs, Ref{
						Name: qname(pkgDir, name),
						File: path,
					})

				case *ast.SelectorExpr:
					selName := node.Sel.Name
					ident, ok := node.X.(*ast.Ident)
					if !ok {
						result.Refs = append(result.Refs, Ref{
							Name: qname(pkgDir, selName),
							File: path,
						})
						break
					}

					if impPath, isImport := importMap[ident.Name]; isImport {
						targetPkgDir := resolveImportToPkgDir(impPath, modulePath, root, pkgDirs)
						if targetPkgDir != "" {
							result.Refs = append(result.Refs, Ref{
								Name: qname(targetPkgDir, selName),
								File: path,
							})
						}
					} else {
						result.Refs = append(result.Refs, Ref{
							Name: qname(pkgDir, ident.Name, selName),
							File: path,
						})
						if !builtins[ident.Name] {
							result.Refs = append(result.Refs, Ref{
								Name: qname(pkgDir, ident.Name),
								File: path,
							})
						}
					}

				case *ast.CallExpr:
					callee := callExprCallee(node, pkgDir, importMap, modulePath, root, pkgDirs)
					if callee != "" {
						result.CallPairs = append(result.CallPairs, CallPair{
							Caller: callerName,
							Callee: callee,
						})
					}

				case *ast.CompositeLit:
					typeName := typeExprName(node.Type)
					if typeName != "" {
						if strings.Contains(typeName, ".") {
							parts := strings.SplitN(typeName, ".", 2)
							if impPath, isImport := importMap[parts[0]]; isImport {
								targetPkgDir := resolveImportToPkgDir(impPath, modulePath, root, pkgDirs)
								if targetPkgDir != "" {
									result.Refs = append(result.Refs, Ref{
										Name: qname(targetPkgDir, parts[1]),
										File: path,
									})
								}
							}
						} else {
							result.Refs = append(result.Refs, Ref{
								Name: qname(pkgDir, typeName),
								File: path,
							})
						}
					}
				}
				return true
			})
		}

		return nil
	})

	return result, err
}

func readModulePath(root string) string {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}

func pkgDirKey(root, filePath string) string {
	dir := filepath.Dir(filePath)
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == "." {
		return "."
	}
	return filepath.ToSlash(rel)
}

func qname(pkgDir string, parts ...string) string {
	name := strings.Join(parts, ".")
	if pkgDir == "." {
		return name
	}
	return pkgDir + "." + name
}

func isExportedName(name string, isMainPkg bool) bool {
	if isMainPkg {
		return false
	}
	r := []rune(name)
	return len(r) > 0 && unicode.IsUpper(r[0])
}

func receiverTypeName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.StarExpr:
		return receiverTypeName(e.X)
	case *ast.Ident:
		return e.Name
	case *ast.IndexExpr:
		return receiverTypeName(e.X)
	case *ast.IndexListExpr:
		return receiverTypeName(e.X)
	}
	return ""
}

func typeExprName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		return typeExprName(e.X)
	case *ast.SelectorExpr:
		if ident, ok := e.X.(*ast.Ident); ok {
			return ident.Name + "." + e.Sel.Name
		}
	}
	return ""
}

func callExprCallee(call *ast.CallExpr, pkgDir string, importMap map[string]string, modulePath, root string, pkgDirs map[string]string) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		if builtins[fn.Name] {
			return ""
		}
		return qname(pkgDir, fn.Name)
	case *ast.SelectorExpr:
		if ident, ok := fn.X.(*ast.Ident); ok {
			if impPath, isImport := importMap[ident.Name]; isImport {
				targetPkgDir := resolveImportToPkgDir(impPath, modulePath, root, pkgDirs)
				if targetPkgDir != "" {
					return qname(targetPkgDir, fn.Sel.Name)
				}
				return ""
			}
			return qname(pkgDir, ident.Name, fn.Sel.Name)
		}
	}
	return ""
}

func resolveImportToPkgDir(impPath, modulePath, root string, pkgDirs map[string]string) string {
	if modulePath == "" {
		return ""
	}
	if !strings.HasPrefix(impPath, modulePath) {
		return ""
	}
	rel := strings.TrimPrefix(impPath, modulePath)
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" {
		return "."
	}
	return rel
}

func walkExprForRefs(expr ast.Expr, pkgDir string, importMap map[string]string, modulePath, root string, pkgDirs map[string]string, filePath string, result *Result) {
	ast.Inspect(expr, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			name := node.Name
			if name == "_" || builtins[name] {
				return true
			}
			if _, isImport := importMap[name]; isImport {
				return true
			}
			result.Refs = append(result.Refs, Ref{
				Name: qname(pkgDir, name),
				File: filePath,
			})

		case *ast.SelectorExpr:
			ident, ok := node.X.(*ast.Ident)
			if !ok {
				return true
			}
			selName := node.Sel.Name

			if impPath, isImport := importMap[ident.Name]; isImport {
				targetPkgDir := resolveImportToPkgDir(impPath, modulePath, root, pkgDirs)
				if targetPkgDir != "" {
					result.Refs = append(result.Refs, Ref{
						Name: qname(targetPkgDir, selName),
						File: filePath,
					})
				}
			} else {
				result.Refs = append(result.Refs, Ref{
					Name: qname(pkgDir, ident.Name, selName),
					File: filePath,
				})
				if !builtins[ident.Name] {
					result.Refs = append(result.Refs, Ref{
						Name: qname(pkgDir, ident.Name),
						File: filePath,
					})
				}
			}
			return false
		}
		return true
	})
}
