package symbols

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"
)

// Private receiver methods in test files are reportable without assuming how
// a test framework dispatches them only when their receiver type cannot be
// obtained at all. Any occurrence beyond the declaration/receiver syntax
// declines this bounded proof, including constructors, interface conversions,
// type aliases, reflection roots and even ambiguous same-spelled identifiers.
func appendUninstantiatedTestMethods(result *Result, files []reachabilityFile, fset *token.FileSet, incomplete map[string]bool) {
	packages := map[string][]reachabilityFile{}
	for _, file := range files {
		packages[file.pkgDir+"\x00"+file.file.Name.Name] = append(packages[file.pkgDir+"\x00"+file.file.Name.Name], file)
	}
	for _, group := range packages {
		if len(group) == 0 || incomplete[filepath.Dir(group[0].path)] || packageHasAssembly(filepath.Dir(group[0].path)) {
			continue
		}
		candidates := map[string][]reachabilityFile{}
		declarationCounts := map[string]int{}
		allowed := map[*ast.Ident]bool{}
		for _, file := range group {
			for _, decl := range file.file.Decls {
				if gen, ok := decl.(*ast.GenDecl); ok {
					for _, spec := range gen.Specs {
						if typ, ok := spec.(*ast.TypeSpec); ok {
							declarationCounts[typ.Name.Name]++
							if strings.HasSuffix(file.path, "_test.go") && !ast.IsExported(typ.Name.Name) {
								candidates[typ.Name.Name] = append(candidates[typ.Name.Name], file)
								allowed[typ.Name] = true
							}
						}
					}
				}
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv != nil {
					for _, field := range fn.Recv.List {
						ast.Inspect(field.Type, func(node ast.Node) bool {
							if id, ok := node.(*ast.Ident); ok {
								allowed[id] = true
							}
							return true
						})
					}
				}
			}
		}
		used := map[string]bool{}
		for _, file := range group {
			ast.Inspect(file.file, func(node ast.Node) bool {
				if id, ok := node.(*ast.Ident); ok && !allowed[id] && candidates[id.Name] != nil {
					used[id.Name] = true
				}
				return true
			})
		}
		for _, file := range group {
			if !strings.HasSuffix(file.path, "_test.go") {
				continue
			}
			for _, decl := range file.file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 || fn.Body == nil || hasExportDirective(fn) {
					continue
				}
				receiver := receiverTypeName(fn.Recv.List[0].Type)
				if candidates[receiver] == nil || declarationCounts[receiver] != 1 || used[receiver] {
					continue
				}
				result.Defs = append(result.Defs, Def{Name: qname(file.pkgDir, receiver, fn.Name.Name), Type: "method", File: file.path, Line: fset.Position(fn.Pos()).Line, Receiver: receiver, Reachability: "unreachable", TestHelper: true})
			}
		}
	}
}
