package symbols

import (
	"go/ast"
	"go/types"
	"strings"
)

// A failed package type-check cannot prove deadness. It can still bind a local
// helper declaration to a use in a real Go test entrypoint. Keep only that
// positive object-identity proof (and helper chains), without removing refs or
// marking any other declaration unreachable.
func markPartialLiveTestHelpers(defs map[string]*Def, files []reachabilityFile, info *types.Info) {
	objects := map[types.Object]string{}
	owners := map[*ast.FuncDecl]string{}
	roots := map[string]bool{}
	for _, file := range files {
		for _, decl := range file.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			name := typedCallerName(fn, file.pkgDir)
			owners[fn] = name
			if object := info.Defs[fn.Name]; object != nil {
				objects[object] = name
			}
			if strings.HasSuffix(file.path, "_test.go") && testHarnessEntry(fn, file.file) {
				roots[name] = true
			}
		}
	}
	edges := map[string][]string{}
	for _, file := range files {
		for _, decl := range file.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			owner := owners[fn]
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				id, ok := node.(*ast.Ident)
				if !ok {
					return true
				}
				object := info.Uses[id]
				if f, ok := object.(*types.Func); ok {
					object = f.Origin()
				}
				if target := objects[object]; target != "" {
					edges[owner] = append(edges[owner], target)
				}
				return true
			})
		}
	}
	live := map[string]bool{}
	queue := []string{}
	for root := range roots {
		queue = append(queue, root)
	}
	for len(queue) > 0 {
		name := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if live[name] {
			continue
		}
		live[name] = true
		queue = append(queue, edges[name]...)
	}
	for name := range live {
		if def := defs[name]; def != nil && def.TestHelper {
			def.Reachability = "reachable"
		}
	}
}

func testHarnessEntry(fn *ast.FuncDecl, file *ast.File) bool {
	if fn.Recv != nil || fn.Type.Results != nil && len(fn.Type.Results.List) > 0 {
		return false
	}
	if strings.HasPrefix(fn.Name.Name, "Example") && (fn.Type.Params == nil || len(fn.Type.Params.List) == 0) {
		return true
	}
	want := ""
	switch {
	case strings.HasPrefix(fn.Name.Name, "Test"):
		want = "T"
	case strings.HasPrefix(fn.Name.Name, "Benchmark"):
		want = "B"
	case strings.HasPrefix(fn.Name.Name, "Fuzz"):
		want = "F"
	}
	if want == "" || fn.Type.Params == nil || len(fn.Type.Params.List) != 1 {
		return false
	}
	field := fn.Type.Params.List[0]
	if len(field.Names) > 1 {
		return false
	}
	ptr, ok := field.Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := ptr.X.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != want {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	for _, imp := range file.Imports {
		if imp.Path.Value != `"testing"` {
			continue
		}
		name := "testing"
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if name == id.Name {
			return true
		}
	}
	return false
}
