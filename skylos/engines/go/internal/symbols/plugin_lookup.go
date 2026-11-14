package symbols

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"
)

func markPluginLookupSymbols(result *Result, files []reachabilityFile) {
	names := map[string]bool{}
	for _, file := range files {
		if !importsStandardPlugin(file.file) {
			continue
		}
		imports := importedPackageNames(file.file)
		ast.Inspect(file.file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Lookup" {
				return true
			}
			if receiver, ok := sel.X.(*ast.Ident); ok && imports[receiver.Name] {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			name, err := strconv.Unquote(lit.Value)
			if err == nil && ast.IsExported(name) {
				names[name] = true
			}
			return true
		})
	}
	if len(names) == 0 {
		return
	}
	mainFiles := map[string]bool{}
	for _, file := range files {
		if file.file.Name.Name == "main" {
			mainFiles[file.path] = true
		}
	}
	for i := range result.Defs {
		def := &result.Defs[i]
		if !mainFiles[def.File] || def.Receiver != "" {
			continue
		}
		if def.Type != "function" && def.Type != "variable" {
			continue
		}
		if names[def.Name[strings.LastIndex(def.Name, ".")+1:]] {
			def.IsExported = true
		}
	}
}

func importedPackageNames(file *ast.File) map[string]bool {
	names := map[string]bool{}
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if imp.Name != nil {
			if imp.Name.Name == "_" || imp.Name.Name == "." {
				continue
			}
			names[imp.Name.Name] = true
			continue
		}
		names[path[strings.LastIndex(path, "/")+1:]] = true
	}
	return names
}

func importsStandardPlugin(file *ast.File) bool {
	for _, imp := range file.Imports {
		if strings.Trim(imp.Path.Value, `"`) == "plugin" {
			return true
		}
	}
	return false
}
