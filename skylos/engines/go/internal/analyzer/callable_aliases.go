package analyzer

import "go/ast"

// Resolve captured providers only for a single local definition. Reassigned
// names stay unknown rather than guessing a provider from its spelling.
func (a *Analyzer) capturedCallable(expr ast.Expr, ft *funcTaint, depth int) ast.Expr {
	if depth > 8 || expr == nil {
		return expr
	}
	switch e := expr.(type) {
	case *ast.ParenExpr:
		return a.capturedCallable(e.X, ft, depth+1)
	case *ast.Ident:
		if _, parameter := ft.declTypes[e.Name]; parameter {
			return expr
		}
		values := ft.defs[e.Name]
		if len(values) == 1 && values[0] != nil && values[0].Pos() < e.Pos() {
			return a.capturedCallable(values[0], ft, depth+1)
		}
	}
	return expr
}
func (a *Analyzer) sourceTypeRef(expr ast.Expr) typeRef {
	return a.resolveAliasRef(typeOfExpr(expr, a.imports), 0)
}
func (a *Analyzer) resolveAliasRef(ref typeRef, depth int) typeRef {
	if depth > 8 {
		return typeRef{}
	}
	if ref.pkg == "" && a.facts != nil {
		if alias, ok := a.facts.aliases[ref.name]; ok {
			return a.resolveAliasRef(alias, depth+1)
		}
	}
	return ref
}
func (a *Analyzer) checkTLSFieldAssignment(assign *ast.AssignStmt, path string) {
	if a.testSupport || len(assign.Lhs) != len(assign.Rhs) {
		return
	}
	ft := a.assignTaint[assign]
	if ft == nil {
		ft = emptyFuncTaint()
	}
	for i, lhs := range assign.Lhs {
		sel, ok := lhs.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "InsecureSkipVerify" {
			continue
		}
		value, ok := assign.Rhs[i].(*ast.Ident)
		if !ok || value.Name != "true" || value.Obj != nil || localDecl(value.Name, ft) || (a.facts != nil && a.facts.valueNames[value.Name]) {
			continue
		}
		if a.resolveType(sel.X, ft, 0).is("crypto/tls", "Config") {
			a.addFinding(assign, path, "SKY-G210", "HIGH", "TLS Verification Disabled", "InsecureSkipVerify disables certificate validation, enabling MITM attacks.")
		}
	}
}
