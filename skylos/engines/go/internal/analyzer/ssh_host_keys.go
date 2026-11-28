package analyzer

import "go/ast"

func (a *Analyzer) insecureSSHHostKey(expr ast.Expr, ft *funcTaint) bool {
	call, ok := a.capturedCallable(expr, ft, 0).(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	fun, ok := a.capturedCallable(call.Fun, ft, 0).(*ast.SelectorExpr)
	if !ok || fun.Sel.Name != "InsecureIgnoreHostKey" {
		return false
	}
	id, ok := fun.X.(*ast.Ident)
	return ok && id.Obj == nil && !localDecl(id.Name, ft) && a.imports[id.Name] == sshPath
}

func (a *Analyzer) checkSSHHostKeyConfig(lit *ast.CompositeLit, path string) {
	if a.testSupport || !a.sourceTypeRef(lit.Type).is(sshPath, "ClientConfig") {
		return
	}
	ft := a.literalTaint[lit]
	if ft == nil {
		ft = emptyFuncTaint()
	}
	if sel, ok := lit.Type.(*ast.SelectorExpr); ok && !a.isPackageIdent(sel.X, ft.tainted) {
		return
	}
	for _, elt := range lit.Elts {
		field, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := field.Key.(*ast.Ident)
		if ok && key.Name == "HostKeyCallback" && a.insecureSSHHostKey(field.Value, ft) {
			a.reportSSHHostKey(field.Value, path)
		}
	}
}

func (a *Analyzer) checkSSHHostKeyAssignment(assign *ast.AssignStmt, path string) {
	ft := a.assignTaint[assign]
	if a.testSupport || ft == nil || len(assign.Lhs) != len(assign.Rhs) {
		return
	}
	for i, lhs := range assign.Lhs {
		sel, ok := lhs.(*ast.SelectorExpr)
		if ok && sel.Sel.Name == "HostKeyCallback" &&
			a.resolveType(sel.X, ft, 0).is(sshPath, "ClientConfig") &&
			a.insecureSSHHostKey(assign.Rhs[i], ft) {
			a.reportSSHHostKey(assign.Rhs[i], path)
		}
	}
}

func (a *Analyzer) reportSSHHostKey(node ast.Node, path string) {
	a.addFinding(node, path, "SKY-D380", "HIGH", "SSH host-key verification disabled",
		"This SSH client configuration accepts every host key. Use known_hosts or verify a pinned host key.")
}
