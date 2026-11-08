package analyzer

// Guard proofs are deliberately separate from the flow-insensitive source
// analysis. A check protects only the value and branch that reaches a sink.
import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
)

type valueGuardState struct {
	facts map[string]bool
	defs  map[string]ast.Expr
	errs  map[string]string // first result of Rel/Parse -> its error result
}

func newValueGuardState() valueGuardState {
	return valueGuardState{map[string]bool{}, map[string]ast.Expr{}, map[string]string{}}
}

func (s valueGuardState) clone() valueGuardState {
	out := newValueGuardState()
	for k, v := range s.facts {
		out.facts[k] = v
	}
	for k, v := range s.defs {
		out.defs[k] = v
	}
	for k, v := range s.errs {
		out.errs[k] = v
	}
	return out
}

func joinValueGuards(left, right valueGuardState) valueGuardState {
	out := newValueGuardState()
	for k := range left.facts {
		if right.facts[k] {
			out.facts[k] = true
		}
	}
	for k, v := range left.defs {
		if right.defs[k] == v {
			out.defs[k] = v
		}
	}
	for k, v := range left.errs {
		if right.errs[k] == v {
			out.errs[k] = v
		}
	}
	return out
}

func (w *valueGuardWalker) join(left, right valueGuardState) valueGuardState {
	for _, state := range []valueGuardState{left, right} {
		paths, redirects := w.prove(state)
		for name := range paths {
			state.facts["path:"+name] = true
		}
		for name := range redirects {
			state.facts["redirect:"+name] = true
		}
	}
	return joinValueGuards(left, right)
}

func (s valueGuardState) forget(name string) {
	if name == "" || name == "_" {
		return
	}
	invalid := map[string]bool{name: true}
	// A boolean alias or parsed/relative result cannot outlive a write to the
	// value it checked. Dropping dependent definitions is conservative for copies.
	for changed := true; changed; {
		changed = false
		for dest, expr := range s.defs {
			for _, source := range guardIdentNames(expr) {
				if invalid[source] && !invalid[dest] {
					invalid[dest] = true
					changed = true
				}
			}
		}
	}
	for name := range invalid {
		delete(s.defs, name)
		delete(s.errs, name)
		for key := range s.facts {
			if strings.HasSuffix(key, ":"+name) {
				delete(s.facts, key)
			}
		}
	}
}

type valueGuardWalker struct {
	a         *Analyzer
	ft        *funcTaint
	immutable map[string]bool
	work      int
}

func simpleGuardName(expr ast.Expr) string {
	if id, ok := expr.(*ast.Ident); ok {
		if id.Obj != nil {
			return id.Name + "@" + strconv.Itoa(int(id.Obj.Pos()))
		}
		return id.Name
	}
	return ""
}

func guardRootName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return simpleGuardName(e)
	case *ast.SelectorExpr:
		return guardRootName(e.X)
	case *ast.IndexExpr:
		return guardRootName(e.X)
	case *ast.StarExpr:
		return guardRootName(e.X)
	case *ast.ParenExpr:
		return guardRootName(e.X)
	case *ast.UnaryExpr:
		return guardRootName(e.X)
	}
	return ""
}

func guardIdentNames(expr ast.Expr) []string {
	var names []string
	ast.Inspect(expr, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			names = append(names, simpleGuardName(id))
		}
		return true
	})
	return names
}

func guardParamNames(fields *ast.FieldList) []string {
	var names []string
	if fields != nil {
		for _, field := range fields.List {
			for _, name := range field.Names {
				names = append(names, simpleGuardName(name))
			}
		}
	}
	return names
}

// An inbound net/http request path is absolute (or the special '*'/empty
// target). Keep this fact only while its native receiver/URL has not escaped
// or been written. This is distinct from arbitrary form/query path text.
func (a *Analyzer) seedRequestPaths(fields *ast.FieldList, s valueGuardState) {
	if fields == nil {
		return
	}
	for _, field := range fields.List {
		typ := field.Type
		if pointer, ok := typ.(*ast.StarExpr); ok {
			typ = pointer.X
		} else {
			continue
		}
		sel, ok := typ.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Request" {
			continue
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Obj != nil || a.imports[pkg.Name] != "net/http" {
			continue
		}
		for _, name := range field.Names {
			s.facts["request:"+simpleGuardName(name)] = true
		}
	}
}

type guardFileFacts struct {
	globals   map[string]ast.Expr
	immutable map[string]bool
}

// File-wide declaration/mutation evidence is indexed once, in linear passes.
func (a *Analyzer) guardFileMetadata(file *ast.File) guardFileFacts {
	info := guardFileFacts{map[string]ast.Expr{}, map[string]bool{}}
	parents := map[ast.Node]ast.Node{}
	initial := map[string]ast.Expr{}
	definitions := map[string]ast.Node{}
	var stack []ast.Node
	define := func(name *ast.Ident, value ast.Expr) {
		if _, exists := definitions[simpleGuardName(name)]; exists {
			info.immutable[simpleGuardName(name)] = false
			return
		}
		definitions[simpleGuardName(name)] = name
		initial[simpleGuardName(name)] = value
		info.immutable[simpleGuardName(name)] = true
	}
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) > 0 {
			parents[n] = stack[len(stack)-1]
		}
		stack = append(stack, n)
		switch d := n.(type) {
		case *ast.ValueSpec:
			if len(d.Names) == len(d.Values) {
				for i, name := range d.Names {
					define(name, d.Values[i])
				}
			}
		case *ast.AssignStmt:
			if d.Tok == token.DEFINE && len(d.Lhs) == len(d.Rhs) {
				for i, lhs := range d.Lhs {
					if name, ok := lhs.(*ast.Ident); ok {
						define(name, d.Rhs[i])
					}
				}
			}
		}
		return true
	})
	ast.Inspect(file, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || !info.immutable[simpleGuardName(id)] || definitions[simpleGuardName(id)] == id {
			return true
		}
		parent := parents[id]
		if assign, ok := parent.(*ast.AssignStmt); ok {
			for _, lhs := range assign.Lhs {
				if lhs == id {
					info.immutable[simpleGuardName(id)] = false
				}
			}
		}
		if unary, ok := parent.(*ast.UnaryExpr); ok && unary.Op == token.AND {
			info.immutable[simpleGuardName(id)] = false
		}
		if _, collection := initial[simpleGuardName(id)].(*ast.CompositeLit); !collection {
			return true
		}
		if index, ok := parent.(*ast.IndexExpr); ok && index.X == id {
			if assign, ok := parents[index].(*ast.AssignStmt); ok {
				for _, lhs := range assign.Lhs {
					if lhs == index {
						info.immutable[simpleGuardName(id)] = false
					}
				}
			}
			return true
		}
		if call, ok := parent.(*ast.CallExpr); ok && len(call.Args) == 2 && call.Args[0] == id && a.isPkgCall(call, "slices", "Contains") {
			return true
		}
		info.immutable[simpleGuardName(id)] = false
		return true
	})
	for _, decl := range file.Decls {
		if gen, ok := decl.(*ast.GenDecl); ok {
			// Other source files can write package vars without appearing in
			// this file's mutation index. Only language-immutable constants may
			// cross that boundary as safety evidence.
			if gen.Tok != token.CONST && len(a.dirFiles[filepath.Dir(a.fset.Position(file.Pos()).Filename)]) > 1 {
				continue
			}
			for _, spec := range gen.Specs {
				if value, ok := spec.(*ast.ValueSpec); ok && len(value.Names) == len(value.Values) {
					for i, name := range value.Names {
						if info.immutable[simpleGuardName(name)] {
							info.globals[simpleGuardName(name)] = value.Values[i]
						}
					}
				}
			}
		}
	}
	return info
}

func (a *Analyzer) collectValueGuards(info guardFileFacts, fd *ast.FuncDecl, ft *funcTaint) {
	if len(ft.tainted) == 0 && len(ft.pathTainted) == 0 {
		return
	}
	s := newValueGuardState()
	for name, value := range info.globals {
		s.defs[name] = value
	}
	for _, name := range guardParamNames(fd.Type.Params) {
		s.forget(name)
	}
	for _, name := range guardParamNames(fd.Recv) {
		s.forget(name)
	}
	a.seedRequestPaths(fd.Type.Params, s)
	w := valueGuardWalker{a: a, ft: ft, immutable: info.immutable}
	// Goto can bypass textual guards. It is outside this bounded proof model.
	gotoSeen := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if b, ok := n.(*ast.BranchStmt); ok && b.Tok == token.GOTO {
			gotoSeen = true
		}
		return true
	})
	if !gotoSeen {
		w.block(fd.Body.List, s)
	}
}

func (w *valueGuardWalker) constant(expr ast.Expr, s valueGuardState, depth int) (string, bool) {
	if depth > 8 || expr == nil {
		return "", false
	}
	if value, ok := stringLiteralValue(expr); ok {
		return value, true
	}
	if id, ok := expr.(*ast.Ident); ok {
		return w.constant(s.defs[simpleGuardName(id)], s, depth+1)
	}
	if bin, ok := expr.(*ast.BinaryExpr); ok && bin.Op == token.ADD {
		left, lok := w.constant(bin.X, s, depth+1)
		right, rok := w.constant(bin.Y, s, depth+1)
		return left + right, lok && rok
	}
	return "", false
}

func (w *valueGuardWalker) clean(expr ast.Expr, s valueGuardState, depth int) bool {
	if depth > 8 || expr == nil {
		return false
	}
	if id, ok := expr.(*ast.Ident); ok {
		return w.clean(s.defs[simpleGuardName(id)], s, depth+1)
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	for _, method := range []string{"Clean", "Join", "Abs", "EvalSymlinks"} {
		if w.a.isPkgCall(call, "path/filepath", method) {
			return true
		}
	}
	return false
}

func (w *valueGuardWalker) allowlist(expr ast.Expr, s valueGuardState) bool {
	if id, ok := expr.(*ast.Ident); ok {
		if !w.immutable[simpleGuardName(id)] {
			return false
		}
		expr = s.defs[simpleGuardName(id)]
	}
	lit, ok := expr.(*ast.CompositeLit)
	if !ok || len(lit.Elts) == 0 {
		return false
	}
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if _, ok := stringLiteralValue(kv.Key); !ok {
				return false
			}
			value, ok := kv.Value.(*ast.Ident)
			if !ok || value.Name != "true" {
				return false
			}
		} else if _, ok := stringLiteralValue(elt); !ok {
			return false
		}
	}
	return true
}

func mergeGuardFacts(left, right map[string]bool, all bool) map[string]bool {
	out := map[string]bool{}
	for k := range left {
		if all || right[k] {
			out[k] = true
		}
	}
	if all {
		for k := range right {
			out[k] = true
		}
	}
	return out
}

func (w *valueGuardWalker) condition(expr ast.Expr, truth bool, s valueGuardState, depth int) map[string]bool {
	facts := map[string]bool{}
	if depth > 12 || expr == nil {
		return facts
	}
	if p, ok := expr.(*ast.ParenExpr); ok {
		return w.condition(p.X, truth, s, depth+1)
	}
	if un, ok := expr.(*ast.UnaryExpr); ok && un.Op == token.NOT {
		return w.condition(un.X, !truth, s, depth+1)
	}
	if id, ok := expr.(*ast.Ident); ok {
		return w.condition(s.defs[simpleGuardName(id)], truth, s, depth+1)
	}
	if bin, ok := expr.(*ast.BinaryExpr); ok {
		if bin.Op == token.LAND || bin.Op == token.LOR {
			return mergeGuardFacts(w.condition(bin.X, truth, s, depth+1), w.condition(bin.Y, truth, s, depth+1), (bin.Op == token.LAND) == truth)
		}
		if bin.Op == token.EQL || bin.Op == token.NEQ {
			equal := truth == (bin.Op == token.EQL)
			for _, pair := range [][2]ast.Expr{{bin.X, bin.Y}, {bin.Y, bin.X}} {
				if value, ok := pair[1].(*ast.Ident); ok && value.Name == "nil" && equal {
					if name := simpleGuardName(pair[0]); name != "" {
						facts["nil:"+name] = true
					}
				}
				if literal, ok := stringLiteralValue(pair[1]); ok && equal {
					if name := simpleGuardName(pair[0]); name != "" {
						facts["redirect:"+name] = true
					}
					if sel, ok := pair[0].(*ast.SelectorExpr); ok && literal == "" && (sel.Sel.Name == "Host" || sel.Sel.Name == "Scheme") {
						if name := simpleGuardName(sel.X); name != "" {
							facts[strings.ToLower(sel.Sel.Name)+":"+name] = true
						}
					}
				}
			}
		}
	}
	if index, ok := expr.(*ast.IndexExpr); ok && truth && w.allowlist(index.X, s) {
		if name := simpleGuardName(index.Index); name != "" {
			facts["redirect:"+name] = true
		}
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return facts
	}
	if w.a.isPkgCall(call, "path/filepath", "IsLocal") && len(call.Args) == 1 && truth {
		if name := simpleGuardName(call.Args[0]); name != "" {
			facts["path:"+name] = true
		}
	}
	if w.a.isPkgCall(call, "slices", "Contains") && len(call.Args) == 2 && truth && w.allowlist(call.Args[0], s) {
		if name := simpleGuardName(call.Args[1]); name != "" {
			facts["redirect:"+name] = true
		}
	}
	if w.a.isPkgCall(call, "strings", "HasPrefix") && len(call.Args) == 2 {
		name := simpleGuardName(call.Args[0])
		prefix, ok := w.constant(call.Args[1], s, 0)
		if name != "" && ok {
			if truth && prefix == "/" {
				facts["slash:"+name] = true
			}
			if !truth && prefix == "//" {
				facts["notdouble:"+name] = true
			}
			if !truth && prefix == ".." {
				facts["relative:"+name] = true
			}
			if truth && strings.HasSuffix(prefix, "/") && strings.HasPrefix(prefix, "/") && !w.a.isTainted(call.Args[1], w.ft.tainted) && w.clean(call.Args[0], s, 0) {
				facts["path:"+name] = true
			}
		}
	}
	return facts
}

func (w *valueGuardWalker) prove(s valueGuardState) (map[string]bool, map[string]bool) {
	paths, redirects := map[string]bool{}, map[string]bool{}
	for key := range s.facts {
		if strings.HasPrefix(key, "path:") {
			paths[strings.TrimPrefix(key, "path:")] = true
		}
		if strings.HasPrefix(key, "redirect:") {
			redirects[strings.TrimPrefix(key, "redirect:")] = true
		}
		if strings.HasPrefix(key, "slash:") {
			name := strings.TrimPrefix(key, "slash:")
			if s.facts["notdouble:"+name] {
				redirects[name] = true
			}
		}
	}
	for name, expr := range s.defs {
		call, ok := expr.(*ast.CallExpr)
		if !ok || s.errs[name] == "" || !s.facts["nil:"+s.errs[name]] {
			continue
		}
		if w.a.isPkgCall(call, "path/filepath", "Rel") && len(call.Args) == 2 && s.facts["relative:"+name] {
			if _, ok := w.constant(call.Args[0], s, 0); ok {
				if source := simpleGuardName(call.Args[1]); source != "" {
					paths[source] = true
				}
			}
		}
		if (w.a.isPkgCall(call, "net/url", "Parse") || w.a.isPkgCall(call, "net/url", "ParseRequestURI")) && len(call.Args) == 1 && s.facts["host:"+name] && s.facts["scheme:"+name] {
			if source := simpleGuardName(call.Args[0]); source != "" {
				redirects[source] = true
			}
		}
	}
	return paths, redirects
}

func (w *valueGuardWalker) record(node ast.Node, s valueGuardState) {
	if node == nil {
		return
	}
	paths, redirects := w.prove(s)
	ast.Inspect(node, func(n ast.Node) bool {
		if literal, ok := n.(*ast.FuncLit); ok {
			child := s.clone()
			child.facts = map[string]bool{}
			for _, name := range guardParamNames(literal.Type.Params) {
				child.forget(name)
			}
			w.a.seedRequestPaths(literal.Type.Params, child)
			w.block(literal.Body.List, child)
			return false
		}
		if call, ok := n.(*ast.CallExpr); ok {
			for _, arg := range call.Args {
				pathSafe := w.guardedPathValue(arg, paths, s, 0)
				redirectSafe := redirects[simpleGuardName(arg)]
				if previous, seen := w.ft.guarded[arg.Pos()]; seen {
					pathSafe = pathSafe && previous["value"]
				}
				if previous, seen := w.ft.redirectGuarded[arg.Pos()]; seen {
					redirectSafe = redirectSafe && previous["value"]
				}
				w.ft.guarded[arg.Pos()] = map[string]bool{"value": pathSafe}
				w.ft.redirectGuarded[arg.Pos()] = map[string]bool{"value": redirectSafe}
			}
		}
		return true
	})
}

// Name proofs apply to that value, not arbitrary expressions containing it.
// In particular helper(checked) or checked + "/../secret" is not protected.
func (w *valueGuardWalker) guardedPathValue(expr ast.Expr, paths map[string]bool, s valueGuardState, depth int) bool {
	if depth > 12 || expr == nil {
		return false
	}
	if id, ok := expr.(*ast.Ident); ok {
		return paths[simpleGuardName(id)] || w.guardedPathValue(s.defs[simpleGuardName(id)], paths, s, depth+1)
	}
	if p, ok := expr.(*ast.ParenExpr); ok {
		return w.guardedPathValue(p.X, paths, s, depth+1)
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	if w.a.isPkgCall(call, "path/filepath", "Join") || w.a.isPkgCall(call, "path", "Join") {
		anchoredBase := false
		if len(call.Args) > 0 {
			if base, ok := w.constant(call.Args[0], s, 0); ok {
				clean := filepath.Clean(base)
				anchoredBase = base != "" && clean != "." && clean != ".." && clean != string(filepath.Separator) && clean != filepath.VolumeName(clean)+string(filepath.Separator)
			}
		}
		for i, arg := range call.Args {
			if w.a.taintedIn(arg, w.ft.pathTainted, taintPath) {
				if !w.guardedPathValue(arg, paths, s, depth+1) && !(i > 0 && anchoredBase && w.cleanedAbsolutePath(arg, s, 0)) {
					return false
				}
			} else {
				literal, ok := w.constant(arg, s, 0)
				if !ok {
					return false
				}
				for _, part := range strings.Split(strings.ReplaceAll(literal, "\\", "/"), "/") {
					if part == ".." {
						return false
					}
				}
			}
		}
		return len(call.Args) > 0
	}
	if (w.a.isPkgCall(call, "path/filepath", "Clean") || w.a.isPkgCall(call, "path/filepath", "Abs")) && len(call.Args) == 1 {
		return w.guardedPathValue(call.Args[0], paths, s, depth+1)
	}
	return false
}

func (w *valueGuardWalker) requestObject(expr ast.Expr, s valueGuardState, depth int) bool {
	if depth > 12 || expr == nil {
		return false
	}
	id, ok := expr.(*ast.Ident)
	if !ok {
		return false
	}
	if s.facts["request:"+simpleGuardName(id)] {
		return true
	}
	return w.requestObject(s.defs[simpleGuardName(id)], s, depth+1)
}

func (w *valueGuardWalker) requestURL(expr ast.Expr, s valueGuardState, depth int) bool {
	if depth > 12 || expr == nil {
		return false
	}
	if id, ok := expr.(*ast.Ident); ok {
		return w.requestURL(s.defs[simpleGuardName(id)], s, depth+1)
	}
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "URL" {
		return false
	}
	return w.requestObject(sel.X, s, depth+1)
}

func (w *valueGuardWalker) absolutePath(expr ast.Expr, s valueGuardState, depth int) bool {
	if depth > 12 || expr == nil {
		return false
	}
	if literal, ok := w.constant(expr, s, 0); ok {
		return strings.HasPrefix(literal, "/") || literal == "*" || literal == ""
	}
	if id, ok := expr.(*ast.Ident); ok {
		return w.absolutePath(s.defs[simpleGuardName(id)], s, depth+1)
	}
	if bin, ok := expr.(*ast.BinaryExpr); ok && bin.Op == token.ADD {
		if prefix, ok := w.constant(bin.X, s, 0); ok {
			return strings.HasPrefix(prefix, "/")
		}
	}
	if sel, ok := expr.(*ast.SelectorExpr); ok && sel.Sel.Name == "Path" {
		return w.requestURL(sel.X, s, depth+1)
	}
	return false
}

// Cleaning an absolute value removes upward traversal before it is joined
// beneath a trusted base. Cleaning relative request text does not do that.
func (w *valueGuardWalker) cleanedAbsolutePath(expr ast.Expr, s valueGuardState, depth int) bool {
	if depth > 12 || expr == nil {
		return false
	}
	if id, ok := expr.(*ast.Ident); ok {
		return w.cleanedAbsolutePath(s.defs[simpleGuardName(id)], s, depth+1)
	}
	call, ok := expr.(*ast.CallExpr)
	return ok && len(call.Args) == 1 && w.a.isPkgCall(call, "path/filepath", "Clean") && w.absolutePath(call.Args[0], s, 0)
}

func (w *valueGuardWalker) bind(lhs []ast.Expr, rhs []ast.Expr, s valueGuardState) {
	changed := map[string]bool{}
	for i, expr := range lhs {
		if len(lhs) == len(rhs) && simpleGuardName(expr) != "" && simpleGuardName(expr) == simpleGuardName(rhs[i]) {
			continue
		}
		changed[w.writeRoot(expr, s)] = true
	}
	for name := range changed {
		s.forget(name)
	}
	if len(lhs) == len(rhs) {
		for i, expr := range lhs {
			if name := simpleGuardName(expr); name != "" {
				if !changed[name] {
					continue
				}
				stale := false
				for _, source := range guardIdentNames(rhs[i]) {
					if changed[source] {
						stale = true
					}
				}
				if stale {
					continue
				} // RHS observed the old value before all stores.
				s.defs[name] = rhs[i]
				if _, ok := w.constant(rhs[i], s, 0); ok {
					s.facts["path:"+name] = true
					s.facts["redirect:"+name] = true
				}
			}
		}
	} else if len(lhs) == 2 && len(rhs) == 1 {
		name, errName := simpleGuardName(lhs[0]), simpleGuardName(lhs[1])
		if name != "" && errName != "" && errName != "_" {
			s.defs[name] = rhs[0]
			s.errs[name] = errName
		}
	}
}

func (w *valueGuardWalker) aliasRoot(name string, s valueGuardState, depth int) string {
	if depth > 12 {
		return name
	}
	if id, ok := s.defs[name].(*ast.Ident); ok {
		return w.aliasRoot(simpleGuardName(id), s, depth+1)
	}
	if ref, ok := s.defs[name].(*ast.UnaryExpr); ok && ref.Op == token.AND {
		return w.aliasRoot(guardRootName(ref.X), s, depth+1)
	}
	if field, ok := s.defs[name].(*ast.SelectorExpr); ok {
		return w.aliasRoot(guardRootName(field.X), s, depth+1)
	}
	return name
}

func (w *valueGuardWalker) writeRoot(expr ast.Expr, s valueGuardState) string {
	name := guardRootName(expr)
	if simpleGuardName(expr) != "" {
		return name
	}
	return w.aliasRoot(name, s, 0)
}

func (w *valueGuardWalker) invalidateWrites(node ast.Node, s valueGuardState) {
	ast.Inspect(node, func(n ast.Node) bool {
		switch d := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range d.Lhs {
				s.forget(w.writeRoot(lhs, s))
			}
		case *ast.IncDecStmt:
			s.forget(guardRootName(d.X))
		case *ast.UnaryExpr:
			if d.Op == token.AND {
				s.forget(w.writeRoot(d.X, s))
			}
		case *ast.RangeStmt:
			s.forget(guardRootName(d.Key))
			s.forget(guardRootName(d.Value))
		case *ast.CallExpr:
			for _, arg := range d.Args {
				name := w.aliasRoot(guardRootName(arg), s, 0)
				if (w.requestObject(arg, s, 0) || w.requestURL(arg, s, 0)) && !w.a.isPkgCall(d, "net/http", "ServeFile") {
					delete(s.facts, "request:"+name)
				}
				if parse, ok := s.defs[name].(*ast.CallExpr); ok && (w.a.isPkgCall(parse, "net/url", "Parse") || w.a.isPkgCall(parse, "net/url", "ParseRequestURI")) {
					s.forget(name)
				}
			}
		}
		return true
	})
}

// Evaluate condition operands in Go order. In particular a write in the RHS
// of && invalidates a proof from its LHS; a later check can prove the new value.
func (w *valueGuardWalker) branchCondition(expr ast.Expr, truth bool, s valueGuardState, depth int) valueGuardState {
	if depth > 16 {
		s.facts = map[string]bool{}
		return s
	}
	if p, ok := expr.(*ast.ParenExpr); ok {
		return w.branchCondition(p.X, truth, s, depth+1)
	}
	if un, ok := expr.(*ast.UnaryExpr); ok && un.Op == token.NOT {
		return w.branchCondition(un.X, !truth, s, depth+1)
	}
	if bin, ok := expr.(*ast.BinaryExpr); ok && (bin.Op == token.LAND || bin.Op == token.LOR) {
		if (bin.Op == token.LAND) == truth {
			return w.branchCondition(bin.Y, truth, w.branchCondition(bin.X, truth, s, depth+1), depth+1)
		}
		short := w.branchCondition(bin.X, truth, s.clone(), depth+1)
		long := w.branchCondition(bin.Y, truth, w.branchCondition(bin.X, !truth, s.clone(), depth+1), depth+1)
		return w.join(short, long)
	}
	w.record(expr, s)
	w.invalidateWrites(expr, s)
	for key := range w.condition(expr, truth, s, 0) {
		s.facts[key] = true
	}
	return s
}

func (w *valueGuardWalker) block(stmts []ast.Stmt, s valueGuardState) (valueGuardState, bool) {
	for _, stmt := range stmts {
		w.work++
		if w.work > 20000 {
			return newValueGuardState(), false
		}
		// A captured write may run through a call we do not summarize. Never
		// carry the old proof past the declaration of that writable closure.
		ast.Inspect(stmt, func(n ast.Node) bool {
			if literal, ok := n.(*ast.FuncLit); ok {
				w.invalidateWrites(literal.Body, s)
				return false
			}
			return true
		})
		switch node := stmt.(type) {
		case *ast.IfStmt:
			if node.Init != nil {
				s, _ = w.block([]ast.Stmt{node.Init}, s)
			}
			passing := w.branchCondition(node.Cond, true, s.clone(), 0)
			failing := w.branchCondition(node.Cond, false, s.clone(), 0)
			passing, pExit := w.block(node.Body.List, passing)
			fExit := false
			if node.Else != nil {
				failing, fExit = w.block([]ast.Stmt{node.Else}, failing)
			}
			if pExit && fExit {
				return s, true
			}
			if pExit {
				s = failing
			} else if fExit {
				s = passing
			} else {
				s = w.join(passing, failing)
			}
		case *ast.BlockStmt:
			var exits bool
			s, exits = w.block(node.List, s)
			if exits {
				return s, true
			}
		case *ast.ReturnStmt:
			w.record(node, s)
			return s, true
		case *ast.AssignStmt:
			w.record(node, s)
			for _, rhs := range node.Rhs {
				w.invalidateWrites(rhs, s)
			}
			w.bind(node.Lhs, node.Rhs, s)
		case *ast.DeclStmt:
			w.record(node, s)
			if gen, ok := node.Decl.(*ast.GenDecl); ok {
				for _, spec := range gen.Specs {
					if value, ok := spec.(*ast.ValueSpec); ok {
						for _, rhs := range value.Values {
							w.invalidateWrites(rhs, s)
						}
						var lhs []ast.Expr
						for _, name := range value.Names {
							lhs = append(lhs, name)
						}
						w.bind(lhs, value.Values, s)
					}
				}
			}
		case *ast.ForStmt:
			if node.Init != nil {
				s, _ = w.block([]ast.Stmt{node.Init}, s)
			}
			w.invalidateWrites(node, s)
			w.record(node.Cond, s)
			child := s.clone()
			for k := range w.condition(node.Cond, true, s, 0) {
				child.facts[k] = true
			}
			w.block(node.Body.List, child)
			w.invalidateWrites(node, s)
		case *ast.RangeStmt:
			w.invalidateWrites(node, s)
			w.record(node.X, s)
			child := s.clone()
			if node.Key != nil {
				child.forget(guardRootName(node.Key))
			}
			if node.Value != nil {
				child.forget(guardRootName(node.Value))
			}
			w.block(node.Body.List, child)
			w.invalidateWrites(node, s)
		case *ast.SwitchStmt:
			if node.Init != nil {
				s, _ = w.block([]ast.Stmt{node.Init}, s)
			}
			w.record(node.Tag, s)
			w.invalidateWrites(node.Body, s)
			for _, clause := range node.Body.List {
				if c, ok := clause.(*ast.CaseClause); ok {
					w.block(c.Body, s.clone())
				}
			}
		case *ast.TypeSwitchStmt:
			w.invalidateWrites(node, s)
			for _, clause := range node.Body.List {
				if c, ok := clause.(*ast.CaseClause); ok {
					w.block(c.Body, s.clone())
				}
			}
		case *ast.IncDecStmt:
			w.record(node, s)
			s.forget(guardRootName(node.X))
		default:
			w.invalidateWrites(node, s)
			w.record(node, s)
		}
	}
	return s, false
}
