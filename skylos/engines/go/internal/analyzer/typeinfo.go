package analyzer

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
)

// Lightweight type resolution for sink receivers. go/types is not used here:
// the engine must work on code whose dependencies are not downloaded. A type
// is resolved from declarations in the enclosing function (parameters,
// receivers, typed vars, assigned values) and from the package's own files
// (struct fields, package-level vars, function results), with import paths
// taken from each declaring file. Anything else stays unknown.

// typeRef names a type: pkg is its import path, "" for a type declared in the
// package being analysed, "builtin" for a predeclared type.
type typeRef struct {
	pkg  string
	name string
}

func (t typeRef) known() bool { return t.name != "" }

func (t typeRef) is(pkg, name string) bool { return t.pkg == pkg && t.name == name }

var builtinString = typeRef{pkg: "builtin", name: "string"}

var predeclaredTypes = map[string]bool{
	"string": true, "bool": true, "byte": true, "rune": true, "error": true, "any": true,
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true, "uintptr": true,
	"float32": true, "float64": true, "complex64": true, "complex128": true,
}

// scalarTypes cannot carry injected text: numbers and booleans.
var scalarTypes = map[string]bool{
	"bool": true, "byte": true, "rune": true,
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true, "uintptr": true,
	"float32": true, "float64": true, "complex64": true, "complex128": true,
}

// pkgFacts are the declarations of one package directory.
type pkgFacts struct {
	fields        map[string]map[string]typeRef
	embeds        map[string][]typeRef
	ifaces        map[string]map[string]int
	vars          map[string]typeRef
	funcResults   map[string]typeRef
	methodResults map[string]map[string]typeRef
	importPaths   map[string]bool
}

func newPkgFacts() *pkgFacts {
	return &pkgFacts{
		fields:        map[string]map[string]typeRef{},
		embeds:        map[string][]typeRef{},
		ifaces:        map[string]map[string]int{},
		vars:          map[string]typeRef{},
		funcResults:   map[string]typeRef{},
		methodResults: map[string]map[string]typeRef{},
		importPaths:   map[string]bool{},
	}
}

func fileImports(file *ast.File) map[string]string {
	imports := map[string]string{}
	for _, imp := range file.Imports {
		importPath := strings.Trim(imp.Path.Value, `"`)
		var alias string
		if imp.Name != nil {
			alias = imp.Name.Name
		} else {
			parts := strings.Split(importPath, "/")
			alias = parts[len(parts)-1]
			if len(parts) > 1 && isMajorVersionSuffix(alias) {
				alias = parts[len(parts)-2]
			}
			if dot := strings.LastIndex(alias, ".v"); dot > 0 && isMajorVersionSuffix(alias[dot+1:]) {
				alias = alias[:dot] // gopkg.in/yaml.v3 is yaml
			}
		}
		imports[alias] = importPath
	}
	return imports
}

// isMajorVersionSuffix: "v2", "v5"... the last element of a module path whose
// package name is the element before it (github.com/labstack/echo/v4 is echo).
func isMajorVersionSuffix(element string) bool {
	if len(element) < 2 || element[0] != 'v' {
		return false
	}
	_, err := strconv.Atoi(element[1:])
	return err == nil
}

func collectPackageFacts(paths []string) *pkgFacts {
	facts := newPkgFacts()
	fset := token.NewFileSet()
	for _, path := range paths {
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			continue
		}
		imports := fileImports(file)
		for _, importPath := range imports {
			facts.importPaths[importPath] = true
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				facts.addGenDecl(d, imports)
			case *ast.FuncDecl:
				facts.addFuncDecl(d, imports)
			}
		}
	}
	return facts
}

func (f *pkgFacts) addGenDecl(d *ast.GenDecl, imports map[string]string) {
	for _, spec := range d.Specs {
		switch s := spec.(type) {
		case *ast.TypeSpec:
			switch t := s.Type.(type) {
			case *ast.StructType:
				fields := map[string]typeRef{}
				for _, field := range t.Fields.List {
					ref := typeOfExpr(field.Type, imports)
					if len(field.Names) == 0 {
						if ref.known() {
							fields[ref.name] = ref
							f.embeds[s.Name.Name] = append(f.embeds[s.Name.Name], ref)
						}
						continue
					}
					for _, name := range field.Names {
						fields[name.Name] = ref
					}
				}
				f.fields[s.Name.Name] = fields
			case *ast.InterfaceType:
				methods := map[string]int{}
				for _, method := range t.Methods.List {
					fn, ok := method.Type.(*ast.FuncType)
					if !ok {
						continue
					}
					for _, name := range method.Names {
						methods[name.Name] = firstStringParam(fn)
					}
				}
				f.ifaces[s.Name.Name] = methods
			case *ast.Ident, *ast.SelectorExpr, *ast.StarExpr:
				if ref := typeOfExpr(t, imports); ref.known() {
					f.embeds[s.Name.Name] = append(f.embeds[s.Name.Name], ref)
				}
			}
		case *ast.ValueSpec:
			for i, name := range s.Names {
				var ref typeRef
				if s.Type != nil {
					ref = typeOfExpr(s.Type, imports)
				} else if len(s.Values) == len(s.Names) {
					ref = staticValueType(s.Values[i], imports)
				} else if len(s.Values) == 1 && i == 0 {
					ref = staticValueType(s.Values[0], imports)
				}
				if ref.known() {
					f.vars[name.Name] = ref
				}
			}
		}
	}
}

func (f *pkgFacts) addFuncDecl(d *ast.FuncDecl, imports map[string]string) {
	if d.Type.Results == nil || len(d.Type.Results.List) == 0 {
		return
	}
	ref := typeOfExpr(d.Type.Results.List[0].Type, imports)
	if !ref.known() {
		return
	}
	if d.Recv == nil || len(d.Recv.List) == 0 {
		f.funcResults[d.Name.Name] = ref
		return
	}
	recv := typeOfExpr(d.Recv.List[0].Type, imports)
	if recv.pkg != "" || !recv.known() {
		return
	}
	if f.methodResults[recv.name] == nil {
		f.methodResults[recv.name] = map[string]typeRef{}
	}
	f.methodResults[recv.name][d.Name.Name] = ref
}

// firstStringParam is the index of a method's first string parameter (the
// query text of a database interface such as sqlc's DBTX), or -1.
func firstStringParam(fn *ast.FuncType) int {
	index := 0
	for _, field := range fn.Params.List {
		count := len(field.Names)
		if count == 0 {
			count = 1
		}
		if id, ok := field.Type.(*ast.Ident); ok && id.Name == "string" {
			return index
		}
		index += count
	}
	return -1
}

// typeOfExpr reads a type expression.
func typeOfExpr(expr ast.Expr, imports map[string]string) typeRef {
	switch e := expr.(type) {
	case *ast.StarExpr:
		return typeOfExpr(e.X, imports)
	case *ast.ParenExpr:
		return typeOfExpr(e.X, imports)
	case *ast.IndexExpr:
		return typeOfExpr(e.X, imports)
	case *ast.IndexListExpr:
		return typeOfExpr(e.X, imports)
	case *ast.Ident:
		if predeclaredTypes[e.Name] {
			return typeRef{pkg: "builtin", name: e.Name}
		}
		return typeRef{name: e.Name}
	case *ast.SelectorExpr:
		if id, ok := e.X.(*ast.Ident); ok {
			if importPath, ok := imports[id.Name]; ok {
				return typeRef{pkg: importPath, name: e.Sel.Name}
			}
		}
	case *ast.ArrayType:
		if id, ok := e.Elt.(*ast.Ident); ok && id.Name == "byte" {
			return typeRef{pkg: "builtin", name: "[]byte"}
		}
		return typeRef{pkg: "builtin", name: "slice"}
	case *ast.MapType:
		return typeRef{pkg: "builtin", name: "map"}
	case *ast.InterfaceType:
		return typeRef{pkg: "builtin", name: "any"}
	}
	return typeRef{}
}

// staticValueType: the type of a package-level initialiser, without a
// function scope (composite literals, new(T), known constructors).
func staticValueType(expr ast.Expr, imports map[string]string) typeRef {
	switch e := expr.(type) {
	case *ast.ParenExpr:
		return staticValueType(e.X, imports)
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return staticValueType(e.X, imports)
		}
	case *ast.CompositeLit:
		return typeOfExpr(e.Type, imports)
	case *ast.CallExpr:
		if id, ok := e.Fun.(*ast.Ident); ok && id.Name == "new" && len(e.Args) == 1 {
			return typeOfExpr(e.Args[0], imports)
		}
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			if pkgIdent, ok := sel.X.(*ast.Ident); ok {
				if importPath, ok := imports[pkgIdent.Name]; ok {
					return constructorType(importPath, sel.Sel.Name)
				}
			}
		}
	}
	return typeRef{}
}

func isPgxPath(importPath string) bool {
	return importPath == "github.com/jackc/pgx" || strings.HasPrefix(importPath, "github.com/jackc/pgx/")
}

func isGormPath(importPath string) bool {
	return importPath == "gorm.io/gorm" || importPath == "github.com/jinzhu/gorm"
}

func isGinPath(importPath string) bool {
	return strings.HasPrefix(importPath, "github.com/gin-gonic/gin")
}

func isEchoPath(importPath string) bool {
	return strings.HasPrefix(importPath, "github.com/labstack/echo")
}

func isFiberPath(importPath string) bool {
	return strings.HasPrefix(importPath, "github.com/gofiber/fiber")
}

const sqlxPath = "github.com/jmoiron/sqlx"
const sshPath = "golang.org/x/crypto/ssh"

// isSQLLibraryPath: an import that proves the package talks to a SQL database.
func isSQLLibraryPath(importPath string) bool {
	return importPath == "database/sql" || importPath == sqlxPath || isPgxPath(importPath) ||
		isGormPath(importPath) || strings.HasPrefix(importPath, "github.com/jackc/pgconn")
}

// constructorType: package functions that return a database, client or
// session handle.
func constructorType(importPath, name string) typeRef {
	switch {
	case importPath == "database/sql":
		if name == "Open" || name == "OpenDB" {
			return typeRef{pkg: importPath, name: "DB"}
		}
	case importPath == sqlxPath:
		switch name {
		case "Open", "Connect", "ConnectContext", "MustConnect", "MustOpen", "NewDb":
			return typeRef{pkg: importPath, name: "DB"}
		}
	case isPgxPath(importPath) && strings.HasSuffix(importPath, "/pgxpool"):
		switch name {
		case "New", "NewWithConfig", "Connect", "ConnectConfig":
			return typeRef{pkg: importPath, name: "Pool"}
		}
	case isPgxPath(importPath):
		switch name {
		case "Connect", "ConnectConfig":
			return typeRef{pkg: importPath, name: "Conn"}
		}
	case isGormPath(importPath):
		if name == "Open" {
			return typeRef{pkg: importPath, name: "DB"}
		}
	case importPath == sshPath:
		if name == "Dial" || name == "NewClient" {
			return typeRef{pkg: importPath, name: "Client"}
		}
	case importPath == bluemondayPath:
		switch name {
		case "NewPolicy", "UGCPolicy", "StrictPolicy", "StripTagsPolicy":
			return typeRef{pkg: importPath, name: "Policy"}
		}
	case numericBarriers[importPath][name] && importPath != "strconv":
		return typeRef{pkg: importPath, name: "UUID"}
	}
	return typeRef{}
}

// isFixedFormatType: a value whose text form is fixed digits and punctuation
// (a UUID or a time), so formatting it into a query adds no SQL.
func isFixedFormatType(ref typeRef) bool {
	if ref.name == "UUID" && strings.Contains(ref.pkg, "uuid") {
		return true
	}
	return ref.pkg == "time" && (ref.name == "Time" || ref.name == "Duration")
}

// Request accessors that return a string.
var stringRequestMethods = map[string]bool{
	"Query": true, "DefaultQuery": true, "Param": true, "Params": true, "PostForm": true,
	"DefaultPostForm": true, "GetHeader": true, "FormValue": true, "PostFormValue": true,
	"QueryParam": true, "QueryString": true, "Get": true, "UserAgent": true, "Referer": true,
	"FullPath": true, "ContentType": true, "OriginalURL": true, "Path": true, "Hostname": true,
	"BaseURL": true, "RealIP": true, "ClientIP": true, "IP": true,
}

// libMethodResult: the result type of a method on a known library type.
func libMethodResult(recv typeRef, method string) typeRef {
	switch {
	case recv.pkg == "database/sql" && recv.name == "DB":
		switch method {
		case "Begin", "BeginTx":
			return typeRef{pkg: recv.pkg, name: "Tx"}
		case "Conn":
			return typeRef{pkg: recv.pkg, name: "Conn"}
		}
	case recv.pkg == sqlxPath && recv.name == "DB":
		switch method {
		case "Beginx", "MustBegin", "BeginTxx", "MustBeginTx":
			return typeRef{pkg: recv.pkg, name: "Tx"}
		case "Connx":
			return typeRef{pkg: recv.pkg, name: "Conn"}
		case "Unsafe":
			return recv
		}
	case isPgxPath(recv.pkg):
		switch method {
		case "Begin", "BeginTx":
			return typeRef{pkg: recv.pkg, name: "Tx"}
		case "Acquire":
			if recv.name == "Pool" {
				return typeRef{pkg: recv.pkg, name: "Conn"}
			}
		}
	case isGormPath(recv.pkg) && recv.name == "DB":
		switch method {
		case "DB":
			return typeRef{pkg: "database/sql", name: "DB"}
		case "Row", "Rows", "ScanRows", "Error", "Statement", "Callback", "Migrator", "AddError", "Transaction", "Get", "InstanceGet", "Association", "SetupJoinTable", "Use", "ToSQL":
			return typeRef{}
		}
		return recv
	case recv.pkg == sshPath && recv.name == "Client":
		if method == "NewSession" {
			return typeRef{pkg: recv.pkg, name: "Session"}
		}
	case recv.pkg == "net/http" && recv.name == "Request":
		switch method {
		case "FormValue", "PostFormValue", "UserAgent", "Referer":
			return builtinString
		}
	case isGinPath(recv.pkg) && recv.name == "Context",
		isEchoPath(recv.pkg) && recv.name == "Context",
		isFiberPath(recv.pkg) && recv.name == "Ctx":
		if stringRequestMethods[method] {
			return builtinString
		}
		switch method {
		case "QueryArray", "PostFormArray", "ParamValues", "ParamNames":
			return typeRef{pkg: "builtin", name: "slice"}
		case "QueryMap", "PostFormMap", "QueryParams", "FormParams", "Queries", "AllParams":
			return typeRef{pkg: "builtin", name: "map"}
		}
	}
	return typeRef{}
}

var strconvResultTypes = map[string]string{
	"Atoi": "int", "ParseInt": "int64", "ParseUint": "uint64", "ParseFloat": "float64", "ParseBool": "bool",
}

var stringsFuncsReturningString = map[string]bool{
	"Join": true, "Replace": true, "ReplaceAll": true, "ToLower": true, "ToUpper": true,
	"TrimSpace": true, "Trim": true, "TrimLeft": true, "TrimRight": true, "TrimPrefix": true,
	"TrimSuffix": true, "Title": true, "Repeat": true, "ToTitle": true, "Clone": true,
}

// localDecl: the name is declared in the function (so it is not a package).
func localDecl(name string, ft *funcTaint) bool {
	if _, ok := ft.declTypes[name]; ok {
		return true
	}
	if _, ok := ft.defs[name]; ok {
		return true
	}
	_, ok := ft.multiDefs[name]
	return ok
}

func (a *Analyzer) packageOf(expr ast.Expr, ft *funcTaint) (string, bool) {
	id, ok := expr.(*ast.Ident)
	if !ok || localDecl(id.Name, ft) {
		return "", false
	}
	importPath, ok := a.imports[id.Name]
	return importPath, ok
}

// resolveType resolves the type of an expression, or returns an unknown ref.
func (a *Analyzer) resolveType(expr ast.Expr, ft *funcTaint, depth int) typeRef {
	if depth > 8 || expr == nil {
		return typeRef{}
	}
	switch e := expr.(type) {
	case *ast.ParenExpr:
		return a.resolveType(e.X, ft, depth+1)
	case *ast.StarExpr:
		return a.resolveType(e.X, ft, depth+1)
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return a.resolveType(e.X, ft, depth+1)
		}
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			return builtinString
		}
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			left := a.resolveType(e.X, ft, depth+1)
			if left == builtinString {
				return left
			}
			if right := a.resolveType(e.Y, ft, depth+1); right == builtinString {
				return right
			}
		}
	case *ast.CompositeLit:
		return typeOfExpr(e.Type, a.imports)
	case *ast.TypeAssertExpr:
		if e.Type != nil {
			return typeOfExpr(e.Type, a.imports)
		}
	case *ast.Ident:
		if t, ok := ft.declTypes[e.Name]; ok {
			return typeOfExpr(t, a.imports)
		}
		for _, value := range ft.defs[e.Name] {
			if value == nil {
				continue
			}
			if ref := a.resolveType(value, ft, depth+1); ref.known() {
				return ref
			}
		}
		for _, value := range ft.multiDefs[e.Name] {
			if ref := a.resolveType(value, ft, depth+1); ref.known() {
				return ref
			}
		}
		if a.facts != nil {
			if ref, ok := a.facts.vars[e.Name]; ok {
				return ref
			}
		}
	case *ast.SelectorExpr:
		if importPath, ok := a.packageOf(e.X, ft); ok {
			if importPath == "net/http" && e.Sel.Name == "DefaultClient" {
				return typeRef{pkg: "net/http", name: "Client"}
			}
			return typeRef{}
		}
		if ref, ok := a.inlineStructField(e, ft); ok {
			return ref
		}
		owner := a.resolveType(e.X, ft, depth+1)
		if !owner.known() {
			return typeRef{}
		}
		if owner.pkg == "" && a.facts != nil {
			if fields, ok := a.facts.fields[owner.name]; ok {
				if ref, ok := fields[e.Sel.Name]; ok {
					return ref
				}
			}
			return typeRef{}
		}
		if e.Sel.Name == "Writer" && isGinPath(owner.pkg) && owner.name == "Context" {
			return typeRef{pkg: "net/http", name: "ResponseWriter"}
		}
		if e.Sel.Name == "Writer" && isEchoPath(owner.pkg) && owner.name == "Response" {
			return typeRef{pkg: "net/http", name: "ResponseWriter"}
		}
		if owner.is("net/http", "Request") && e.Sel.Name == "URL" {
			return typeRef{pkg: "net/url", name: "URL"}
		}
	case *ast.CallExpr:
		return a.callResultType(e, ft, depth)
	}
	return typeRef{}
}

// inlineStructField: v.F where v is declared with an anonymous struct type
// (var req struct{ Limit int }), the usual shape of a handler's bind target.
func (a *Analyzer) inlineStructField(sel *ast.SelectorExpr, ft *funcTaint) (typeRef, bool) {
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return typeRef{}, false
	}
	declared := ft.declTypes[id.Name]
	if star, ok := declared.(*ast.StarExpr); ok {
		declared = star.X
	}
	st, ok := declared.(*ast.StructType)
	if !ok {
		return typeRef{}, false
	}
	for _, field := range st.Fields.List {
		for _, name := range field.Names {
			if name.Name == sel.Sel.Name {
				return typeOfExpr(field.Type, a.imports), true
			}
		}
	}
	return typeRef{}, true
}

func (a *Analyzer) callResultType(call *ast.CallExpr, ft *funcTaint, depth int) typeRef {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		switch fun.Name {
		case "new":
			if len(call.Args) == 1 {
				return typeOfExpr(call.Args[0], a.imports)
			}
		case "len", "cap":
			return typeRef{pkg: "builtin", name: "int"}
		case "string":
			return builtinString
		}
		if predeclaredTypes[fun.Name] {
			return typeRef{pkg: "builtin", name: fun.Name}
		}
		if a.facts != nil {
			if ref, ok := a.facts.funcResults[fun.Name]; ok {
				return ref
			}
		}
	case *ast.ArrayType:
		return typeOfExpr(fun, a.imports)
	case *ast.SelectorExpr:
		if importPath, ok := a.packageOf(fun.X, ft); ok {
			switch {
			case importPath == "fmt" && strings.HasPrefix(fun.Sel.Name, "Sprint"):
				return builtinString
			case importPath == "strings" && stringsFuncsReturningString[fun.Sel.Name]:
				return builtinString
			case importPath == "strconv":
				if name, ok := strconvResultTypes[fun.Sel.Name]; ok {
					return typeRef{pkg: "builtin", name: name}
				}
			}
			return constructorType(importPath, fun.Sel.Name)
		}
		recv := a.resolveType(fun.X, ft, depth+1)
		if !recv.known() {
			return typeRef{}
		}
		if recv.pkg == "" && a.facts != nil {
			if results, ok := a.facts.methodResults[recv.name]; ok {
				if ref, ok := results[fun.Sel.Name]; ok {
					return ref
				}
			}
			for _, embedded := range a.facts.embeds[recv.name] {
				if ref := libMethodResult(embedded, fun.Sel.Name); ref.known() {
					return ref
				}
			}
			return typeRef{}
		}
		return libMethodResult(recv, fun.Sel.Name)
	}
	return typeRef{}
}

func isScalarRef(ref typeRef) bool {
	return ref.pkg == "builtin" && scalarTypes[ref.name]
}

// isScalarTyped: the expression has a numeric or boolean type, so it cannot
// carry injected text whatever its origin. A variable counts only when its
// declaration and every value assigned to it agree.
func (a *Analyzer) isScalarTyped(expr ast.Expr, ft *funcTaint) bool {
	if id, ok := expr.(*ast.Ident); ok {
		declared, isDeclared := ft.declTypes[id.Name]
		if !isDeclared && len(ft.defs[id.Name]) == 0 && len(ft.multiDefs[id.Name]) == 0 {
			return a.facts != nil && isScalarRef(a.facts.vars[id.Name])
		}
		if isDeclared && !isScalarRef(typeOfExpr(declared, a.imports)) {
			return false
		}
		evidence := isDeclared
		unresolved := 0
		for _, value := range ft.defs[id.Name] {
			if value == nil {
				unresolved++
				continue
			}
			if !isScalarRef(a.resolveType(value, ft, 1)) {
				return false
			}
			evidence = true
		}
		if unresolved > len(ft.multiDefs[id.Name]) {
			return false // a later position of `a, b := f()`: unknown type
		}
		for _, value := range ft.multiDefs[id.Name] {
			if !isScalarRef(a.resolveType(value, ft, 1)) {
				return false
			}
			evidence = true
		}
		return evidence
	}
	return isScalarRef(a.resolveType(expr, ft, 0))
}

// isNonStringTyped: the expression resolves to a type other than string (a
// struct, map, slice or pointer that an ORM binds as parameters).
func (a *Analyzer) isNonStringTyped(expr ast.Expr, ft *funcTaint) bool {
	if unary, ok := expr.(*ast.UnaryExpr); ok && unary.Op == token.AND {
		return true
	}
	if call, ok := expr.(*ast.CallExpr); ok {
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && len(call.Args) == 1 && sel.Sel.Name == "Get" {
			if _, isLit := stringLiteralValue(call.Args[0]); isLit {
				return false // r.URL.Query().Get("k"), r.Header.Get("k")
			}
		}
	}
	ref := a.resolveType(expr, ft, 0)
	return ref.known() && ref != builtinString
}

// collectDeclTypes records the declared type of every parameter, receiver,
// named result and typed var in a function, closures included. A name
// declared twice with different types (shadowing) is left out: unknown.
func collectDeclTypes(fd *ast.FuncDecl, imports map[string]string) map[string]ast.Expr {
	types := map[string]ast.Expr{}
	conflicting := map[string]bool{}
	add := func(name string, typ ast.Expr) {
		if name == "_" || conflicting[name] {
			return
		}
		if previous, seen := types[name]; seen {
			_, prevAnon := previous.(*ast.StructType)
			_, anon := typ.(*ast.StructType)
			if prevAnon || anon || typeOfExpr(previous, imports) != typeOfExpr(typ, imports) {
				delete(types, name)
				conflicting[name] = true
			}
			return
		}
		types[name] = typ
	}
	addFields := func(list *ast.FieldList) {
		if list == nil {
			return
		}
		for _, field := range list.List {
			for _, name := range field.Names {
				add(name.Name, field.Type)
			}
		}
	}
	addFields(fd.Recv)
	addFields(fd.Type.Params)
	addFields(fd.Type.Results)
	if fd.Body == nil {
		return types
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncLit:
			addFields(node.Type.Params)
			addFields(node.Type.Results)
		case *ast.ValueSpec:
			if node.Type != nil {
				for _, name := range node.Names {
					add(name.Name, node.Type)
				}
			}
		}
		return true
	})
	return types
}

// collectMultiDefs records, for `a, b := f()`, the call that defines the
// first name (its result type is the call's first result).
func collectMultiDefs(body ast.Node) map[string][]ast.Expr {
	defs := map[string][]ast.Expr{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Rhs) == 1 && len(node.Lhs) > 1 {
				if id, ok := node.Lhs[0].(*ast.Ident); ok {
					defs[id.Name] = append(defs[id.Name], node.Rhs[0])
				}
			}
		case *ast.ValueSpec:
			if len(node.Values) == 1 && len(node.Names) > 1 {
				defs[node.Names[0].Name] = append(defs[node.Names[0].Name], node.Values[0])
			}
		}
		return true
	})
	return defs
}

// hasSQLEvidence: the current file or another file of its package imports a
// SQL library.
func (a *Analyzer) hasSQLEvidence() bool {
	for _, importPath := range a.imports {
		if isSQLLibraryPath(importPath) {
			return true
		}
	}
	if a.facts == nil {
		return false
	}
	for importPath := range a.facts.importPaths {
		if isSQLLibraryPath(importPath) {
			return true
		}
	}
	return false
}

func (a *Analyzer) hasImportMatching(match func(string) bool) bool {
	for _, importPath := range a.imports {
		if match(importPath) {
			return true
		}
	}
	if a.facts == nil {
		return false
	}
	for importPath := range a.facts.importPaths {
		if match(importPath) {
			return true
		}
	}
	return false
}

// frameworkOf names the web framework of a request-context expression.
func (a *Analyzer) frameworkOf(expr ast.Expr, ft *funcTaint) string {
	ref := a.resolveType(expr, ft, 0)
	switch {
	case isGinPath(ref.pkg) && ref.name == "Context":
		return "gin"
	case isEchoPath(ref.pkg) && ref.name == "Context":
		return "echo"
	case isFiberPath(ref.pkg) && ref.name == "Ctx":
		return "fiber"
	}
	return ""
}

// exprKey renders an identifier or field path ("w", "h.out").
func exprKey(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.ParenExpr:
		return exprKey(e.X)
	case *ast.StarExpr:
		return exprKey(e.X)
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return exprKey(e.X)
		}
	case *ast.SelectorExpr:
		if base := exprKey(e.X); base != "" {
			return base + "." + e.Sel.Name
		}
	}
	return ""
}
