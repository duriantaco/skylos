package analyzer

import (
	"go/ast"
	"go/token"
	"strings"
)

// SQL sinks (SKY-G211). A call is a sink when its receiver is a database
// handle of a known library, resolved from declarations (database/sql,
// jmoiron/sqlx, jackc/pgx and pgxpool, GORM; sink lists follow gosec G201/G202
// and CodeQL's sqlx and GORM models). A local struct embedding one of them
// and a local interface with query methods (sqlc's DBTX) count too. When the
// receiver cannot be resolved, a database-like name is still accepted: a
// plain variable as before, a field (s.db, r.DB) only when the package
// imports a SQL library.

// queryArg per method; Select/Get take the destination first.
var sqlMethodArgs = map[string]map[string]int{
	"sql": {
		"Query": 0, "QueryRow": 0, "Exec": 0, "Prepare": 0,
		"QueryContext": 1, "QueryRowContext": 1, "ExecContext": 1, "PrepareContext": 1,
	},
	"sqlx": {
		"Query": 0, "QueryRow": 0, "Exec": 0, "Prepare": 0,
		"QueryContext": 1, "QueryRowContext": 1, "ExecContext": 1, "PrepareContext": 1,
		"Queryx": 0, "QueryRowx": 0, "MustExec": 0, "NamedExec": 0, "NamedQuery": 0,
		"Preparex": 0, "PrepareNamed": 0, "Select": 1, "Get": 1,
		"QueryxContext": 1, "QueryRowxContext": 1, "MustExecContext": 1, "NamedExecContext": 1,
		"NamedQueryContext": 1, "PreparexContext": 1, "PrepareNamedContext": 1,
		"SelectContext": 2, "GetContext": 2,
	},
	"pgx": {
		"Query": 1, "QueryRow": 1, "Exec": 1, "Prepare": 2, "QueryFunc": 1, "ExecParams": 1,
	},
	"pgx3": {
		"Query": 0, "QueryRow": 0, "Exec": 0, "Prepare": 1,
	},
	"gorm": {
		"Where": 0, "Raw": 0, "Order": 0, "Not": 0, "Or": 0, "Select": 0, "Table": 0,
		"Group": 0, "Having": 0, "Joins": 0, "Exec": 0, "Distinct": 0, "Pluck": 0,
	},
}

// GORM inline conditions: db.First(&u, cond) runs a string cond as SQL (GORM
// security docs: "db.First(&user, userInputID)" is SQL injection).
var gormInlineConditionMethods = map[string]bool{
	"First": true, "Find": true, "Take": true, "Last": true, "Delete": true,
}

// sqlx package functions take a Queryer/Execer first.
var sqlxPackageFuncArgs = map[string]int{
	"Select": 2, "Get": 2, "SelectContext": 3, "GetContext": 3,
	"NamedExec": 1, "NamedQuery": 1, "MustExec": 1,
	"NamedExecContext": 2, "NamedQueryContext": 2, "MustExecContext": 2,
}

// Receiver names kept from the original name-only check, accepted without
// any import evidence.
var legacySQLReceiverNames = map[string]bool{
	"db": true, "tx": true, "conn": true, "sqldb": true, "database": true,
}

func dbLikeName(name string) bool {
	lower := strings.ToLower(name)
	if legacySQLReceiverNames[lower] {
		return true
	}
	switch lower {
	case "pool", "dbpool", "pgpool", "pgxpool", "sqlx", "gormdb", "orm", "querier", "queries":
		return true
	}
	if strings.HasSuffix(lower, "tx") && !strings.HasSuffix(lower, "ctx") {
		return true
	}
	return strings.HasSuffix(lower, "db") || strings.HasPrefix(lower, "db")
}

func (a *Analyzer) sqlKind(ref typeRef, depth int) string {
	switch {
	case !ref.known():
		return ""
	case ref.pkg == "database/sql":
		switch ref.name {
		case "DB", "Tx", "Conn":
			return "sql"
		}
		return "nonsql"
	case ref.pkg == sqlxPath:
		switch ref.name {
		case "DB", "Tx", "Conn":
			return "sqlx"
		}
		return "nonsql"
	case ref.pkg == "github.com/jackc/pgx":
		switch ref.name {
		case "Conn", "ConnPool", "Tx":
			return "pgx3"
		}
		return "nonsql"
	case isPgxPath(ref.pkg) || ref.pkg == "github.com/jackc/pgconn":
		switch ref.name {
		case "Conn", "Tx", "Pool", "PgConn":
			return "pgx"
		}
		return "nonsql"
	case isGormPath(ref.pkg):
		if ref.name == "DB" {
			return "gorm"
		}
		return "nonsql"
	case ref.pkg == "" && a.facts != nil && depth < 4:
		for _, embedded := range a.facts.embeds[ref.name] {
			if kind := a.sqlKind(embedded, depth+1); kind != "" && kind != "nonsql" {
				return kind
			}
		}
		if methods, ok := a.facts.ifaces[ref.name]; ok && a.hasSQLEvidence() {
			for method := range methods {
				if _, isSQL := sqlMethodArgs["sqlx"][method]; isSQL {
					return "iface:" + ref.name
				}
			}
		}
	}
	return ""
}

// receiverName is the last name of a receiver: db, s.db, or the root of a
// chain such as db.WithContext(ctx).
func receiverName(expr ast.Expr) (string, bool) {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name, true
	case *ast.SelectorExpr:
		return e.Sel.Name, false
	case *ast.ParenExpr:
		return receiverName(e.X)
	case *ast.CallExpr:
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			name, _ := receiverName(sel.X)
			return name, false
		}
	}
	return "", false
}

func (a *Analyzer) looksLikeContext(expr ast.Expr, ft *funcTaint) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		lower := strings.ToLower(e.Name)
		return lower == "ctx" || strings.HasSuffix(lower, "ctx") || lower == "context"
	case *ast.CallExpr:
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			if importPath, ok := a.packageOf(sel.X, ft); ok {
				return importPath == "context"
			}
			return sel.Sel.Name == "Context" || sel.Sel.Name == "UserContext"
		}
	}
	return false
}

// sqlQueryArg returns the query argument of a SQL sink call, and whether the
// library binds non-string arguments as parameters (GORM), in which case only
// a string argument is query text.
func (a *Analyzer) sqlQueryArg(call *ast.CallExpr, ft *funcTaint) (int, bool, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return 0, false, false
	}
	method := sel.Sel.Name
	if importPath, ok := a.packageOf(sel.X, ft); ok {
		if importPath == sqlxPath {
			index, ok := sqlxPackageFuncArgs[method]
			return index, false, ok
		}
		return 0, false, false
	}
	kind := a.sqlKind(a.resolveType(sel.X, ft, 0), 0)
	switch {
	case kind == "nonsql":
		return 0, false, false
	case strings.HasPrefix(kind, "iface:"):
		index, ok := a.facts.ifaces[strings.TrimPrefix(kind, "iface:")][method]
		if !ok || index < 0 {
			return 0, false, false
		}
		if _, isSQL := sqlMethodArgs["sqlx"][method]; !isSQL {
			return 0, false, false
		}
		return index, false, true
	case kind == "gorm":
		if index, ok := sqlMethodArgs["gorm"][method]; ok {
			return index, true, true
		}
		if gormInlineConditionMethods[method] && len(call.Args) >= 2 {
			return 1, true, true
		}
		return 0, false, false
	case kind != "":
		index, ok := sqlMethodArgs[kind][method]
		return index, false, ok
	}
	return a.unresolvedSQLQueryArg(call, sel, ft)
}

func (a *Analyzer) unresolvedSQLQueryArg(call *ast.CallExpr, sel *ast.SelectorExpr, ft *funcTaint) (int, bool, bool) {
	method := sel.Sel.Name
	name, plain := receiverName(sel.X)
	if name == "" || !dbLikeName(name) {
		return 0, false, false
	}
	evidence := a.hasSQLEvidence()
	if !evidence && !(plain && legacySQLReceiverNames[strings.ToLower(name)]) {
		return 0, false, false
	}
	if index, ok := sqlMethodArgs["sql"][method]; ok {
		if index == 0 && len(call.Args) >= 2 && a.hasImportMatching(isPgxPath) && a.looksLikeContext(call.Args[0], ft) {
			index = 1
		}
		return index, false, true
	}
	if !evidence {
		return 0, false, false
	}
	if a.hasImportMatching(isGormPath) {
		if index, ok := sqlMethodArgs["gorm"][method]; ok {
			isDest := false
			if len(call.Args) > 0 {
				if unary, ok := call.Args[0].(*ast.UnaryExpr); ok && unary.Op == token.AND {
					isDest = true
				}
			}
			if !(isDest && a.hasImportMatching(func(p string) bool { return p == sqlxPath })) {
				return index, true, true
			}
		}
	}
	if a.hasImportMatching(func(p string) bool { return p == sqlxPath }) {
		if index, ok := sqlMethodArgs["sqlx"][method]; ok {
			return index, false, true
		}
	}
	return 0, false, false
}
