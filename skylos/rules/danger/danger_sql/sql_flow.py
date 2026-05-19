from __future__ import annotations
import ast
import sys
from skylos.rules.danger.taint import TaintVisitor


DB_MODULES = frozenset(
    {
        "sqlite3",
        "psycopg2",
        "psycopg",
        "pymysql",
        "MySQLdb",
        "cx_Oracle",
        "oracledb",
        "pyodbc",
        "sqlalchemy",
        "asyncpg",
        "aiosqlite",
        "databases",
        "peewee",
        "tortoise",
        "django.db",
    }
)

DB_RECEIVER_NAMES = frozenset(
    {
        "cursor",
        "cur",
        "conn",
        "connection",
        "db",
        "database",
        "session",
        "engine",
        "tx",
        "transaction",
    }
)


def _qualified_name_from_call(node):
    func = node.func
    parts = []

    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
        parts.reverse()
        return ".".join(parts)
    return None


def _is_static_string_expr(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)

    if isinstance(node, ast.JoinedStr):
        for value in node.values:
            if isinstance(value, ast.Constant):
                continue
            if isinstance(value, ast.FormattedValue) and isinstance(
                value.value, ast.Constant
            ):
                continue
            return False
        return True

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_static_string_expr(node.left) and _is_static_string_expr(node.right)

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        if not _is_static_string_expr(node.left):
            return False
        right = node.right
        if isinstance(right, ast.Tuple):
            return all(_is_static_string_expr(elt) for elt in right.elts)
        return _is_static_string_expr(right)

    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return (
            _is_static_string_expr(node.func.value)
            and all(_is_static_string_expr(arg) for arg in node.args)
            and all(_is_static_string_expr(k.value) for k in node.keywords)
        )

    return False


def _is_interpolated_string(node):
    if isinstance(node, ast.JoinedStr):
        return not _is_static_string_expr(node)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return not _is_static_string_expr(node)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return not _is_static_string_expr(node)
    return False


def _is_passthrough_return(node: ast.AST, param_names):
    if isinstance(node, ast.Name) and node.id in param_names:
        return True

    if isinstance(node, ast.JoinedStr):
        for v in node.values:
            if (
                isinstance(v, ast.FormattedValue)
                and isinstance(v.value, ast.Name)
                and v.value.id in param_names
            ):
                return True
        return True

    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return True
    if isinstance(node, ast.BinOp):
        return True
    return False


def _func_name(node):
    return node.name


def _receiver_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Attribute):
        value = node.func.value
        if isinstance(value, ast.Name):
            return value.id
        if isinstance(value, ast.Attribute):
            return value.attr
    return None


def _qualified_name_from_expr(node: ast.AST) -> str | None:
    parts = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        parts.reverse()
        return ".".join(parts)
    return None


def get_query_expression(call: ast.Call, names=("sql", "query", "statement")):
    expression = None
    if call.args and len(call.args) > 0:
        expression = call.args[0]
    if expression is None:
        for keyword in call.keywords or []:
            if keyword.arg in names and keyword.value is not None:
                expression = keyword.value
                break
    return expression


def is_parameterized_query(call: ast.Call, query_expr: ast.AST):
    if _is_interpolated_string(query_expr):
        return False

    if len(call.args) >= 2:
        return True

    for keyword in call.keywords or []:
        if keyword.arg in {"params", "parameters"}:
            return True
    return False


def is_sqlalchemy_text(expr: ast.AST):
    if not isinstance(expr, ast.Call):
        return False

    func = expr.func

    if isinstance(func, ast.Attribute) and func.attr == "text":
        return True

    if isinstance(func, ast.Name) and func.id == "text":
        return True
    return False


class _SQLFlowChecker(TaintVisitor):
    RULE_ID_SQLI = "SKY-D211"
    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    DBAPI_SQL_SINK_SUFFIXES = (".execute", ".executemany", ".executescript")

    def __init__(self, file_path, findings):
        super().__init__(file_path, findings)
        self.passthrough_functions: set[str] = set()
        self.db_names: set[str] = set()
        self.static_string_stack: list[dict[str, bool]] = [{}]
        self.db_receiver_alias_stack: list[set[str]] = [set()]

    def _push(self):
        super()._push()
        self.static_string_stack.append({})
        self.db_receiver_alias_stack.append(set())

    def _pop(self):
        if len(self.static_string_stack) > 1:
            self.static_string_stack.pop()
        if len(self.db_receiver_alias_stack) > 1:
            self.db_receiver_alias_stack.pop()
        super()._pop()

    def _set_static_string(self, name: str, is_static: bool) -> None:
        if not self.static_string_stack:
            self.static_string_stack.append({})
        self.static_string_stack[-1][name] = bool(is_static)

    def _is_static_string_name(self, name: str) -> bool:
        for scope in reversed(self.static_string_stack):
            if name in scope:
                return scope[name]
        return False

    def _is_static_query_expr(self, node: ast.AST) -> bool:
        if _is_static_string_expr(node):
            return True
        if isinstance(node, ast.Name):
            return self._is_static_string_name(node.id)
        return False

    def _mark_db_receiver_alias(self, name: str) -> None:
        if not self.db_receiver_alias_stack:
            self.db_receiver_alias_stack.append(set())
        self.db_receiver_alias_stack[-1].add(name)

    def _is_known_db_receiver_name(self, name: str) -> bool:
        if name in self.db_names:
            return True
        return any(name in scope for scope in reversed(self.db_receiver_alias_stack))

    def _is_db_reference(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            return self._is_db_reference(node.func)

        if isinstance(node, ast.Name):
            return self._is_known_db_receiver_name(node.id)

        qual_name = _qualified_name_from_expr(node)
        if not qual_name:
            return False

        root = qual_name.split(".", 1)[0]
        if root in DB_MODULES:
            return True
        return self._is_known_db_receiver_name(root)

    def _track_db_receiver_aliases(self, targets, value: ast.AST | None) -> None:
        if value is None or not self._is_db_reference(value):
            return

        for target in targets:
            if isinstance(target, ast.Name):
                self._mark_db_receiver_alias(target.id)
            elif isinstance(target, ast.Attribute):
                self._mark_db_receiver_alias(target.attr)

    def visit_Import(self, node):
        for alias in node.names:
            top_level = alias.name.split(".")[0]
            if top_level in DB_MODULES or alias.name in DB_MODULES:
                self.db_names.add(alias.asname or alias.name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            top_level = node.module.split(".")[0]
            if top_level in DB_MODULES or node.module in DB_MODULES:
                for alias in node.names:
                    self.db_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def _is_likely_db_receiver(self, node: ast.Call) -> bool:
        name = _receiver_name(node)
        if name is None:
            return False

        if self._is_known_db_receiver_name(name):
            return True

        if name.lower() in DB_RECEIVER_NAMES:
            return True

        lower = name.lower()
        if any(hint in lower for hint in ("cursor", "conn", "session", "engine", "db")):
            return True

        return False

    def _record_passthrough_function(self, node):
        param_names = {a.arg for a in node.args.args}
        for statement in node.body:
            if isinstance(statement, ast.Return) and statement.value is not None:
                if _is_passthrough_return(statement.value, param_names):
                    self.passthrough_functions.add(_func_name(node))
                    break

    def visit_FunctionDef(self, node):
        self._record_passthrough_function(node)
        super().visit_FunctionDef(node)

    def visit_AsyncFunctionDef(self, node):
        self._record_passthrough_function(node)
        super().visit_AsyncFunctionDef(node)

    def visit_Assign(self, node):
        self._track_db_receiver_aliases(node.targets, node.value)
        is_static = self._is_static_query_expr(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._set_static_string(target.id, is_static)
        super().visit_Assign(node)

    def visit_AnnAssign(self, node):
        self._track_db_receiver_aliases([node.target], node.value)
        if node.value and isinstance(node.target, ast.Name):
            self._set_static_string(
                node.target.id,
                self._is_static_query_expr(node.value),
            )
        super().visit_AnnAssign(node)

    def visit_AugAssign(self, node):
        if isinstance(node.target, ast.Name):
            target_name = node.target.id
            remains_static = (
                isinstance(node.op, ast.Add)
                and self._is_static_string_name(target_name)
                and self._is_static_query_expr(node.value)
            )
            self._set_static_string(target_name, remains_static)
            self._set(target_name, self._get(target_name) or self.is_tainted(node.value))
        self.generic_visit(node)

    def visit_Call(self, node):
        qual_name = _qualified_name_from_call(node)

        if qual_name and qual_name in self.passthrough_functions:
            pass

        if qual_name and qual_name.endswith(self.DBAPI_SQL_SINK_SUFFIXES):
            if not self._is_likely_db_receiver(node):
                self.generic_visit(node)
                return

            query_expr = get_query_expression(node, names=("sql", "query", "statement"))

            if query_expr is not None:
                if _is_interpolated_string(query_expr) or self.is_tainted(query_expr):
                    self.findings.append(
                        {
                            "rule_id": self.RULE_ID_SQLI,
                            "severity": self.SEVERITY_CRITICAL,
                            "message": "Possible SQL injection: tainted or string-built query.",
                            "file": str(self.file_path),
                            "line": node.lineno,
                            "col": node.col_offset,
                            "symbol": self._current_symbol(),
                        }
                    )
                else:
                    is_literal = self._is_static_query_expr(query_expr)
                    if not is_literal and not is_parameterized_query(node, query_expr):
                        self.findings.append(
                            {
                                "rule_id": self.RULE_ID_SQLI,
                                "severity": self.SEVERITY_HIGH,
                                "message": "Likely unparameterized SQL execution.",
                                "file": str(self.file_path),
                                "line": node.lineno,
                                "col": node.col_offset,
                                "symbol": self._current_symbol(),
                            }
                        )

            self.generic_visit(node)
            return

        # ----- Pandas read_sql / read_sql_query -----
        if qual_name and (
            qual_name.endswith(".read_sql") or qual_name.endswith(".read_sql_query")
        ):
            query_expr = get_query_expression(node, names=("sql", "query"))

            if query_expr is not None and (
                _is_interpolated_string(query_expr) or self.is_tainted(query_expr)
            ):
                self.findings.append(
                    {
                        "rule_id": self.RULE_ID_SQLI,
                        "severity": self.SEVERITY_CRITICAL,
                        "message": "Possible SQL injection in read_sql.",
                        "file": str(self.file_path),
                        "line": node.lineno,
                        "col": node.col_offset,
                        "symbol": self._current_symbol(),
                    }
                )
            self.generic_visit(node)
            return

        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            if not self._is_likely_db_receiver(node):
                self.generic_visit(node)
                return

            statement_expression = get_query_expression(
                node, names=("statement", "sql", "query")
            )
            if statement_expression is not None:
                if _is_interpolated_string(statement_expression) or self.is_tainted(
                    statement_expression
                ):
                    self.findings.append(
                        {
                            "rule_id": self.RULE_ID_SQLI,
                            "severity": self.SEVERITY_CRITICAL,
                            "message": "Possible SQL injection: tainted statement passed to execute().",
                            "file": str(self.file_path),
                            "line": node.lineno,
                            "col": node.col_offset,
                            "symbol": self._current_symbol(),
                        }
                    )

            self.generic_visit(node)
            return

        if is_sqlalchemy_text(node):
            for argument in node.args:
                if _is_interpolated_string(argument) or self.is_tainted(argument):
                    self.findings.append(
                        {
                            "rule_id": self.RULE_ID_SQLI,
                            "severity": self.SEVERITY_CRITICAL,
                            "message": "Possible SQL injection: tainted string used in sqlalchemy.text().",
                            "file": str(self.file_path),
                            "line": node.lineno,
                            "col": node.col_offset,
                            "symbol": self._current_symbol(),
                        }
                    )
                    break

        self.generic_visit(node)


def scan(tree, file_path, findings):
    try:
        checker = _SQLFlowChecker(file_path, findings)
        checker.visit(tree)
    except Exception as e:
        print(f"SQL flow analysis failed for {file_path}: {e}", file=sys.stderr)
