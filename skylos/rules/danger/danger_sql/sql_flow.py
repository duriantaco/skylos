from __future__ import annotations
import ast
import sys
from collections import Counter
from skylos.rules.danger.taint import TaintVisitor
from skylos.rules.danger.danger_sql.sqlalchemy_provenance import (
    SQLAlchemyTextProvenance,
)
from skylos.rules.danger.untrusted_sources import UntrustedSourceIndex


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


# Calls whose result is a DB-API connection/cursor or SQLAlchemy connection:
# ``sqlite3.connect(...).execute(...)``, ``conn.cursor().execute(...)``,
# ``engine.connect().execute(...)``, ``engine.begin().execute(...)``.
DB_CHAIN_METHODS = frozenset(
    {
        "connect",
        "cursor",
        "begin",
        "begin_nested",
        "execution_options",
        "raw_connection",
        "get_connection",
        "get_session",
    }
)
DB_RECEIVER_HINTS = ("cursor", "conn", "session", "engine", "db")
SQL_EXECUTE_METHODS = frozenset({"execute", "executemany", "executescript"})
# SQLAlchemy / SQLModel Core constructs compile to bound-parameter SQL.
SQL_CONSTRUCT_MODULES = ("sqlalchemy", "sqlmodel")
SQL_CONSTRUCT_NAMES = frozenset(
    {"select", "delete", "insert", "update", "union", "union_all", "exists"}
)
# ``notes.insert().values(...)``, ``User.__table__.delete().where(...)``:
# statements built from a Table object, values bound as parameters.
TABLE_STATEMENT_METHODS = frozenset({"select", "delete", "insert", "update"})
SQL_BUILDER_METHODS = frozenset(
    {
        "values",
        "ordered_values",
        "where",
        "filter",
        "filter_by",
        "returning",
        "order_by",
        "group_by",
        "having",
        "limit",
        "offset",
        "select_from",
        "with_only_columns",
        "on_conflict_do_nothing",
        "on_conflict_do_update",
        "on_duplicate_key_update",
    }
)
_PROCESS_INPUT_ATTRS = frozenset({"sys.argv", "os.environ", "sys.stdin"})
_PROCESS_INPUT_CALLS = frozenset(
    {"os.getenv", "os.environ.get", "sys.stdin.read", "sys.stdin.readline"}
)


def _callee_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    if isinstance(node.func, ast.Name):
        return node.func.id
    return None


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


class _SQLFlowChecker(TaintVisitor):
    RULE_ID_SQLI = "SKY-D211"
    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    DBAPI_SQL_SINK_SUFFIXES = (".execute", ".executemany", ".executescript")

    def __init__(self, tree: ast.AST, file_path, findings):
        super().__init__(file_path, findings)
        self.untrusted_sources = UntrustedSourceIndex(tree)
        self.passthrough_functions: set[str] = set()
        self.db_names: set[str] = set()
        self.sqlalchemy_text = SQLAlchemyTextProvenance(tree)
        self.static_string_stack: list[dict[str, bool]] = [{}]
        self.sql_statement_stack: list[dict[str, bool]] = [{}]
        self.sql_table_stack: list[dict[str, bool]] = [{}]
        bindings = Counter(
            node.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))
        )
        self.rebound_global_sql_names = {
            name for name, count in bindings.items() if count > 1
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Global):
                self.rebound_global_sql_names.update(node.names)
            elif isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                root = self._sql_binding_root(node)
                if root is not None:
                    self.rebound_global_sql_names.add(root)
        self.db_receiver_alias_stack: list[set[str]] = [set()]

    def _push(self):
        super()._push()
        self.static_string_stack.append({})
        self.sql_statement_stack.append({})
        self.sql_table_stack.append({})
        self.db_receiver_alias_stack.append(set())

    def _pop(self):
        if len(self.static_string_stack) > 1:
            self.static_string_stack.pop()
        if len(self.sql_statement_stack) > 1:
            self.sql_statement_stack.pop()
        if len(self.sql_table_stack) > 1:
            self.sql_table_stack.pop()
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

    def _set_sql_statement(self, name: str, is_statement: bool) -> None:
        if not self.sql_statement_stack:
            self.sql_statement_stack.append({})
        self.sql_statement_stack[-1][name] = bool(is_statement)

    def _is_sql_statement_name(self, name: str) -> bool:
        return self._lookup_sql_proof(self.sql_statement_stack, name)

    def _lookup_sql_proof(self, stack: list[dict[str, bool]], name: str) -> bool:
        for index in range(len(stack) - 1, -1, -1):
            scope = stack[index]
            if name in scope:
                # A function can run after a later module/global assignment.
                if (
                    index == 0
                    and len(stack) > 1
                    and name in self.rebound_global_sql_names
                ):
                    return False
                return scope[name]
        return False

    def _set_sql_table(self, name: str, is_table: bool) -> None:
        self.sql_table_stack[-1][name] = bool(is_table)

    def _is_sql_table(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return self._lookup_sql_proof(self.sql_table_stack, node.id)
        if not isinstance(node, ast.Call):
            return False
        name = _qualified_name_from_expr(node.func)
        if not name:
            return False
        resolved = self.untrusted_sources.resolved_import(
            self._current_function(), name
        )
        return bool(
            resolved
            and resolved.startswith("sqlalchemy.")
            and resolved.rsplit(".", 1)[-1] == "Table"
        )

    def _invalidate_sql_binding(self, name: str) -> None:
        self._set_sql_statement(name, False)
        self._set_sql_table(name, False)

    def _is_static_query_expr(self, node: ast.AST) -> bool:
        if _is_static_string_expr(node):
            return True
        if isinstance(node, ast.Name):
            return self._is_static_string_name(node.id)
        # sqlalchemy.text("... :id") over a constant is a static statement;
        # values travel as bound parameters.
        if (
            isinstance(node, ast.Call)
            and self.sqlalchemy_text.is_text_call(node)
            and len(node.args) == 1
            and not node.keywords
        ):
            return self._is_static_query_expr(node.args[0])
        return False

    def _is_sql_construct(self, node: ast.AST) -> bool:
        """``select(User).where(...)``, ``sa.delete(Item)``, ``notes.insert().values(...)``,
        or a name holding one: bound-parameter SQL.

        Clause arguments must not be string-built or tainted. Methods that
        bind values may accept tainted strings, including formatted strings.
        """
        if isinstance(node, ast.Name):
            return self._is_sql_statement_name(node.id)
        chain: list[ast.Call] = []
        current = node
        while isinstance(current, ast.Call):
            chain.append(current)
            func = current.func
            if not (
                isinstance(func, ast.Attribute) and isinstance(func.value, ast.Call)
            ):
                break
            current = func.value
        if not chain:
            return False
        if any(
            not isinstance(call.func, ast.Attribute)
            or call.func.attr not in SQL_BUILDER_METHODS
            for call in chain[:-1]
        ):
            return False
        for call in chain:
            binds_values = isinstance(call.func, ast.Attribute) and call.func.attr in {
                "values",
                "ordered_values",
                "filter_by",
                "limit",
                "offset",
            }
            for arg in [*call.args, *(keyword.value for keyword in call.keywords)]:
                if not binds_values and (
                    _is_interpolated_string(arg) or self.is_tainted(arg)
                ):
                    return False
        func = chain[-1].func
        if isinstance(func, ast.Name):
            return self._is_imported_sql_construct(func)
        if not isinstance(func, ast.Attribute):
            return False
        if isinstance(func.value, ast.Name) and self._is_sql_statement_name(
            func.value.id
        ):
            return func.attr in SQL_BUILDER_METHODS
        if func.attr in SQL_CONSTRUCT_NAMES:
            if self._is_imported_sql_construct(func):
                return True
        return func.attr in TABLE_STATEMENT_METHODS and self._is_sql_table(func.value)

    def _is_imported_sql_construct(self, func: ast.AST) -> bool:
        name = _qualified_name_from_expr(func)
        if not name:
            return False
        resolved = self.untrusted_sources.resolved_import(
            self._current_function(), name
        )
        return bool(
            resolved
            and resolved.split(".", 1)[0] in SQL_CONSTRUCT_MODULES
            and resolved.rsplit(".", 1)[-1] in SQL_CONSTRUCT_NAMES
        )

    def _text_call_root(self, node: ast.AST) -> ast.Call | None:
        """The ``sqlalchemy.text()`` call at the root of ``text(q).bindparams(...)``."""
        current = node
        while (
            isinstance(current, ast.Call)
            and isinstance(current.func, ast.Attribute)
            and isinstance(current.func.value, ast.Call)
        ):
            if current.func.attr not in {
                "bindparams",
                "params",
                "columns",
                "execution_options",
            }:
                return None
            current = current.func.value
        if isinstance(current, ast.Call) and self.sqlalchemy_text.is_text_call(current):
            return current
        return None

    def _is_sql_statement(self, node: ast.AST) -> bool:
        """A statement that needs no report where it is executed.

        Either a bound-parameter construct, or a ``text()`` statement whose SQL
        is constant or already reported on the ``text()`` call itself.
        """
        if self._is_sql_construct(node):
            return True
        text_call = self._text_call_root(node)
        if text_call is None or not text_call.args:
            return False
        sql = text_call.args[0]
        return (
            self._is_static_query_expr(sql)
            or _is_interpolated_string(sql)
            or self.is_tainted(sql)
        )

    def is_tainted(self, node):
        # Untrusted process input also reaches SQL text: sys.argv, sys.stdin,
        # os.environ / os.getenv (the same sources the hook policy accepts).
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            base = node
            while isinstance(base, (ast.Attribute, ast.Subscript)):
                if _qualified_name_from_expr(base) in _PROCESS_INPUT_ATTRS:
                    return True
                base = base.value
        if isinstance(node, ast.Call):
            name = _qualified_name_from_call(node)
            if name in _PROCESS_INPUT_CALLS:
                return True
        return super().is_tainted(node)

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
            self._invalidate_sql_binding(alias.asname or alias.name.split(".", 1)[0])
        self.sqlalchemy_text.record_import(node)
        for alias in node.names:
            top_level = alias.name.split(".")[0]
            if top_level in DB_MODULES or alias.name in DB_MODULES:
                self.db_names.add(alias.asname or alias.name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            if alias.name != "*":
                self._invalidate_sql_binding(alias.asname or alias.name)
        self.sqlalchemy_text.record_import(node)
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
        if any(hint in lower for hint in DB_RECEIVER_HINTS):
            return True

        return False

    def _is_chained_db_receiver(self, node: ast.Call) -> bool:
        """``<db call>().execute(...)``: the receiver is itself a call result."""
        if not isinstance(node.func, ast.Attribute):
            return False
        inner = node.func.value
        if isinstance(inner, ast.Await):
            inner = inner.value
        if not isinstance(inner, ast.Call):
            return False
        if self._is_db_reference(inner):
            return True
        callee = (_callee_name(inner) or "").lower()
        if callee in DB_CHAIN_METHODS:
            return True
        if any(hint in callee for hint in DB_RECEIVER_HINTS):
            return True
        return self._is_likely_db_receiver(inner)

    def _source_evidence(self, node, query_expr, sink):
        return self.untrusted_sources.evidence(
            self._current_function(),
            query_expr,
            sink=sink,
            missing_guard="parameterized SQL binding",
            evidence_kind="python_sql_taint",
        )

    def _sqli_finding(self, node, severity, message, query_expr, sink, evidence=None):
        finding = {
            "rule_id": self.RULE_ID_SQLI,
            "severity": severity,
            "message": message,
            "file": str(self.file_path),
            "line": node.lineno,
            "col": node.col_offset,
            "symbol": self._current_symbol(),
        }
        if evidence is None:
            evidence = self._source_evidence(node, query_expr, sink)
        if evidence is not None:
            finding["metadata"] = {"security_evidence": evidence}
        self.findings.append(finding)

    def _check_chained_execute(self, node: ast.Call) -> None:
        """``sqlite3.connect(...).execute(q)`` and friends.

        Stricter than the named-receiver check: the query must carry data
        from a real untrusted source (entry-point parameter, ``request.*``,
        ``input()``, ``sys.argv``, environment), so a constant-built query or
        a plain helper parameter is never reported here.
        """
        query_expr = get_query_expression(node, names=("statement", "sql", "query"))
        if query_expr is None or not self.is_tainted(query_expr):
            return
        if self._is_sql_statement(query_expr):
            return  # bound parameters, or reported on the text() call itself
        if isinstance(query_expr, ast.Call) and self.sqlalchemy_text.is_text_call(
            query_expr
        ):
            return  # reported on the text() call itself
        sink = f"SQL text passed to .{node.func.attr}()"
        evidence = self._source_evidence(node, query_expr, sink)
        if evidence is None:
            return
        self._sqli_finding(
            node,
            self.SEVERITY_CRITICAL,
            "Possible SQL injection: untrusted input reaches a query executed "
            "on a chained connection/cursor call.",
            query_expr,
            sink,
            evidence,
        )

    def _taint_params(self, fn):
        super()._taint_params(fn)
        # A parameter shadows a module-level statement of the same name.
        for name in self.env_stack[-1]:
            self._invalidate_sql_binding(name)

    def _record_passthrough_function(self, node):
        param_names = {a.arg for a in node.args.args}
        for statement in node.body:
            if isinstance(statement, ast.Return) and statement.value is not None:
                if _is_passthrough_return(statement.value, param_names):
                    self.passthrough_functions.add(_func_name(node))
                    break

    def visit_FunctionDef(self, node):
        self._invalidate_sql_binding(node.name)
        self.sqlalchemy_text.record_name_binding(node.name)
        self.sqlalchemy_text.enter_function(node)
        try:
            self._record_passthrough_function(node)
            super().visit_FunctionDef(node)
        finally:
            self.sqlalchemy_text.leave_scope()

    def visit_AsyncFunctionDef(self, node):
        self._invalidate_sql_binding(node.name)
        self.sqlalchemy_text.record_name_binding(node.name)
        self.sqlalchemy_text.enter_function(node)
        try:
            self._record_passthrough_function(node)
            super().visit_AsyncFunctionDef(node)
        finally:
            self.sqlalchemy_text.leave_scope()

    def visit_ClassDef(self, node):
        self._invalidate_sql_binding(node.name)
        self.sqlalchemy_text.record_name_binding(node.name)
        self.sqlalchemy_text.enter_class(node)
        try:
            super().visit_ClassDef(node)
        finally:
            self.sqlalchemy_text.leave_scope()

    def visit_Name(self, node: ast.Name):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.sqlalchemy_text.record_name_binding(node.id)
            self._invalidate_sql_binding(node.id)
        self.generic_visit(node)

    @staticmethod
    def _sql_binding_root(node: ast.AST) -> str | None:
        while isinstance(node, (ast.Attribute, ast.Subscript)):
            node = node.value
        return node.id if isinstance(node, ast.Name) else None

    def visit_Attribute(self, node: ast.Attribute):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            root = self._sql_binding_root(node)
            if root is not None:
                self._invalidate_sql_binding(root)
        self.generic_visit(node)

    visit_Subscript = visit_Attribute

    def visit_Lambda(self, node: ast.Lambda):
        self.sqlalchemy_text.enter_lambda(node)
        try:
            self.generic_visit(node)
        finally:
            self.sqlalchemy_text.leave_scope()

    def _visit_scoped_comprehension(self, node):
        first, *remaining = node.generators
        self.visit(first.iter)
        self.sqlalchemy_text.enter_comprehension(node)
        try:
            self.visit(first.target)
            for condition in first.ifs:
                self.visit(condition)
            for generator in remaining:
                self.visit(generator.iter)
                self.visit(generator.target)
                for condition in generator.ifs:
                    self.visit(condition)
            if isinstance(node, ast.DictComp):
                self.visit(node.key)
                self.visit(node.value)
            else:
                self.visit(node.elt)
        finally:
            self.sqlalchemy_text.leave_scope()

    def visit_ListComp(self, node: ast.ListComp):
        self._visit_scoped_comprehension(node)

    def visit_SetComp(self, node: ast.SetComp):
        self._visit_scoped_comprehension(node)

    def visit_DictComp(self, node: ast.DictComp):
        self._visit_scoped_comprehension(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp):
        self._visit_scoped_comprehension(node)

    def _invalidate_branch_sql_bindings(self, nodes) -> None:
        for root in nodes:
            for child in ast.walk(root):
                if isinstance(child, ast.Name) and isinstance(
                    child.ctx, (ast.Store, ast.Del)
                ):
                    self._invalidate_sql_binding(child.id)
                elif isinstance(child, (ast.Attribute, ast.Subscript)) and isinstance(
                    child.ctx, (ast.Store, ast.Del)
                ):
                    root_name = self._sql_binding_root(child)
                    if root_name is not None:
                        self._invalidate_sql_binding(root_name)
                elif isinstance(
                    child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    self._invalidate_sql_binding(child.name)
                elif isinstance(child, ast.ExceptHandler) and child.name:
                    self._invalidate_sql_binding(child.name)

    def visit_If(self, node):
        self.visit(node.test)
        statements = [scope.copy() for scope in self.sql_statement_stack]
        tables = [scope.copy() for scope in self.sql_table_stack]
        for branch in (node.body, node.orelse):
            self.sql_statement_stack = [scope.copy() for scope in statements]
            self.sql_table_stack = [scope.copy() for scope in tables]
            for child in branch:
                self.visit(child)
        self._invalidate_branch_sql_bindings([*node.body, *node.orelse])

    def visit_For(self, node):
        statements = [scope.copy() for scope in self.sql_statement_stack]
        tables = [scope.copy() for scope in self.sql_table_stack]
        self._invalidate_branch_sql_bindings(node.body)
        if isinstance(node, ast.While):
            self.visit(node.test)
        else:
            self.visit(node.iter)
            self.visit(node.target)
        for child in node.body:
            self.visit(child)
        self.sql_statement_stack = statements
        self.sql_table_stack = tables
        self._invalidate_branch_sql_bindings([node])
        for child in node.orelse:
            self.visit(child)
        self._invalidate_branch_sql_bindings([node])

    visit_AsyncFor = visit_For
    visit_While = visit_For

    def visit_Try(self, node):
        statements = [scope.copy() for scope in self.sql_statement_stack]
        tables = [scope.copy() for scope in self.sql_table_stack]
        for child in node.body:
            self.visit(child)
        # The else branch is reached only after the entire try body succeeds.
        for child in node.orelse:
            self.visit(child)
        for handler in node.handlers:
            self.sql_statement_stack = [scope.copy() for scope in statements]
            self.sql_table_stack = [scope.copy() for scope in tables]
            self._invalidate_branch_sql_bindings(node.body)
            if handler.name:
                self._invalidate_sql_binding(handler.name)
            self.visit(handler)
        self.sql_statement_stack = statements
        self.sql_table_stack = tables
        self._invalidate_branch_sql_bindings([*node.body, *node.orelse, *node.handlers])
        for child in node.finalbody:
            self.visit(child)
        self._invalidate_branch_sql_bindings([node])

    visit_TryStar = visit_Try

    def visit_Assign(self, node):
        self._track_db_receiver_aliases(node.targets, node.value)
        is_static = self._is_static_query_expr(node.value)
        is_statement = self._is_sql_statement(node.value)
        is_table = self._is_sql_table(node.value)
        super().visit_Assign(node)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._set_static_string(target.id, is_static)
                self._set_sql_statement(target.id, is_statement)
                self._set_sql_table(target.id, is_table)

    def visit_AnnAssign(self, node):
        self._track_db_receiver_aliases([node.target], node.value)
        is_static = bool(node.value and self._is_static_query_expr(node.value))
        is_statement = bool(node.value and self._is_sql_statement(node.value))
        is_table = bool(node.value and self._is_sql_table(node.value))
        super().visit_AnnAssign(node)
        if node.value and isinstance(node.target, ast.Name):
            self._set_static_string(
                node.target.id,
                is_static,
            )
            self._set_sql_statement(
                node.target.id,
                is_statement,
            )
            self._set_sql_table(node.target.id, is_table)

    def visit_AugAssign(self, node):
        if isinstance(node.target, ast.Name):
            target_name = node.target.id
            remains_static = (
                isinstance(node.op, ast.Add)
                and self._is_static_string_name(target_name)
                and self._is_static_query_expr(node.value)
            )
            self._set_static_string(target_name, remains_static)
            self._set_sql_statement(target_name, False)
            self._set(
                target_name, self._get(target_name) or self.is_tainted(node.value)
            )
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

            if query_expr is not None and not self._is_sql_statement(query_expr):
                sink = f"SQL text passed to .{node.func.attr}()"
                if _is_interpolated_string(query_expr) or self.is_tainted(query_expr):
                    self._sqli_finding(
                        node,
                        self.SEVERITY_CRITICAL,
                        "Possible SQL injection: tainted or string-built query.",
                        query_expr,
                        sink,
                    )
                else:
                    is_literal = self._is_static_query_expr(query_expr)
                    if not is_literal and not is_parameterized_query(node, query_expr):
                        self._sqli_finding(
                            node,
                            self.SEVERITY_HIGH,
                            "Likely unparameterized SQL execution.",
                            query_expr,
                            sink,
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
                self._sqli_finding(
                    node,
                    self.SEVERITY_CRITICAL,
                    "Possible SQL injection in read_sql.",
                    query_expr,
                    "SQL text passed to read_sql()",
                )
            self.generic_visit(node)
            return

        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in SQL_EXECUTE_METHODS
            and self._is_chained_db_receiver(node)
        ):
            self._check_chained_execute(node)
            self.generic_visit(node)
            return

        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            if not self._is_likely_db_receiver(node):
                self.generic_visit(node)
                return

            statement_expression = get_query_expression(
                node, names=("statement", "sql", "query")
            )
            if statement_expression is not None and not self._is_sql_statement(
                statement_expression
            ):
                if _is_interpolated_string(statement_expression) or self.is_tainted(
                    statement_expression
                ):
                    self._sqli_finding(
                        node,
                        self.SEVERITY_CRITICAL,
                        "Possible SQL injection: tainted statement passed to execute().",
                        statement_expression,
                        "SQL statement passed to .execute()",
                    )

            self.generic_visit(node)
            return

        if self.sqlalchemy_text.is_text_call(node):
            for argument in node.args:
                if _is_interpolated_string(argument) or self.is_tainted(argument):
                    self._sqli_finding(
                        node,
                        self.SEVERITY_CRITICAL,
                        "Possible SQL injection: tainted string used in sqlalchemy.text().",
                        argument,
                        "SQL text passed to sqlalchemy.text()",
                    )
                    break

        self.generic_visit(node)


def scan(tree, file_path, findings):
    try:
        checker = _SQLFlowChecker(tree, file_path, findings)
        checker.visit(tree)
    except Exception as e:
        print(f"SQL flow analysis failed for {file_path}: {e}", file=sys.stderr)
