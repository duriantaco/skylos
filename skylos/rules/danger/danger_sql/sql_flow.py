from __future__ import annotations
import ast
import hashlib
import re
import string
import sys
from collections import Counter
from skylos.rules.danger.builtin_bindings import builtin_references
from skylos.rules.danger.taint import TaintVisitor
from skylos.rules.danger.danger_sql.sqlalchemy_provenance import (
    SQLAlchemyTextProvenance,
)
from skylos.rules.danger.danger_sql.write_only_collections import (
    WriteOnlyReceiver,
    write_only_methods,
)
from skylos.rules.danger.untrusted_sources import UntrustedSourceIndex
from skylos.security.receiver_resolution import ReceiverResolver
from skylos.rules.danger.danger_sql.class_sql_constants import project_class_constants


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
SQL_FETCH_METHODS = frozenset(
    {
        "fetch",
        "fetchrow",
        "fetchval",
        "fetch_all",
        "fetch_one",
        "fetch_val",
        "execute_sql",
    }
)
_POOL_RECEIVER_HINT = "pool"
_FETCH_API_MODULES = ("asyncpg", "databases", "peewee")
_SQL_KEYWORD_RE = re.compile(
    r"\b(?:select|insert|update|delete|from|where|values|join|order\s+by|group\s+by|"
    r"create|drop|alter|truncate|returning|limit)\b",
    re.IGNORECASE,
)


def _constant_text_parts(node: ast.AST) -> list[str]:
    parts = []
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            parts.append(child.value)
    return parts


def _has_sql_keyword(node: ast.AST) -> bool:
    """The literal text of a string-built query reads as SQL, so a URL or
    cache key built the same way on a ``session``-named object is not one."""
    return any(_SQL_KEYWORD_RE.search(part) for part in _constant_text_parts(node))


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
        "join",
        "outerjoin",
        "join_from",
        "outerjoin_from",
        "options",
        "distinct",
        "add_columns",
        "correlate",
        "with_for_update",
        "execution_options",
        "params",
    }
)
STANDARD_LITERAL_CONNECTIONS = frozenset({"sqlite3.connect", "duckdb.connect"})
_LITERAL_CONNECTION = "connection"
_LITERAL_ESCAPED = "escaped"
_UNPROVEN_SQL_QUOTES = frozenset("`[]$")
_LITERAL_OPENERS = frozenset(" \t\r\n(,='")
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


_NUMERIC_CALLS = frozenset({"int", "float", "len", "round", "abs", "bool"})
_TRUSTED_BUILTINS = _NUMERIC_CALLS | {"str"}
_NUMERIC_MODULE_CALLS = frozenset(
    {
        "random.randint",
        "random.randrange",
        "random.getrandbits",
        "math.floor",
        "math.ceil",
        "math.trunc",
        "math.isqrt",
    }
)
_TEXT_SAFE = "safe"
_TEXT_IDENTIFIER = "identifier"
_TEXT_COMPOSED = "composed"
_IDENTIFIER_QUOTERS = frozenset(
    {"psycopg2.extensions.quote_ident", "asyncpg.utils._quote_ident"}
)
_PSYCOPG_SQL_MODULES = frozenset({"psycopg.sql", "psycopg2.sql"})
_PSYCOPG_QUOTED_MEMBERS = frozenset({"Identifier", "Literal", "Placeholder"})


def _concatenated_parts(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return [*_concatenated_parts(node.left), *_concatenated_parts(node.right)]
    return [node]


def _outside_sql_quotes(text: str) -> bool:
    """No single-quoted literal, double-quoted identifier or dollar-quoted
    string is open at the end of ``text``."""
    return (
        text.count("'") % 2 == 0
        and text.count('"') % 2 == 0
        and text.count("$$") % 2 == 0
    )


def _composite_text_kind(parts) -> str | None:
    """Text built from literal pieces and values. Safe values may sit
    anywhere; a quoted identifier only where no quoted literal is open, and
    the whole text must close its own quotes so it can be embedded again."""
    text = ""
    kind = _TEXT_SAFE
    for part, value in parts:
        if part == "text":
            text += value
        elif value == _TEXT_SAFE:
            text += "0"
        elif value == _TEXT_IDENTIFIER and _outside_sql_quotes(text):
            kind = _TEXT_IDENTIFIER
            text += "x"
        else:
            return None
    if kind == _TEXT_IDENTIFIER and not _outside_sql_quotes(text):
        return None
    return kind


def _doubles_double_quotes(node: ast.AST, parameter: str) -> bool:
    """``parameter.replace('"', '""')`` (also on ``str(parameter)``)."""
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "replace"
        and not node.keywords
        and len(node.args) == 2
        and all(_is_string_literal(arg) for arg in node.args)
        and [arg.value for arg in node.args] == ['"', '""']
    ):
        return False
    receiver = node.func.value
    if (
        isinstance(receiver, ast.Call)
        and isinstance(receiver.func, ast.Name)
        and receiver.func.id == "str"
        and len(receiver.args) == 1
        and not receiver.keywords
    ):
        receiver = receiver.args[0]
    return isinstance(receiver, ast.Name) and receiver.id == parameter


def _wraps_in_double_quotes(node: ast.AST, parameter: str) -> bool:
    """``'"{}"'.format(escaped)``, ``'"' + escaped + '"'``, ``f'"{escaped}"'``
    or ``'"%s"' % escaped``."""
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and _is_string_literal(node.func.value)
        and node.func.value.value == '"{}"'
        and len(node.args) == 1
        and not node.keywords
    ):
        return _doubles_double_quotes(node.args[0], parameter)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        parts = _concatenated_parts(node)
        return (
            len(parts) == 3
            and _is_string_literal(parts[0])
            and parts[0].value == '"'
            and _is_string_literal(parts[2])
            and parts[2].value == '"'
            and _doubles_double_quotes(parts[1], parameter)
        )
    if isinstance(node, ast.JoinedStr):
        values = node.values
        return (
            len(values) == 3
            and _is_string_literal(values[0])
            and values[0].value == '"'
            and _is_string_literal(values[2])
            and values[2].value == '"'
            and isinstance(values[1], ast.FormattedValue)
            and values[1].conversion == -1
            and values[1].format_spec is None
            and _doubles_double_quotes(values[1].value, parameter)
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        operand = node.right
        if isinstance(operand, ast.Tuple) and len(operand.elts) == 1:
            operand = operand.elts[0]
        return (
            _is_string_literal(node.left)
            and node.left.value == '"%s"'
            and _doubles_double_quotes(operand, parameter)
        )
    return False


def _identifier_quote_helpers(tree: ast.AST) -> frozenset[str]:
    """Module functions bound once whose only behaviour is returning their
    single argument as a double-quoted identifier with ``"`` doubled."""
    if not isinstance(tree, ast.Module):
        return frozenset()
    counts = Counter()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            counts[node.name] += 1
        elif isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
            counts[node.id] += 1
        elif isinstance(node, ast.arg):
            counts[node.arg] += 1
        elif isinstance(node, ast.alias):
            counts[node.asname or node.name.split(".", 1)[0]] += 1
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                counts[name] += 1
    helpers = set()
    for statement in tree.body:
        if not isinstance(statement, ast.FunctionDef) or statement.decorator_list:
            continue
        if counts[statement.name] != 1:
            continue
        arguments = statement.args
        positional = [*arguments.posonlyargs, *arguments.args]
        if (
            len(positional) != 1
            or arguments.vararg
            or arguments.kwarg
            or arguments.kwonlyargs
        ):
            continue
        body = list(statement.body)
        if body and isinstance(body[0], ast.Expr) and _is_string_literal(body[0].value):
            body = body[1:]
        if (
            len(body) == 1
            and isinstance(body[0], ast.Return)
            and body[0].value is not None
            and _wraps_in_double_quotes(body[0].value, positional[0].arg)
        ):
            helpers.add(statement.name)
    return frozenset(helpers)


def _is_literal_string_sequence(node: ast.AST) -> bool:
    return isinstance(node, (ast.List, ast.Tuple)) and all(
        _is_string_literal(element) for element in node.elts
    )


def _is_string_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


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

    def __init__(self, tree: ast.AST, file_path, findings, project_root=None):
        super().__init__(file_path, findings)
        self.project_root = project_root
        self.tree = tree
        self.untrusted_sources = UntrustedSourceIndex(tree)
        self.receiver_resolver = None
        self.receiver_resolution_error = None
        if isinstance(tree, ast.Module):
            try:
                self.receiver_resolver = ReceiverResolver(tree, file_path)
            except Exception as exc:
                self.receiver_resolution_error = (
                    f"Receiver resolution unavailable ({type(exc).__name__})."
                )
        self.receiver_resolution_cache: dict[ast.Call, dict] = {}
        self.cosmos_provenance = None
        self.passthrough_functions: set[str] = set()
        self.db_names: set[str] = set()
        self.sqlalchemy_text = SQLAlchemyTextProvenance(tree)
        self.static_string_stack: list[dict[str, bool]] = [{}]
        self.sql_statement_stack: list[dict[str, bool]] = [{}]
        self.sql_table_stack: list[dict[str, bool]] = [{}]
        self.sql_text_stack: list[dict[str, bool]] = [{}]
        self.sql_literal_stack: list[dict[str, str | None]] = [{}]
        self.builtin_names = builtin_references(tree, _TRUSTED_BUILTINS)
        self.identifier_quote_helpers = _identifier_quote_helpers(tree)
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
        self.write_only_methods: dict[int, WriteOnlyReceiver] = {}
        self.write_only_receiver_stack: list[WriteOnlyReceiver | None] = [None]
        self._read_module_classes(tree, bindings)
        self._attribute_owners: dict[tuple[int, str], str | None] = {}
        self._class_constants_loaded = False
        self._class_constants = None
        self.method_decorators = builtin_references(tree, {"property", "classmethod"})
        self.sql_source_ast_sha256 = None

    def _read_module_classes(self, tree: ast.AST, bindings) -> None:
        self.method_classes: dict[int, ast.ClassDef] = {}
        self.module_classes: set[str] = set()
        self.module_written_attributes: set[str] = set()
        self.has_sql_sink = False
        if not isinstance(tree, ast.Module):
            return
        counts = Counter()
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                counts[node.name] += 1
            elif isinstance(node, ast.Attribute):
                if isinstance(node.ctx, (ast.Store, ast.Del)):
                    self.module_written_attributes.add(node.attr)
            elif isinstance(node, ast.Call) and _callee_name(
                node
            ) in SQL_EXECUTE_METHODS | {"read_sql", "read_sql_query", "text"}:
                self.has_sql_sink = True
        for statement in tree.body:
            if not isinstance(statement, ast.ClassDef):
                continue
            if counts[statement.name] == 1 and statement.name not in bindings:
                self.module_classes.add(statement.name)
            for member in statement.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.method_classes[id(member)] = statement

    def _project_class_constants(self):
        if not self._class_constants_loaded:
            self._class_constants_loaded = True
            root = self.project_root or getattr(self.receiver_resolver, "root", None)
            self._class_constants = project_class_constants(
                root, self.file_path, self.tree
            )
        return self._class_constants

    def _is_fixed_class_text(self, node: ast.Attribute) -> bool:
        if not self.has_sql_sink or not isinstance(node.value, ast.Name):
            return False
        if node.attr in self.module_written_attributes:
            return False
        owner = self._attribute_owner(node.value.id)
        if owner is None:
            return False
        constants = self._project_class_constants()
        return constants is not None and constants.holds_fixed_text(owner, node.attr)

    def _class_mapping_iteration_names(self, node):
        iterator = node.iter
        if (
            not isinstance(iterator, ast.Call)
            or not isinstance(iterator.func, ast.Attribute)
            or iterator.func.attr not in {"items", "values", "keys"}
            or iterator.args
            or iterator.keywords
        ):
            return []
        mapping = iterator.func.value
        if not isinstance(mapping, ast.Attribute) or not isinstance(
            mapping.value, ast.Name
        ):
            return []
        owner = self._attribute_owner(mapping.value.id)
        constants = self._project_class_constants()
        if (
            owner is None
            or constants is None
            or not constants.holds_fixed_mapping(owner, mapping.attr)
        ):
            return []
        if isinstance(node.target, ast.Name) and iterator.func.attr in {
            "values",
            "keys",
        }:
            return [node.target.id]
        if (
            iterator.func.attr == "items"
            and isinstance(node.target, (ast.Tuple, ast.List))
            and len(node.target.elts) == 2
            and all(isinstance(item, ast.Name) for item in node.target.elts)
        ):
            return [item.id for item in node.target.elts]
        return []

    def _attribute_owner(self, name: str) -> str | None:
        """The class ``name.attribute`` reads from: a method's own first
        parameter, or a module class that nothing in scope shadows."""
        function = self._current_function()
        key = (id(function), name)
        if key not in self._attribute_owners:
            self._attribute_owners[key] = self._find_attribute_owner(function, name)
        return self._attribute_owners[key]

    def _find_attribute_owner(self, function, name: str) -> str | None:
        if function is not None:
            klass = self.method_classes.get(id(function))
            if klass is not None and self._is_method_receiver(function, name):
                return klass.name
            if any(self._binds_name(scope, name) for scope in self._function_stack):
                return None
        if name in self.module_classes and self._import_names_are_stable(name):
            return name
        return None

    @staticmethod
    def _binds_name(function: ast.AST, name: str) -> bool:
        arguments = function.args
        parameters = [
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
            *filter(None, (arguments.vararg, arguments.kwarg)),
        ]
        if any(parameter.arg == name for parameter in parameters):
            return True
        return any(
            isinstance(child, ast.Name)
            and child.id == name
            and isinstance(child.ctx, (ast.Store, ast.Del))
            for child in ast.walk(function)
        )

    def _is_method_receiver(self, function: ast.AST, name: str) -> bool:
        positional = [*function.args.posonlyargs, *function.args.args]
        if not positional or positional[0].arg != name:
            return False
        for decorator in function.decorator_list:
            if id(decorator) in self.method_decorators:
                continue
            provider = self._stable_provider(decorator)
            if provider not in {
                "abc.abstractmethod",
                "typing.final",
                "typing.override",
            }:
                return False
        return not any(
            isinstance(child, ast.Name)
            and child.id == name
            and isinstance(child.ctx, (ast.Store, ast.Del))
            for child in ast.walk(function)
        )

    def _stable_provider(self, func: ast.AST) -> str | None:
        name = _qualified_name_from_expr(func)
        if not name or not self._import_names_are_stable(name):
            return None
        resolved = self.untrusted_sources.resolved_import(
            self._current_function(), name
        )
        if resolved is None or not self._sanitizer_is_unpatched(resolved):
            return None
        return resolved

    def _is_generated_hex_text(self, node: ast.Call) -> bool:
        if self._stable_provider(node.func) == "secrets.token_hex":
            return True
        if (
            not isinstance(node.func, ast.Attribute)
            or node.func.attr != "hexdigest"
            or not isinstance(node.func.value, ast.Call)
            or node.args
            or node.keywords
        ):
            return False
        constructor = node.func.value
        provider = self._stable_provider(constructor.func)
        algorithms = {
            "md5",
            "sha1",
            "sha224",
            "sha256",
            "sha384",
            "sha512",
            "sha3_224",
            "sha3_256",
            "sha3_384",
            "sha3_512",
            "blake2b",
            "blake2s",
        }
        if provider in {f"hashlib.{name}" for name in algorithms}:
            return self._sanitizer_is_unpatched("hashlib.hexdigest")
        if provider != "hashlib.new" or not constructor.args:
            return False
        algorithm = constructor.args[0]
        return (
            isinstance(algorithm, ast.Constant)
            and algorithm.value in algorithms
            and self._sanitizer_is_unpatched("hashlib.hexdigest")
        )

    def _bound_column_expression(self, node: ast.AST) -> bool:
        if (
            not isinstance(node, ast.Call)
            or not isinstance(node.func, ast.Attribute)
            or not isinstance(node.func.value, ast.Attribute)
            or self.is_tainted(node.func.value)
        ):
            return False
        return node.func.attr in {
            "in_",
            "not_in",
            "notin_",
            "like",
            "ilike",
            "not_like",
            "not_ilike",
            "contains",
            "startswith",
            "endswith",
            "is_",
            "is_not",
            "isnot",
            "between",
            "match",
        }

    def _push(self):
        super()._push()
        self.static_string_stack.append({})
        self.sql_statement_stack.append({})
        self.sql_table_stack.append({})
        self.sql_text_stack.append({})
        self.sql_literal_stack.append({})
        self.db_receiver_alias_stack.append(set())

    def _pop(self):
        if len(self.static_string_stack) > 1:
            self.static_string_stack.pop()
        if len(self.sql_statement_stack) > 1:
            self.sql_statement_stack.pop()
        if len(self.sql_table_stack) > 1:
            self.sql_table_stack.pop()
        if len(self.sql_text_stack) > 1:
            self.sql_text_stack.pop()
        if len(self.sql_literal_stack) > 1:
            self.sql_literal_stack.pop()
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
        self.sql_text_stack[-1][name] = False
        self.sql_literal_stack[-1][name] = None

    def _is_sql_safe_name(self, name: str) -> bool:
        """A name proven to hold SQL-safe text in this scope, or a module-level
        one bound once. Enclosing function scopes are not trusted: a closure
        reads the name when it runs, possibly after a rebinding."""
        scope = self.sql_text_stack[-1]
        if name in scope:
            return scope[name]
        if len(self.sql_text_stack) > 1 and name not in self.rebound_global_sql_names:
            return self.sql_text_stack[0].get(name, False)
        return False

    def _is_sql_safe_text(self, node: ast.AST) -> bool:
        """Text that cannot carry data into SQL: string literals, numbers
        (``int()``, ``float()``, ``len()``, ``round()``, ``random.randint()``),
        and strings built only from those. That covers placeholder runs such
        as ``",".join("?" * len(ids))`` or ``", ".join(["%s"] * len(rows))``:
        the values travel as bound parameters and only their count reaches
        the SQL text."""
        return self._sql_text_kind(node) == _TEXT_SAFE

    def _is_safe_query(self, node: ast.AST) -> bool:
        """A query whose text cannot carry data: safe text, text whose only
        values are quoted identifiers outside any quoted literal, or a
        psycopg ``sql.SQL`` composition."""
        return self._sql_text_kind(node) is not None

    def _sql_text_kind(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant):
            if isinstance(node.value, (str, int, float)) or node.value is None:
                return _TEXT_SAFE
            return None
        if isinstance(node, ast.Name):
            if self._is_sql_safe_name(node.id):
                return _TEXT_SAFE
            fact = self._sql_literal_fact_of(node.id)
            if fact in (_TEXT_IDENTIFIER, _TEXT_COMPOSED):
                return fact
            return None
        if isinstance(node, ast.Attribute) and self._is_fixed_class_text(node):
            return _TEXT_SAFE
        if isinstance(node, ast.JoinedStr):
            return self._joined_text_kind(node)
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Add):
                parts = []
                for part in _concatenated_parts(node):
                    if isinstance(part, ast.Constant) and isinstance(part.value, str):
                        parts.append(("text", part.value))
                    else:
                        parts.append(("value", self._sql_text_kind(part)))
                return _composite_text_kind(parts)
            if isinstance(node.op, ast.Mult):
                if self._repeats_literal(node, _is_string_literal):
                    return _TEXT_SAFE
                return None
            if isinstance(node.op, ast.Mod):
                right = node.right
                parts = [right]
                if isinstance(right, ast.Tuple):
                    parts = right.elts
                if self._is_sql_safe_text(node.left) and all(
                    self._is_sql_safe_text(part) for part in parts
                ):
                    return _TEXT_SAFE
            return None
        if not isinstance(node, ast.Call):
            return None
        if self._is_generated_hex_text(node):
            return _TEXT_SAFE
        if self._is_psycopg_composition(node):
            return _TEXT_COMPOSED
        if self._is_identifier_quote_call(node):
            return _TEXT_IDENTIFIER
        if self._is_numeric_call(node):
            return _TEXT_SAFE
        if self._builtin_called(node) == "str":
            if len(node.args) == 1 and not node.keywords:
                kind = self._sql_text_kind(node.args[0])
                if kind in (_TEXT_SAFE, _TEXT_IDENTIFIER):
                    return kind
            return None
        if not isinstance(node.func, ast.Attribute):
            return None
        if node.func.attr == "format":
            return self._format_text_kind(node)
        if node.func.attr == "join" and len(node.args) == 1 and not node.keywords:
            if self._is_sql_safe_text(node.func.value) and self._joins_sql_safe_text(
                node.args[0]
            ):
                return _TEXT_SAFE
        return None

    def _joined_text_kind(self, node: ast.JoinedStr) -> str | None:
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(("text", str(value.value)))
                continue
            if not isinstance(value, ast.FormattedValue):
                return None
            if value.format_spec is not None and not self._is_sql_safe_text(
                value.format_spec
            ):
                return None
            kind = self._sql_text_kind(value.value)
            if kind == _TEXT_IDENTIFIER and (
                value.conversion != -1 or value.format_spec is not None
            ):
                return None
            parts.append(("value", kind))
        return _composite_text_kind(parts)

    def _format_text_kind(self, node: ast.Call) -> str | None:
        """``"...".format(...)`` on a literal template: each field is checked
        where it lands, so a quoted identifier may fill a field outside
        quotes. Other templates need every argument to be safe text."""
        template = node.func.value
        simple_arguments = not any(
            isinstance(argument, ast.Starred) for argument in node.args
        ) and all(keyword.arg is not None for keyword in node.keywords)
        if not (
            simple_arguments
            and isinstance(template, ast.Constant)
            and isinstance(template.value, str)
        ):
            if (
                self._is_sql_safe_text(template)
                and all(self._is_sql_safe_text(arg) for arg in node.args)
                and all(self._is_sql_safe_text(kw.value) for kw in node.keywords)
            ):
                return _TEXT_SAFE
            return None
        try:
            fields = list(string.Formatter().parse(template.value))
        except ValueError:
            return None
        keywords = {keyword.arg: keyword.value for keyword in node.keywords}
        parts = []
        automatic = 0
        for literal, field, spec, conversion in fields:
            parts.append(("text", literal))
            if field is None:
                continue
            value = None
            if field == "":
                position = automatic
                automatic += 1
            elif field.isdigit():
                position = int(field)
            elif field.isidentifier():
                position = None
                value = keywords.get(field)
            else:
                return None
            if position is not None and position < len(node.args):
                value = node.args[position]
            if value is None or (spec and "{" in spec):
                return None
            kind = self._sql_text_kind(value)
            if kind == _TEXT_IDENTIFIER and (spec or conversion):
                return None
            parts.append(("value", kind))
        return _composite_text_kind(parts)

    def _resolved_call_name(self, func: ast.AST) -> str | None:
        name = _qualified_name_from_expr(func)
        if not name:
            return None
        return self.untrusted_sources.resolved_import(self._current_function(), name)

    def _is_numeric_call(self, node: ast.Call) -> bool:
        if self._builtin_called(node) in _NUMERIC_CALLS:
            return True
        return self._resolved_call_name(node.func) in _NUMERIC_MODULE_CALLS

    def _is_identifier_quote_call(self, node: ast.Call) -> bool:
        """A call that returns a double-quoted SQL identifier with every
        embedded ``"`` doubled: psycopg2's ``quote_ident`` or a function in
        this module whose whole body does exactly that."""
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in self.identifier_quote_helpers
            and len(node.args) == 1
            and not node.keywords
            and not isinstance(node.args[0], ast.Starred)
        ):
            return True
        return self._resolved_call_name(node.func) in _IDENTIFIER_QUOTERS

    def _psycopg_sql_member(self, func: ast.AST) -> str | None:
        resolved = self._resolved_call_name(func)
        if not resolved or "." not in resolved:
            return None
        module, member = resolved.rsplit(".", 1)
        if module in _PSYCOPG_SQL_MODULES:
            return member
        return None

    def _is_psycopg_composition(self, node: ast.AST) -> bool:
        """``sql.SQL("... {} ...").format(sql.Identifier(name), ...)``: psycopg
        quotes identifiers and literals itself; only a literal template may
        become ``sql.SQL`` text."""
        if isinstance(node, ast.Name):
            return self._sql_literal_fact_of(node.id) == _TEXT_COMPOSED
        if not isinstance(node, ast.Call):
            return False
        member = self._psycopg_sql_member(node.func)
        if member == "SQL":
            return (
                len(node.args) == 1
                and not node.keywords
                and _is_string_literal(node.args[0])
            )
        if member in _PSYCOPG_QUOTED_MEMBERS:
            return True
        if not isinstance(node.func, ast.Attribute):
            return False
        receiver = node.func.value
        if not self._is_psycopg_composition(receiver):
            return False
        arguments = [*node.args, *(keyword.value for keyword in node.keywords)]
        if node.func.attr == "format":
            return all(keyword.arg is not None for keyword in node.keywords) and all(
                self._is_psycopg_composition(value) for value in arguments
            )
        if node.func.attr == "join" and len(node.args) == 1 and not node.keywords:
            items = node.args[0]
            if isinstance(items, (ast.List, ast.Tuple)):
                return all(self._is_psycopg_composition(item) for item in items.elts)
            if isinstance(items, (ast.ListComp, ast.GeneratorExp)):
                return self._is_psycopg_composition(items.elt)
            return False
        return node.func.attr == "as_string"

    def _builtin_called(self, node: ast.Call) -> str | None:
        func = node.func
        if isinstance(func, ast.Name) and id(func) in self.builtin_names:
            return func.id
        return None

    def _repeats_literal(self, node: ast.BinOp, is_literal) -> bool:
        if is_literal(node.left) and self._is_count(node.right):
            return True
        return is_literal(node.right) and self._is_count(node.left)

    def _is_count(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Constant):
            return isinstance(node.value, int)
        if isinstance(node, ast.Call):
            return self._builtin_called(node) in ("int", "len")
        if isinstance(node, ast.BinOp) and isinstance(
            node.op, (ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Mod)
        ):
            return self._is_count(node.left) and self._is_count(node.right)
        return False

    def _joins_sql_safe_text(self, node: ast.AST) -> bool:
        """An iterable whose items are SQL-safe strings."""
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return all(self._is_sql_safe_text(element) for element in node.elts)
        if (
            isinstance(node, ast.BinOp)
            and isinstance(node.op, ast.Mult)
            and self._repeats_literal(node, _is_literal_string_sequence)
        ):
            return True
        if isinstance(node, (ast.ListComp, ast.GeneratorExp, ast.SetComp)):
            return _is_string_literal(node.elt)
        return self._is_sql_safe_text(node)

    def _sql_literal_fact_of(self, name: str) -> str | None:
        """What ``name`` is known to hold for SQL literals in this scope (or a
        module-level binding made once): a SQLite/DuckDB connection or cursor,
        or text whose single quotes are doubled."""
        scope = self.sql_literal_stack[-1]
        if name in scope:
            return scope[name]
        if (
            len(self.sql_literal_stack) > 1
            and name not in self.rebound_global_sql_names
        ):
            return self.sql_literal_stack[0].get(name)
        return None

    def _is_str_expression(self, node: ast.AST) -> bool:
        """An expression that evaluates to a ``str``: a string literal, an
        f-string, the builtin ``str()``, or ``str.replace`` with literal
        arguments on one of those."""
        if _is_string_literal(node) or isinstance(node, ast.JoinedStr):
            return True
        if not isinstance(node, ast.Call):
            return False
        if self._builtin_called(node) == "str":
            return len(node.args) <= 1 and not node.keywords
        return (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "replace"
            and len(node.args) == 2
            and not node.keywords
            and all(_is_string_literal(arg) for arg in node.args)
            and self._is_str_expression(node.func.value)
        )

    def _sql_literal_fact(self, node: ast.AST) -> str | None:
        """``sqlite3.connect()``/``duckdb.connect()`` (imported, unshadowed) or
        ``.cursor()`` of one is a connection; ``text.replace("'", "''")`` on a
        ``str`` is escaped text. Quoted identifiers and psycopg compositions
        keep their kind so a later query can check where they land."""
        kind = self._sql_text_kind(node)
        if kind in (_TEXT_IDENTIFIER, _TEXT_COMPOSED):
            return kind
        if not isinstance(node, ast.Call):
            return None
        func = node.func
        if isinstance(func, ast.Attribute) and not node.keywords:
            if (
                func.attr == "replace"
                and len(node.args) == 2
                and all(_is_string_literal(arg) for arg in node.args)
                and [arg.value for arg in node.args] == ["'", "''"]
                and self._is_str_expression(func.value)
            ):
                return _LITERAL_ESCAPED
            if (
                func.attr == "cursor"
                and not node.args
                and isinstance(func.value, ast.Name)
                and self._sql_literal_fact_of(func.value.id) == _LITERAL_CONNECTION
            ):
                return _LITERAL_CONNECTION
        name = _qualified_name_from_expr(func)
        if not name:
            return None
        resolved = self.untrusted_sources.resolved_import(
            self._current_function(), name
        )
        if resolved in STANDARD_LITERAL_CONNECTIONS:
            return _LITERAL_CONNECTION
        return None

    def _literal_scan_value(self, value: ast.AST) -> str | None:
        """The text a value contributes to the quote scan, when it is fixed or
        numeric; None when it could be anything."""
        if isinstance(value, ast.Constant) and isinstance(
            value.value, (str, int, float)
        ):
            return str(value.value)
        if (
            isinstance(value, ast.Call)
            and self._builtin_called(value) in _NUMERIC_CALLS
        ):
            return "0"
        return None

    def _escaped_literal_query(self, node: ast.Call, query_expr: ast.AST) -> bool:
        """``conn.execute(f"ATTACH '{path}' AS store")`` on a SQLite or DuckDB
        connection, where ``path`` had its single quotes doubled and sits
        inside a plain single-quoted literal; every other interpolation is a
        fixed string or a number outside any literal or identifier.

        The literal is proven by scanning the text: a single quote opens one
        only after whitespace, ``(``, ``,``, ``=`` or a just-closed literal
        (``''``), so a prefixed literal (``E'``, ``X'``, ``U&'``) never
        qualifies; ``"`` identifiers are tracked; a backtick, bracket or
        ``$`` (backtick/bracket identifiers, list or dollar-quoted text) or a
        comment marker leaves the context unproven and the finding stays.

        SQLite and DuckDB string literals treat a backslash as an ordinary
        character, so doubling every single quote is a complete escape there.
        MySQL (default sql_mode) and PostgreSQL without
        standard_conforming_strings treat a backslash as an escape, so their
        connections never qualify."""
        if not (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and self._sql_literal_fact_of(node.func.value.id) == _LITERAL_CONNECTION
            and isinstance(query_expr, ast.JoinedStr)
        ):
            return False
        quote = None
        previous = " "
        escaped = False
        for value in query_expr.values:
            if isinstance(value, ast.FormattedValue):
                if value.conversion != -1 or value.format_spec is not None:
                    return False
                inner = value.value
                if (
                    quote == "'"
                    and isinstance(inner, ast.Name)
                    and self._sql_literal_fact_of(inner.id) == _LITERAL_ESCAPED
                ):
                    escaped = True
                    continue
                text = self._literal_scan_value(inner)
                if text is None or quote is not None:
                    return False
                if previous in "-/" or text.startswith(("-", "*")):
                    return False
            else:
                text = value.value
            for position, char in enumerate(text):
                if quote is not None:
                    if char == quote:
                        quote = None
                        previous = char
                    continue
                pair = text[position : position + 2]
                if pair in ("--", "/*") or char in _UNPROVEN_SQL_QUOTES:
                    return False
                if char == "'" and previous not in _LITERAL_OPENERS:
                    return False
                if char in "'\"":
                    quote = char
                previous = char
        return escaped and quote is None

    def _is_static_query_expr(self, node: ast.AST) -> bool:
        if _is_static_string_expr(node) or self._is_sql_safe_text(node):
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
                "params",
                "execution_options",
            }
            for arg in [*call.args, *(keyword.value for keyword in call.keywords)]:
                if not binds_values and (
                    _is_interpolated_string(arg)
                    or (self.is_tainted(arg) and not self._bound_column_expression(arg))
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
        if func.attr not in TABLE_STATEMENT_METHODS:
            return False
        receiver = self.write_only_receiver_stack[-1]
        if receiver is not None and receiver.owns(func.value):
            return True
        return self._is_sql_table(func.value)

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

    def _unknown_receiver_resolution(self, node: ast.Call, limitation: str) -> dict:
        return {
            "status": "unknown",
            "qualified_name": None,
            "kind": "unknown",
            "file": str(self.file_path),
            "line": node.lineno,
            "steps": [],
            "limitations": [limitation],
        }

    def _receiver_resolution(self, node: ast.Call) -> dict | None:
        if self.receiver_resolver is None:
            if self.receiver_resolution_error:
                return self._unknown_receiver_resolution(
                    node, self.receiver_resolution_error
                )
            return None
        if node not in self.receiver_resolution_cache:
            try:
                proof = self.receiver_resolver.resolve_call(node)
            except Exception as exc:
                # Receiver proof is additional precision, not a requirement
                # for retaining an otherwise reportable SQL operation.
                proof = self._unknown_receiver_resolution(
                    node,
                    f"Receiver resolution unavailable ({type(exc).__name__}).",
                )
            if not isinstance(proof, dict):
                proof = self._unknown_receiver_resolution(
                    node, "Receiver resolver returned no usable proof."
                )
            self.receiver_resolution_cache[node] = proof
        return self.receiver_resolution_cache[node]

    def _proved_non_database_receiver(self, node: ast.Call) -> bool:
        """Exclude only a resolved implementation whose body proves no DB effect.

        Knowing a local method's name or owner is insufficient: it may delegate
        to a database, inherit unknown behavior or have been replaced. The
        resolver keeps those cases unknown/ambiguous rather than authorizing
        an exclusion.
        """
        proof = self._receiver_resolution(node)
        return bool(
            proof
            and proof.get("status") == "resolved"
            and isinstance(proof.get("effects"), dict)
            and proof["effects"].get("database") == "none"
        )

    def _sqli_finding(self, node, severity, message, query_expr, sink, evidence=None):
        if self.sql_source_ast_sha256 is None:
            self.sql_source_ast_sha256 = hashlib.sha256(
                ast.dump(self.tree).encode()
            ).hexdigest()
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
        metadata = {
            "sql_operand": {
                "line": getattr(query_expr, "lineno", None),
                "col": getattr(query_expr, "col_offset", None),
                "end_line": getattr(query_expr, "end_lineno", None),
                "end_col": getattr(query_expr, "end_col_offset", None),
            },
            "sql_sink": sink,
            "sql_source_ast_sha256": self.sql_source_ast_sha256,
        }
        if evidence is not None:
            metadata["security_evidence"] = evidence
            metadata["source_status"] = "untrusted"
        else:
            metadata["source_status"] = "unresolved"
            metadata["audit_only"] = True
            finding["message"] = (
                "Review SQL execution: the query's origin is unresolved; "
                "attacker control has not been established."
            )
        if isinstance(node, ast.Call):
            receiver = self._receiver_resolution(node)
            if receiver is not None:
                metadata["receiver_resolution"] = receiver
        if metadata:
            finding["metadata"] = metadata
        self.findings.append(finding)

    def _is_fetch_receiver(self, node: ast.Call) -> bool:
        """A database handle for asyncpg/``databases``/peewee query methods:
        a database-like receiver, a connection pool, or ``execute_sql`` in a
        module that imports peewee."""
        if self._is_likely_db_receiver(node) or self._is_chained_db_receiver(node):
            return True
        name = (_receiver_name(node) or "").lower()
        if _POOL_RECEIVER_HINT in name:
            return True
        return node.func.attr == "execute_sql" and self._imports_module("peewee")

    def _imports_module(self, module: str) -> bool:
        tree = self.untrusted_sources.module
        if tree is None:
            return False
        for child in ast.walk(tree):
            if isinstance(child, ast.Import) and any(
                alias.name.split(".", 1)[0] == module for alias in child.names
            ):
                return True
            if (
                isinstance(child, ast.ImportFrom)
                and (child.module or "").split(".", 1)[0] == module
            ):
                return True
        return False

    def _check_fetch_query(self, node: ast.Call) -> None:
        """Tainted SQL text passed to a query method.

        Unlike ``execute``, these method names are also used by HTTP and
        cache clients, and SQL text built only from the module's own values
        (identifiers it quotes, counts, expressions from a constant table) is
        what drivers such as asyncpg do internally. A query is reported only
        when data from a parameter or another untrusted source reaches its
        text; a string-built query must also read as SQL, and a plain value
        counts only in a module that imports asyncpg, ``databases`` or
        peewee."""
        if not self._is_fetch_receiver(node):
            return
        query_expr = get_query_expression(node, names=("query", "sql"))
        if (
            query_expr is None
            or self._is_sql_statement(query_expr)
            or self._is_safe_query(query_expr)
            or self._escaped_literal_query(node, query_expr)
            or not self.is_tainted(query_expr)
        ):
            return
        if _is_interpolated_string(query_expr):
            if not _has_sql_keyword(query_expr):
                return
        elif not any(self._imports_module(module) for module in _FETCH_API_MODULES):
            return
        if isinstance(query_expr, ast.Call) and self.sqlalchemy_text.is_text_call(
            query_expr
        ):
            return
        sink = f"SQL text passed to .{node.func.attr}()"
        self._sqli_finding(
            node,
            self.SEVERITY_CRITICAL,
            "Possible SQL injection: tainted or string-built query.",
            query_expr,
            sink,
        )

    def _check_chained_execute(self, node: ast.Call) -> None:
        """``sqlite3.connect(...).execute(q)`` and friends.

        Stricter than the named-receiver check: the query must carry data
        from a real untrusted source (entry-point parameter, ``request.*``,
        ``input()``, ``sys.argv``, environment), so a constant-built query or
        a plain helper parameter is never reported here.
        """
        query_expr = get_query_expression(node, names=("statement", "sql", "query"))
        if (
            query_expr is None
            or not self.is_tainted(query_expr)
            or self._is_safe_query(query_expr)
        ):
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
        self.write_only_receiver_stack.append(self.write_only_methods.get(id(node)))
        try:
            self._record_passthrough_function(node)
            super().visit_FunctionDef(node)
        finally:
            self.write_only_receiver_stack.pop()
            self.sqlalchemy_text.leave_scope()

    def visit_AsyncFunctionDef(self, node):
        self._invalidate_sql_binding(node.name)
        self.sqlalchemy_text.record_name_binding(node.name)
        self.sqlalchemy_text.enter_function(node)
        self.write_only_receiver_stack.append(self.write_only_methods.get(id(node)))
        try:
            self._record_passthrough_function(node)
            super().visit_AsyncFunctionDef(node)
        finally:
            self.write_only_receiver_stack.pop()
            self.sqlalchemy_text.leave_scope()

    def visit_ClassDef(self, node):
        self._invalidate_sql_binding(node.name)
        self.sqlalchemy_text.record_name_binding(node.name)
        self.sqlalchemy_text.enter_class(node)
        current_function = self._current_function()
        self.write_only_methods.update(
            write_only_methods(
                node,
                lambda name: self.untrusted_sources.resolved_import(
                    current_function, name
                ),
                self.untrusted_sources.module,
            )
        )
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
        self.write_only_receiver_stack.append(None)
        try:
            self.generic_visit(node)
        finally:
            self.write_only_receiver_stack.pop()
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
        texts = [scope.copy() for scope in self.sql_text_stack]
        literals = [scope.copy() for scope in self.sql_literal_stack]
        branch_statements = []
        for branch in (node.body, node.orelse):
            self.sql_statement_stack = [scope.copy() for scope in statements]
            self.sql_table_stack = [scope.copy() for scope in tables]
            self.sql_text_stack = [scope.copy() for scope in texts]
            self.sql_literal_stack = [scope.copy() for scope in literals]
            for child in branch:
                self.visit(child)
            branch_statements.append(
                [scope.copy() for scope in self.sql_statement_stack]
            )
        self._invalidate_branch_sql_bindings([*node.body, *node.orelse])
        for index, scope in enumerate(branch_statements[0]):
            for name, proven in scope.items():
                if proven and branch_statements[1][index].get(name, False):
                    self.sql_statement_stack[index][name] = True

    def visit_For(self, node):
        statements = [scope.copy() for scope in self.sql_statement_stack]
        tables = [scope.copy() for scope in self.sql_table_stack]
        texts = [scope.copy() for scope in self.sql_text_stack]
        literals = [scope.copy() for scope in self.sql_literal_stack]
        self._invalidate_branch_sql_bindings(node.body)
        if isinstance(node, ast.While):
            self.visit(node.test)
        else:
            self.visit(node.iter)
            self.visit(node.target)
            if isinstance(node.target, ast.Name) and self._joins_sql_safe_text(
                node.iter
            ):
                self.sql_text_stack[-1][node.target.id] = True
            for name in self._class_mapping_iteration_names(node):
                self.sql_text_stack[-1][name] = True
        for child in node.body:
            self.visit(child)
        self.sql_statement_stack = statements
        self.sql_table_stack = tables
        self.sql_text_stack = texts
        self.sql_literal_stack = literals
        self._invalidate_branch_sql_bindings([node])
        for child in node.orelse:
            self.visit(child)
        self._invalidate_branch_sql_bindings([node])

    visit_AsyncFor = visit_For
    visit_While = visit_For

    def visit_Try(self, node):
        statements = [scope.copy() for scope in self.sql_statement_stack]
        tables = [scope.copy() for scope in self.sql_table_stack]
        texts = [scope.copy() for scope in self.sql_text_stack]
        literals = [scope.copy() for scope in self.sql_literal_stack]
        for child in node.body:
            self.visit(child)
        # The else branch is reached only after the entire try body succeeds.
        for child in node.orelse:
            self.visit(child)
        for handler in node.handlers:
            self.sql_statement_stack = [scope.copy() for scope in statements]
            self.sql_table_stack = [scope.copy() for scope in tables]
            self.sql_text_stack = [scope.copy() for scope in texts]
            self.sql_literal_stack = [scope.copy() for scope in literals]
            self._invalidate_branch_sql_bindings(node.body)
            if handler.name:
                self._invalidate_sql_binding(handler.name)
            self.visit(handler)
        self.sql_statement_stack = statements
        self.sql_table_stack = tables
        self.sql_text_stack = texts
        self.sql_literal_stack = literals
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
        is_safe_text = self._is_sql_safe_text(node.value)
        literal_fact = self._sql_literal_fact(node.value)
        super().visit_Assign(node)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._set_static_string(target.id, is_static)
                self._set_sql_statement(target.id, is_statement)
                self._set_sql_table(target.id, is_table)
                self.sql_text_stack[-1][target.id] = is_safe_text
                self.sql_literal_stack[-1][target.id] = literal_fact

    def visit_AnnAssign(self, node):
        self._track_db_receiver_aliases([node.target], node.value)
        is_static = bool(node.value and self._is_static_query_expr(node.value))
        is_statement = bool(node.value and self._is_sql_statement(node.value))
        is_table = bool(node.value and self._is_sql_table(node.value))
        is_safe_text = bool(node.value and self._is_sql_safe_text(node.value))
        literal_fact = None
        if node.value is not None:
            literal_fact = self._sql_literal_fact(node.value)
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
            self.sql_text_stack[-1][node.target.id] = is_safe_text
            self.sql_literal_stack[-1][node.target.id] = literal_fact

    def visit_AugAssign(self, node):
        if isinstance(node.target, ast.Name):
            target_name = node.target.id
            remains_static = (
                isinstance(node.op, ast.Add)
                and self._is_static_string_name(target_name)
                and self._is_static_query_expr(node.value)
            )
            self._set_static_string(target_name, remains_static)
            self.sql_text_stack[-1][target_name] = (
                isinstance(node.op, ast.Add)
                and self._is_sql_safe_name(target_name)
                and self._is_sql_safe_text(node.value)
            )
            self._set_sql_statement(target_name, False)
            self._set(
                target_name, self._get(target_name) or self.is_tainted(node.value)
            )
        self.generic_visit(node)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "query_items":
            provider = None
            try:
                if self.cosmos_provenance is None:
                    from .cosmos_provenance import CosmosQueryProvenance

                    root = self.project_root or getattr(
                        self.receiver_resolver, "root", None
                    )
                    self.cosmos_provenance = CosmosQueryProvenance(
                        self.untrusted_sources.module, self.file_path, root
                    )
                provider = self.cosmos_provenance.query_receiver(node)
            except Exception:
                pass
            query = get_query_expression(node)
            if (
                provider is not None
                and query is not None
                and self.is_tainted(query)
                and not self._is_safe_query(query)
                and not self._is_static_query_expr(query)
            ):
                self._sqli_finding(
                    node,
                    self.SEVERITY_CRITICAL,
                    "Possible SQL injection: tainted SQL text passed to Cosmos DB.",
                    query,
                    "SQL text passed to Cosmos ContainerProxy.query_items()",
                )
                self.findings[-1].setdefault("metadata", {})["cosmos_receiver"] = (
                    provider
                )
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in SQL_EXECUTE_METHODS | SQL_FETCH_METHODS
            and self._proved_non_database_receiver(node)
        ):
            self.generic_visit(node)
            return

        qual_name = _qualified_name_from_call(node)

        if isinstance(node.func, ast.Attribute) and node.func.attr in SQL_FETCH_METHODS:
            self._check_fetch_query(node)
            self.generic_visit(node)
            return

        if qual_name and qual_name in self.passthrough_functions:
            pass

        if qual_name and qual_name.endswith(self.DBAPI_SQL_SINK_SUFFIXES):
            if not self._is_likely_db_receiver(node):
                self.generic_visit(node)
                return

            query_expr = get_query_expression(node, names=("sql", "query", "statement"))

            if (
                query_expr is not None
                and not self._is_sql_statement(query_expr)
                and not self._is_safe_query(query_expr)
                and not self._escaped_literal_query(node, query_expr)
            ):
                sink = f"SQL text passed to .{node.func.attr}()"
                if _is_interpolated_string(query_expr) or self.is_tainted(query_expr):
                    self._sqli_finding(
                        node,
                        self.SEVERITY_CRITICAL,
                        "Possible SQL injection: tainted or string-built query.",
                        query_expr,
                        sink,
                    )
                elif node.func.attr != "executescript":
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

            if (
                query_expr is not None
                and not self._is_safe_query(query_expr)
                and (_is_interpolated_string(query_expr) or self.is_tainted(query_expr))
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
            if (
                statement_expression is not None
                and not self._is_sql_statement(statement_expression)
                and not self._is_safe_query(statement_expression)
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
                if self._is_safe_query(argument):
                    continue
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


def scan(tree, file_path, findings, project_root=None):
    try:
        checker = _SQLFlowChecker(tree, file_path, findings, project_root)
        checker.visit(tree)
    except Exception as e:
        print(f"SQL flow analysis failed for {file_path}: {e}", file=sys.stderr)
