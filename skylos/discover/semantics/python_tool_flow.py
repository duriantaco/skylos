from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any

from skylos.discover.integration import ToolDef

_MAX_RESOLVE_DEPTH = 6
_MAX_FIXPOINT_ROUNDS = 12

SANITIZER_CALLS = frozenset({"int", "float", "bool", "len"})
_TOOL_ATTRS = frozenset(
    {"tool_calls", "function_call", "arguments", "tool_use", "input"}
)
_CODE_SINKS = frozenset({"eval", "exec", "compile"})
_COMMAND_SINKS = frozenset(
    {
        "subprocess.run",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.check_output",
        "subprocess.check_call",
        "os.system",
        "os.popen",
        "os.execvp",
        "os.execve",
        "shutil.rmtree",
    }
)
_SINK_KEYWORDS = frozenset(
    {"args", "cmd", "command", "source", "path", "code", "expression"}
)
_SQL_METHODS = frozenset(
    {"execute", "executemany", "executescript", "raw", "execute_sql"}
)
_SQL_KEYWORDS = frozenset({"sql", "query", "statement", "operation"})
_DB_MODULES = (
    "sqlite3",
    "psycopg2",
    "psycopg",
    "pymysql",
    "MySQLdb",
    "mysql.connector",
    "sqlalchemy",
    "sqlmodel",
    "asyncpg",
    "aiosqlite",
    "aiomysql",
    "aiopg",
    "duckdb",
    "pyodbc",
    "oracledb",
    "cx_Oracle",
    "django.db",
    "snowflake.connector",
    "clickhouse_driver",
    "peewee",
    "databases",
)
_SQL_RECEIVER_HINTS = (
    "cursor",
    "conn",
    "connection",
    "db",
    "database",
    "session",
    "engine",
    "sql",
)
_SCHEMA_VALUE_KEYS = frozenset(
    {"type", "enum", "$ref", "anyOf", "oneOf", "allOf", "const"}
)
_SCHEMA_CALL_SUFFIXES = ("model_json_schema", "schema", "json_schema")
_MUTATING_METHODS = frozenset(
    {"append", "extend", "insert", "update", "setdefault", "pop", "clear", "remove"}
)


@dataclass
class _SinkHit:
    params: frozenset[str]
    kind: str
    name: str
    line: int

    def label(self) -> str:
        if self.kind == "sql":
            return f"SQL {self.name} (L{self.line})"
        return f"{self.name} (L{self.line})"

    def tool_label(self) -> str:
        if self.kind == "sql":
            return f"SQL {self.name} of tool argument (L{self.line})"
        return self.label()


@dataclass
class _FunctionSummary:
    node: ast.FunctionDef | ast.AsyncFunctionDef
    positional: list[str]
    keyword_only: list[str]
    vararg: str
    kwarg: str
    hits: list[_SinkHit] = field(default_factory=list)
    dangerous_calls: list[str] = field(default_factory=list)

    @property
    def params(self) -> list[str]:
        names = list(self.positional) + list(self.keyword_only)
        if self.vararg:
            names.append(self.vararg)
        if self.kwarg:
            names.append(self.kwarg)
        return names


@dataclass
class _ToolDecl:
    kind: str
    name: str
    line: int
    typed: bool = False


def dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        if base:
            return f"{base}.{node.attr}"
    return ""


def import_map(tree: ast.AST) -> dict[str, str]:
    result: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    result[alias.asname] = alias.name
                else:
                    head = alias.name.split(".", 1)[0]
                    result[head] = head
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for alias in node.names:
                if alias.name != "*":
                    result[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return result


def scope_nodes(statements: list[ast.stmt]):
    for statement in statements:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield from _walk_local(statement)


def _walk_local(node: ast.AST):
    yield node
    for child in ast.iter_child_nodes(node):
        if isinstance(
            child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        yield from _walk_local(child)


def assigned_names(statements: list[ast.stmt]) -> set[str]:
    names: set[str] = set()
    for node in scope_nodes(statements):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
    return names


def _target_names(node: ast.AST) -> list[str]:
    return [
        child.id
        for child in ast.walk(node)
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)
    ]


def _bindings(statements: list[ast.stmt]) -> list[tuple[list[str], ast.AST]]:
    result: list[tuple[list[str], ast.AST]] = []
    for node in scope_nodes(statements):
        if isinstance(node, ast.Assign):
            names: list[str] = []
            for target in node.targets:
                names.extend(_target_names(target))
            result.append((names, node.value))
        elif isinstance(node, (ast.AugAssign, ast.NamedExpr)) or (
            isinstance(node, ast.AnnAssign) and node.value is not None
        ):
            result.append((_target_names(node.target), node.value))
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            result.append((_target_names(node.target), node.iter))
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            result.append((_target_names(node.optional_vars), node.context_expr))
    return result


def module_sanitizers(tree: ast.AST) -> frozenset[str]:
    shadowed: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            shadowed.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            shadowed.add(node.id)
        elif isinstance(node, ast.arg):
            shadowed.add(node.arg)
        elif isinstance(node, ast.alias):
            shadowed.add(node.asname or node.name.split(".", 1)[0])
    return SANITIZER_CALLS - shadowed


def expr_tags(
    node: ast.AST | None,
    env: dict[str, frozenset[str]],
    seeds: dict[int, frozenset[str]],
    sanitizers: frozenset[str] = SANITIZER_CALLS,
) -> frozenset[str]:
    if node is None:
        return frozenset()
    seeded = seeds.get(id(node))
    if seeded is not None:
        return seeded
    if isinstance(node, ast.Name):
        return env.get(node.id, frozenset())
    if isinstance(node, ast.Constant):
        return frozenset()
    if isinstance(node, ast.Call):
        if dotted_name(node.func) in sanitizers:
            return frozenset()
        tags = set(expr_tags(node.func, env, seeds, sanitizers))
        for arg in node.args:
            tags.update(expr_tags(arg, env, seeds, sanitizers))
        for keyword in node.keywords:
            tags.update(expr_tags(keyword.value, env, seeds, sanitizers))
        return frozenset(tags)
    if isinstance(node, ast.Attribute):
        tags = expr_tags(node.value, env, seeds, sanitizers)
        if node.attr in _TOOL_ATTRS and "llm" in tags:
            return tags | {"tool"}
        return tags
    if isinstance(node, ast.Subscript):
        return expr_tags(node.value, env, seeds, sanitizers)
    if isinstance(node, ast.Lambda):
        return frozenset()
    tags: set[str] = set()
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.expr, ast.comprehension, ast.keyword)):
            tags.update(expr_tags(child, env, seeds, sanitizers))
    return frozenset(tags)


def propagate(
    statements: list[ast.stmt],
    seeds_by_name: dict[str, frozenset[str]],
    seeds_by_node: dict[int, frozenset[str]] | None = None,
    sanitizers: frozenset[str] = SANITIZER_CALLS,
) -> dict[str, frozenset[str]]:
    env = dict(seeds_by_name)
    node_seeds = seeds_by_node or {}
    bindings = _bindings(statements)
    for _round in range(_MAX_FIXPOINT_ROUNDS):
        changed = False
        for names, value in bindings:
            tags = expr_tags(value, env, node_seeds, sanitizers)
            if not tags:
                continue
            for name in names:
                current = env.get(name, frozenset())
                merged = current | tags
                if merged != current:
                    env[name] = merged
                    changed = True
        if not changed:
            break
    return env


def function_params(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[list[str], list[str], str, str]:
    positional = [arg.arg for arg in node.args.posonlyargs]
    positional.extend(arg.arg for arg in node.args.args)
    keyword_only = [arg.arg for arg in node.args.kwonlyargs]
    vararg = ""
    kwarg = ""
    if node.args.vararg:
        vararg = node.args.vararg.arg
    if node.args.kwarg:
        kwarg = node.args.kwarg.arg
    return positional, keyword_only, vararg, kwarg


class _ModuleContext:
    def __init__(self, tree: ast.Module, filepath: str):
        self.tree = tree
        self.filepath = filepath
        self.body = list(getattr(tree, "body", []))
        self.imports = import_map(tree)
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        for statement in self.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[statement.name] = statement
        self.functions_by_line: dict[int, ast.FunctionDef | ast.AsyncFunctionDef] = {
            node.lineno: node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.sanitizers = module_sanitizers(tree)
        self.has_db_import = any(
            target == module or target.startswith(module + ".")
            for target in self.imports.values()
            for module in _DB_MODULES
        )
        self._summaries: dict[int, _FunctionSummary] = {}
        self._single_values: dict[int, dict[str, ast.AST]] = {}
        self._assignments: dict[
            int, dict[str, tuple[list[ast.AST], list[ast.AST]]]
        ] = {}
        self._local_names: dict[int, set[str]] = {}

    def single_values(self, statements: list[ast.stmt]) -> dict[str, ast.AST]:
        cached = self._single_values.get(id(statements))
        if cached is not None:
            return cached
        counts: dict[str, int] = {}
        values: dict[str, ast.AST] = {}
        for names, value in _bindings(statements):
            for name in names:
                counts[name] = counts.get(name, 0) + 1
        for node in scope_nodes(statements):
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
            ):
                values[node.targets[0].id] = node.value
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in _MUTATING_METHODS
                and isinstance(node.func.value, ast.Name)
            ):
                name = node.func.value.id
                counts[name] = counts.get(name, 0) + 1
        result = {
            name: value for name, value in values.items() if counts.get(name) == 1
        }
        self._single_values[id(statements)] = result
        return result

    def summary(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> _FunctionSummary:
        cached = self._summaries.get(id(node))
        if cached is not None:
            return cached
        positional, keyword_only, vararg, kwarg = function_params(node)
        summary = _FunctionSummary(node, positional, keyword_only, vararg, kwarg)
        seeds = {name: frozenset({name}) for name in summary.params}
        env = propagate(node.body, seeds, None, self.sanitizers)
        local_names = assigned_names(node.body) | set(summary.params)
        for child in scope_nodes(node.body):
            if not isinstance(child, ast.Call):
                continue
            hit = self._sink_hit(child, env, local_names)
            if hit is None:
                continue
            if hit.kind != "sql":
                summary.dangerous_calls.append(hit.label())
            if hit.params:
                summary.hits.append(hit)
        self._summaries[id(node)] = summary
        return summary

    def _canonical(self, node: ast.AST, local_names: set[str]) -> str:
        dotted = dotted_name(node)
        if not dotted:
            return ""
        head, _, tail = dotted.partition(".")
        if head in local_names:
            return ""
        if head in self.imports:
            base = self.imports[head]
            if tail:
                return f"{base}.{tail}"
            return base
        if not tail and head in _CODE_SINKS and head not in self.functions:
            return head
        return ""

    def _sink_hit(
        self,
        call: ast.Call,
        env: dict[str, frozenset[str]],
        local_names: set[str],
    ) -> _SinkHit | None:
        canonical = self._canonical(call.func, local_names)
        if canonical in _CODE_SINKS:
            operands: list[ast.AST] = list(call.args[:1])
            operands.extend(
                keyword.value
                for keyword in call.keywords
                if keyword.arg in _SINK_KEYWORDS
            )
            return _SinkHit(
                self._operand_params(operands, env), "code", canonical, call.lineno
            )
        if canonical in _COMMAND_SINKS:
            operands = list(call.args)
            operands.extend(
                keyword.value
                for keyword in call.keywords
                if keyword.arg in _SINK_KEYWORDS
            )
            return _SinkHit(
                self._operand_params(operands, env),
                "command",
                canonical,
                call.lineno,
            )
        if (
            isinstance(call.func, ast.Attribute)
            and call.func.attr in _SQL_METHODS
            and self._is_sql_receiver(call.func.value)
        ):
            operands = list(call.args[:1])
            operands.extend(
                keyword.value
                for keyword in call.keywords
                if keyword.arg in _SQL_KEYWORDS
            )
            return _SinkHit(
                self._operand_params(operands, env), "sql", call.func.attr, call.lineno
            )
        return None

    def _operand_params(
        self, operands: list[ast.AST], env: dict[str, frozenset[str]]
    ) -> frozenset[str]:
        params: set[str] = set()
        for operand in operands:
            params.update(expr_tags(operand, env, {}, self.sanitizers))
        return frozenset(params)

    def _is_sql_receiver(self, receiver: ast.AST) -> bool:
        if self.has_db_import:
            return True
        base = receiver
        while isinstance(base, (ast.Attribute, ast.Call, ast.Subscript)):
            if isinstance(base, ast.Attribute):
                lowered = base.attr.lower()
                if any(hint in lowered for hint in _SQL_RECEIVER_HINTS):
                    return True
                base = base.value
            elif isinstance(base, ast.Call):
                base = base.func
            else:
                base = base.value
        if isinstance(base, ast.Name):
            lowered = base.id.lower()
            return any(hint in lowered for hint in _SQL_RECEIVER_HINTS)
        return False

    def assigned_values(
        self, statements: list[ast.stmt], name: str
    ) -> tuple[list[ast.AST], list[ast.AST]]:
        index = self._assignment_index(statements)
        values, additions = index.get(name, ([], []))
        return list(values), list(additions)

    def local_names(self, statements: list[ast.stmt]) -> set[str]:
        cached = self._local_names.get(id(statements))
        if cached is None:
            cached = assigned_names(statements)
            self._local_names[id(statements)] = cached
        return cached

    def _assignment_index(
        self, statements: list[ast.stmt]
    ) -> dict[str, tuple[list[ast.AST], list[ast.AST]]]:
        cached = self._assignments.get(id(statements))
        if cached is not None:
            return cached
        index: dict[str, tuple[list[ast.AST], list[ast.AST]]] = {}

        def entry(name: str) -> tuple[list[ast.AST], list[ast.AST]]:
            return index.setdefault(name, ([], []))

        for node in scope_nodes(statements):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        entry(target.id)[0].append(node.value)
            elif (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.value is not None
            ):
                entry(node.target.id)[0].append(node.value)
            elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
                entry(node.target.id)[1].append(node.value)
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.args
            ):
                name = node.func.value.id
                if node.func.attr in ("append", "insert"):
                    item = ast.List(elts=[node.args[-1]], ctx=ast.Load())
                    entry(name)[1].append(item)
                elif node.func.attr == "extend":
                    entry(name)[1].append(node.args[0])
        self._assignments[id(statements)] = index
        return index

    def string_constant(
        self, node: ast.AST, statements: list[ast.stmt], depth: int = 0
    ) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if not isinstance(node, ast.Name) or depth > _MAX_RESOLVE_DEPTH:
            return None
        values, additions = self.assigned_values(statements, node.id)
        if not values and statements is not self.body:
            values, additions = self.assigned_values(self.body, node.id)
            statements = self.body
        if len(values) != 1 or additions:
            return None
        return self.string_constant(values[0], statements, depth + 1)

    def dict_constant(
        self, node: ast.AST, statements: list[ast.stmt], depth: int = 0
    ) -> ast.Dict | None:
        if isinstance(node, ast.Dict):
            return node
        if not isinstance(node, ast.Name) or depth > _MAX_RESOLVE_DEPTH:
            return None
        values, additions = self.assigned_values(statements, node.id)
        if not values and statements is not self.body:
            values, additions = self.assigned_values(self.body, node.id)
            statements = self.body
        if len(values) != 1 or additions:
            return None
        return self.dict_constant(values[0], statements, depth + 1)


def _dict_entries(node: ast.Dict) -> dict[str, ast.AST]:
    entries: dict[str, ast.AST] = {}
    for key, value in zip(node.keys, node.values):
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            entries[key.value] = value
    return entries


class _ToolResolver:
    def __init__(
        self, ctx: _ModuleContext, scope: list[ast.stmt], scope_params: set[str]
    ):
        self.ctx = ctx
        self.scope = scope
        self._params: dict[int, set[str]] = {id(scope): set(scope_params)}

    def resolve(self, node: ast.AST) -> list[_ToolDecl] | None:
        return self._resolve_list(node, self.scope, 0, set())

    def _resolve_list(
        self,
        node: ast.AST,
        statements: list[ast.stmt],
        depth: int,
        seen: set[tuple[int, str]],
    ) -> list[_ToolDecl] | None:
        if depth > _MAX_RESOLVE_DEPTH:
            return None
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            result: list[_ToolDecl] = []
            for element in node.elts:
                if isinstance(element, ast.Starred):
                    nested = self._resolve_list(
                        element.value, statements, depth + 1, seen
                    )
                    if nested:
                        result.extend(nested)
                    continue
                result.extend(self._resolve_element(element, statements, depth + 1))
            return result
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._resolve_list(node.left, statements, depth + 1, seen)
            right = self._resolve_list(node.right, statements, depth + 1, seen)
            if left is None and right is None:
                return None
            return list(left or []) + list(right or [])
        if isinstance(node, ast.Name):
            return self._resolve_name(node.id, statements, depth, seen)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            helper = self.ctx.functions.get(node.func.id)
            if helper is None:
                return None
            positional, keyword_only, vararg, kwarg = function_params(helper)
            helper_params = set(positional) | set(keyword_only) | {vararg, kwarg}
            self._params[id(helper.body)] = helper_params
            result = []
            found = False
            for child in scope_nodes(helper.body):
                if isinstance(child, ast.Return) and child.value is not None:
                    nested = self._resolve_list(
                        child.value, helper.body, depth + 1, seen
                    )
                    if nested is not None:
                        found = True
                        result.extend(nested)
            if not found:
                return None
            return result
        return None

    def _resolve_name(
        self,
        name: str,
        statements: list[ast.stmt],
        depth: int,
        seen: set[tuple[int, str]],
    ) -> list[_ToolDecl] | None:
        key = (id(statements), name)
        if key in seen:
            return None
        if name in self._params.get(id(statements), set()):
            return None
        seen = seen | {key}
        values, additions = self.ctx.assigned_values(statements, name)
        if not values and statements is not self.ctx.body:
            statements = self.ctx.body
            values, additions = self.ctx.assigned_values(statements, name)
        if not values:
            return None
        result: list[_ToolDecl] = []
        found = False
        for value in values + additions:
            nested = self._resolve_list(value, statements, depth + 1, seen)
            if nested is not None:
                found = True
                result.extend(nested)
        if not found:
            return None
        return result

    def _resolve_element(
        self, node: ast.AST, statements: list[ast.stmt], depth: int
    ) -> list[_ToolDecl]:
        if (
            isinstance(node, ast.Name)
            and node.id in self.ctx.functions
            and node.id not in self.ctx.local_names(statements)
        ):
            function = self.ctx.functions[node.id]
            return [_ToolDecl("function", node.id, function.lineno)]
        schema = self.ctx.dict_constant(node, statements)
        if schema is None:
            return []
        return self._schema_tools(schema, statements)

    def _schema_tools(
        self, node: ast.Dict, statements: list[ast.stmt]
    ) -> list[_ToolDecl]:
        entries = _dict_entries(node)
        declarations = entries.get("function_declarations")
        if isinstance(declarations, (ast.List, ast.Tuple)):
            result: list[_ToolDecl] = []
            for item in declarations.elts:
                nested = self.ctx.dict_constant(item, statements)
                if nested is not None:
                    result.extend(self._schema_tools(nested, statements))
            return result
        function_value = entries.get("function")
        if function_value is not None:
            nested = self.ctx.dict_constant(function_value, statements)
            if nested is None:
                return []
            entries = _dict_entries(nested)
        name_node = entries.get("name")
        if name_node is None:
            return []
        name = self.ctx.string_constant(name_node, statements)
        if not name:
            return []
        params = entries.get("parameters")
        if params is None:
            params = entries.get("input_schema")
        return [_ToolDecl("schema", name, node.lineno, self._typed(params, statements))]

    def _typed(self, node: ast.AST | None, statements: list[ast.stmt]) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Call):
            return dotted_name(node.func).endswith(_SCHEMA_CALL_SUFFIXES)
        schema = self.ctx.dict_constant(node, statements)
        if schema is None:
            return False
        properties = _dict_entries(schema).get("properties")
        if properties is None:
            return False
        properties = self.ctx.dict_constant(properties, statements)
        if properties is None:
            return False
        for value in properties.values:
            prop = self.ctx.dict_constant(value, statements)
            if prop is None:
                return False
            if not set(_dict_entries(prop)) & _SCHEMA_VALUE_KEYS:
                return False
        return True


@dataclass
class _Dispatch:
    tool_key: str
    function: str


class _OutputFlow:
    def __init__(
        self,
        ctx: _ModuleContext,
        call_node: ast.Call,
        scope: list[ast.stmt],
    ):
        self.ctx = ctx
        self.call_node = call_node
        self.scope = scope
        self.local_names = assigned_names(scope)
        self.seeds = {id(call_node): frozenset({"llm"})}
        self.env = propagate(scope, {}, self.seeds, ctx.sanitizers)
        self.dispatch_tables = self._dispatch_tables()
        self.aliases = self._aliases()

    def _function_table(self, node: ast.AST) -> dict[str, str] | None:
        if isinstance(node, ast.Dict):
            table: dict[str, str] = {}
            for key, value in zip(node.keys, node.values):
                if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
                    return None
                if not (isinstance(value, ast.Name) and value.id in self.ctx.functions):
                    return None
                table[key.value] = value.id
            return table or None
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "dict"
            and not node.args
        ):
            table = {}
            for keyword in node.keywords:
                if keyword.arg is None:
                    return None
                if not (
                    isinstance(keyword.value, ast.Name)
                    and keyword.value.id in self.ctx.functions
                ):
                    return None
                table[keyword.arg] = keyword.value.id
            return table or None
        return None

    def _dispatch_tables(self) -> dict[str, dict[str, str]]:
        tables: dict[str, dict[str, str]] = {}
        for name, value in self.ctx.single_values(self.ctx.body).items():
            table = self._function_table(value)
            if table:
                tables[name] = table
        if self.scope is not self.ctx.body:
            for name in self.local_names:
                tables.pop(name, None)
            for name, value in self.ctx.single_values(self.scope).items():
                table = self._function_table(value)
                if table:
                    tables[name] = table
        return tables

    def _table_lookup(self, node: ast.AST) -> list[_Dispatch] | None:
        table_name = ""
        key_node: ast.AST | None = None
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
            table_name = node.value.id
            key_node = node.slice
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Name)
            and node.args
        ):
            table_name = node.func.value.id
            key_node = node.args[0]
        table = self.dispatch_tables.get(table_name)
        if table is None or key_node is None:
            return None
        if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
            function = table.get(key_node.value)
            if function is None:
                return []
            return [_Dispatch(key_node.value, function)]
        return [_Dispatch(key, function) for key, function in table.items()]

    def _aliases(self) -> dict[str, list[_Dispatch]]:
        aliases: dict[str, list[_Dispatch]] = {}
        for node in scope_nodes(self.scope):
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if not isinstance(target, ast.Name):
                continue
            resolved = self._direct(node.value)
            if resolved:
                aliases.setdefault(target.id, []).extend(resolved)
        return aliases

    def _direct(self, node: ast.AST) -> list[_Dispatch]:
        if isinstance(node, ast.Name):
            if node.id in self.local_names:
                return []
            if node.id in self.ctx.functions:
                return [_Dispatch(node.id, node.id)]
            return []
        return self._table_lookup(node) or []

    def callee(self, node: ast.AST) -> list[_Dispatch]:
        if isinstance(node, ast.Name) and node.id in self.aliases:
            return list(self.aliases[node.id])
        return self._direct(node)

    def tags(self, node: ast.AST) -> frozenset[str]:
        return expr_tags(node, self.env, self.seeds, self.ctx.sanitizers)

    def controlled_params(
        self, call: ast.Call, summary: _FunctionSummary
    ) -> dict[str, frozenset[str]]:
        controlled: dict[str, frozenset[str]] = {}

        def mark(name: str, tags: frozenset[str]) -> None:
            controlled[name] = controlled.get(name, frozenset()) | tags

        for index, arg in enumerate(call.args):
            if isinstance(arg, ast.Starred):
                tags = self.tags(arg.value)
                if "llm" in tags:
                    for name in summary.positional[index:]:
                        mark(name, tags)
                    if summary.vararg:
                        mark(summary.vararg, tags)
                break
            tags = self.tags(arg)
            if "llm" not in tags:
                continue
            if index < len(summary.positional):
                mark(summary.positional[index], tags)
            elif summary.vararg:
                mark(summary.vararg, tags)
        for keyword in call.keywords:
            tags = self.tags(keyword.value)
            if "llm" not in tags:
                continue
            if keyword.arg is None:
                for name in summary.params:
                    mark(name, tags)
            elif (
                keyword.arg in summary.positional or keyword.arg in summary.keyword_only
            ):
                mark(keyword.arg, tags)
            elif summary.kwarg:
                mark(summary.kwarg, tags)
        return controlled


@dataclass
class _Binding:
    function: str
    controlled: dict[str, frozenset[str]]


def _origin(tags: frozenset[str]) -> str:
    if "tool" in tags:
        return "tool-call arguments"
    return "model output"


def _analyze_output(
    ctx: _ModuleContext, call_node: ast.Call, scope: list[ast.stmt]
) -> tuple[list[str], dict[str, _Binding]]:
    flow = _OutputFlow(ctx, call_node, scope)
    flows: list[str] = []
    bindings: dict[str, _Binding] = {}
    for node in scope_nodes(scope):
        if not isinstance(node, ast.Call) or node is call_node:
            continue
        for dispatch in flow.callee(node.func):
            function = ctx.functions.get(dispatch.function)
            if function is None:
                continue
            summary = ctx.summary(function)
            controlled = flow.controlled_params(node, summary)
            if not controlled:
                continue
            binding = bindings.get(dispatch.tool_key)
            if binding is None:
                binding = _Binding(dispatch.function, {})
                bindings[dispatch.tool_key] = binding
            for name, tags in controlled.items():
                binding.controlled[name] = (
                    binding.controlled.get(name, frozenset()) | tags
                )
            for hit in summary.hits:
                reached = hit.params & set(controlled)
                if not reached:
                    continue
                tags: set[str] = set()
                for name in reached:
                    tags.update(controlled[name])
                label = (
                    f"{_origin(frozenset(tags))} → {dispatch.function}() → "
                    f"{hit.label()}"
                )
                if label not in flows:
                    flows.append(label)
    return flows, bindings


def _function_tool(
    ctx: _ModuleContext,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    existing: ToolDef | None,
) -> ToolDef:
    summary = ctx.summary(function)
    location = f"{ctx.filepath}:{function.lineno}"
    if existing is not None:
        tool = existing
    else:
        args = [arg for arg in function.args.args if arg.arg not in ("self", "cls")]
        typed = bool(args) and all(arg.annotation is not None for arg in args)
        tool = ToolDef(
            name=function.name,
            location=location,
            has_typed_schema=typed,
            dangerous_calls=list(summary.dangerous_calls),
        )
    if not tool.handler_location:
        tool.handler_location = location
    _add_tool_hits(tool, summary, set(summary.params))
    return tool


def _add_tool_hits(
    tool: ToolDef, summary: _FunctionSummary, controlled: set[str]
) -> None:
    for hit in summary.hits:
        if hit.kind != "sql" or not hit.params & controlled:
            continue
        marker = f"(L{hit.line})"
        if any(existing.endswith(marker) for existing in tool.dangerous_calls):
            continue
        tool.dangerous_calls.append(hit.tool_label())


def _schema_tool(
    ctx: _ModuleContext, decl: _ToolDecl, binding: _Binding | None
) -> ToolDef:
    tool = ToolDef(
        name=decl.name,
        location=f"{ctx.filepath}:{decl.line}",
        has_typed_schema=decl.typed,
        kind="schema",
    )
    if binding is None:
        return tool
    function = ctx.functions.get(binding.function)
    if function is None:
        return tool
    summary = ctx.summary(function)
    tool.handler_location = f"{ctx.filepath}:{function.lineno}"
    tool.dangerous_calls = list(summary.dangerous_calls)
    _add_tool_hits(tool, summary, set(binding.controlled))
    return tool


def _tools_kwarg(call_node: ast.Call) -> ast.AST | None:
    for keyword in call_node.keywords:
        if keyword.arg in ("tools", "functions"):
            return keyword.value
    return None


def attach_python_tool_flow(
    tree: ast.AST,
    raw_calls: list[dict[str, Any]],
    integrations: list[Any],
    filepath: str,
    tool_defs: list[ToolDef],
) -> None:
    if not isinstance(tree, ast.Module):
        return
    if not raw_calls and not tool_defs:
        return
    ctx = _ModuleContext(tree, filepath)
    by_location = {tool.location: tool for tool in tool_defs}
    for tool in tool_defs:
        line = int(tool.location.rsplit(":", 1)[-1])
        function = ctx.functions_by_line.get(line)
        if function is not None:
            _function_tool(ctx, function, tool)

    for index, call in enumerate(raw_calls):
        if index >= len(integrations):
            break
        call_node = call.get("ast_node")
        if not isinstance(call_node, ast.Call):
            continue
        integration = integrations[index]
        func_node = call.get("func_node")
        scope = ctx.body
        if isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scope = func_node.body
        flows, bindings = _analyze_output(ctx, call_node, scope)
        integration.output_sink_flows = flows

        tools_value = _tools_kwarg(call_node)
        if tools_value is None:
            continue
        scope_params: set[str] = set()
        if isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            positional, keyword_only, vararg, kwarg = function_params(func_node)
            scope_params = set(positional) | set(keyword_only) | {vararg, kwarg}
        declarations = _ToolResolver(ctx, scope, scope_params).resolve(tools_value)
        if not declarations:
            continue
        tools: list[ToolDef] = []
        seen: set[tuple[str, str]] = set()
        for decl in declarations:
            if (decl.kind, decl.name) in seen:
                continue
            seen.add((decl.kind, decl.name))
            if decl.kind == "function":
                function = ctx.functions[decl.name]
                existing = by_location.get(f"{filepath}:{function.lineno}")
                tools.append(_function_tool(ctx, function, existing))
            else:
                tools.append(_schema_tool(ctx, decl, bindings.get(decl.name)))
        integration.tools = tools
