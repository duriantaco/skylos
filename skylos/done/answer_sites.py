"""What the code does: places in added non-test code that answer a literal
input with a literal (``if n == 3: return 6``, ``{3: 6}[n]``, ``switch`` and
``match`` cases), that detect the test run, or that rig a comparison so it
always passes. Python is read with ``ast``; JavaScript and TypeScript with the
tree-sitter grammars ``js_inventory`` uses.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from skylos.done.expected_answers import (
    _JS_FUNCTIONS,
    _JS_WRAPPERS,
    _NONLIT,
    _TEST_DIRS,
    _clip,
    _dotted,
    _js_ancestors,
    _js_args,
    _js_callee,
    _js_declarations,
    _js_key,
    _js_named,
    _js_number,
    _js_param_names,
    _js_unwrap,
    _js_value,
    _lit,
    _py_params,
    _py_parse,
    _py_value,
    _show,
)
from skylos.done.inventory import is_pytest_file
from skylos.done.js_inventory import (
    JS_SUFFIXES,
    _parse,
    _string_value,
    _text,
    is_js_test_file,
)

# The name given to a function without one (a callback).
ANONYMOUS = "<anonymous>"

RULE_HARDCODED = "SKY-A115"
RULE_TEST_DETECTION = "SKY-A116"
RULE_RIGGED = "SKY-A117"

_MAX_DISJUNCTS = 16
# A table with more entries than this is data, not a list of test answers.
_MAX_TABLE_ENTRIES = 100
# Directories whose files support the tests rather than ship.
_SUPPORT_DIRS = frozenset(
    {
        "__mocks__",
        "__fixtures__",
        "fixtures",
        "mocks",
        "test-utils",
        "test_utils",
        "testutils",
        "test-helpers",
        "test_helpers",
        "e2e",
        "cypress",
        "playwright",
    }
)
_CONFIG_DIRS = frozenset({"settings", "config", "configs"})
_PY_CONFIG_FILES = frozenset(
    {
        "conftest.py",
        "setup.py",
        "noxfile.py",
        "tasks.py",
        "manage.py",
        "conf.py",
        "config.py",
        "configuration.py",
        "settings.py",
    }
)
_GENERATED_DIRS = frozenset(
    {"generated", "__generated__", "dist", "build", "vendor", "node_modules"}
)
_GENERATED_SUFFIXES = (
    "_pb2.py",
    "_pb2_grpc.py",
    ".min.js",
    ".generated.ts",
    ".generated.js",
    ".gen.ts",
    ".gen.js",
)
_JS_TEST_IMPORTS = re.compile(
    r"""(?:from\s+|require\(\s*)["'](?:vitest|jest|@jest/[\w-]+|mocha|chai|"""
    r"""node:test|@playwright/test|@testing-library/[\w-]+|msw[\w/-]*)["']"""
)


# ---------------------------------------------------------------------------
# What the code does: literal answers to literal inputs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Cond:
    subject: str  # the compared expression as written
    param: str | None  # the parameter compared, when it is one
    index: int | None  # that parameter's position (after self/cls)
    convert: str  # conversion applied before comparing ("" none)
    values: tuple  # literal(s) it is compared with
    counter: bool = False  # a count of calls the function keeps


@dataclass
class Site:
    path: str
    line: int
    function: str  # "" for module-level code
    owner: str  # enclosing class
    conds: tuple[Cond, ...]
    result: tuple
    result_text: str
    verb: str  # "returns", "prints", "sets x to", "answers ... from T"
    condition: str  # as written
    general: bool  # the function also works its answer out some other way
    js: bool = False

    @property
    def key(self) -> tuple:
        return (
            self.function,
            tuple((c.subject, c.values) for c in self.conds),
            self.result,
        )

    @property
    def where(self) -> str:
        if self.function == ANONYMOUS:
            return "an anonymous function"
        return f"{self.function}()" if self.function else "the module"


@dataclass(frozen=True)
class Marker:
    """A finding that needs no test: test detection or a rigged comparison."""

    rule: str
    line: int
    key: tuple
    message: str
    blocking: bool = True
    expects: str | None = None  # advice only if a test expects this text


@dataclass
class Scan:
    sites: list[Site] = field(default_factory=list)
    markers: list[Marker] = field(default_factory=list)
    clean: bool = True


# -- Python ---------------------------------------------------------------------

_PY_CONVERSIONS = frozenset(
    {"str", "repr", "int", "float", "tuple", "list", "sorted", "set", "frozenset"}
)
_PY_OUTPUT = frozenset({"print", "write", "append"})


_PY_NESTED = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


class _PyScope:
    """One function (or the module's own statements), analysed on demand."""

    def __init__(self, node, name, owner, params, source, module_tables, module_names):
        self.node = node
        self.name = name
        self.owner = owner
        self.params = params
        self.source = source
        self._module_tables = module_tables
        self._module_names = module_names
        self._nodes: list | None = None
        self._tables: dict | None = None
        self._counters: set[str] | None = None
        self._general: bool | None = None
        self._tuple_keys: dict | None = None

    def nodes(self) -> list:
        """Nodes of this function, not of functions or classes inside it."""
        if self._nodes is None:
            body = self.node.body if hasattr(self.node, "body") else []
            stack = [
                node
                for node in reversed(body if isinstance(body, list) else [])
                if not isinstance(node, _PY_NESTED)
            ]
            found = []
            while stack:
                node = stack.pop()
                found.append(node)
                for child in reversed(list(ast.iter_child_nodes(node))):
                    if not isinstance(child, _PY_NESTED):
                        stack.append(child)
            self._nodes = found
        return self._nodes

    @property
    def tables(self) -> dict:
        if self._tables is None:
            self._tables = dict(self._module_tables)
            if self.name or self.owner:
                self._tables.update(_py_tables(self.nodes()))
        return self._tables

    @property
    def counters(self) -> set[str]:
        if self._counters is None:
            self._counters = (
                _py_counters(self, self._module_names) if self.name else set()
            )
        return self._counters

    @property
    def general(self) -> bool:
        if self._general is None:
            self._general = _py_general(self)
        return self._general

    def tuple_keys(self) -> dict:
        """Names assigned once, to a tuple (``key = (n, k, tuple(a))``)."""
        if self._tuple_keys is None:
            counts: dict[str, int] = {}
            values: dict[str, ast.Tuple] = {}
            for node in self.nodes():
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            counts[target.id] = counts.get(target.id, 0) + 1
                            if isinstance(node.value, ast.Tuple):
                                values[target.id] = node.value
            self._tuple_keys = {
                name: value for name, value in values.items() if counts.get(name) == 1
            }
        return self._tuple_keys

    def text(self, node) -> str:
        return _clip(ast.get_source_segment(self.source, node) or "?")


def _py_scopes(tree, source, added: set[int] | None, functions: set[str] | None):
    """The module's statements and every function. With ``added``, functions
    the change did not touch are skipped, unless a module-level table did;
    with ``functions``, only those names ("" for the module's statements)."""
    module_tables = _py_tables(tree.body)
    module_names = {
        t.id
        for stmt in tree.body
        if isinstance(stmt, (ast.Assign, ast.AnnAssign))
        for t in (stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target])
        if isinstance(t, ast.Name)
    }
    tables_changed = added is None or any(
        line in added
        for table in module_tables.values()
        for line in range(table.lineno, (table.end_lineno or table.lineno) + 1)
    )
    if functions is None or "" in functions:
        yield _PyScope(tree, "", "", [], source, module_tables, module_names)
    for function, owner in _py_owned_functions(tree):
        if functions is not None and function.name not in functions:
            continue
        if not tables_changed and not any(
            line in added
            for line in range(function.lineno, (function.end_lineno or 0) + 1)
        ):
            continue
        params = _py_params(function)
        decorators = {(_dotted(d) or ("",))[-1] for d in function.decorator_list}
        if owner and params and "staticmethod" not in decorators:
            params = params[1:]
        yield _PyScope(
            function, function.name, owner, params, source, module_tables, module_names
        )


def _py_owned_functions(tree):
    stack = [(tree, "")]
    while stack:
        node, owner = stack.pop()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield child, owner
                stack.append((child, ""))
            elif isinstance(child, ast.ClassDef):
                stack.append((child, child.name))
            else:
                stack.append((child, owner))


def _py_tables(statements) -> dict[str, ast.Dict]:
    tables = {}
    for stmt in statements:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target, value = stmt.targets[0], stmt.value
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            target, value = stmt.target, stmt.value
        else:
            continue
        if isinstance(target, ast.Name) and isinstance(value, ast.Dict):
            if len(value.keys) > _MAX_TABLE_ENTRIES:
                continue
            if value.keys and all(
                k is not None and _lit(_py_value(k)) for k in value.keys
            ):
                tables[target.id] = value
    return tables


def _py_counters(scope: _PyScope, module_names: set[str]) -> set[str]:
    """Module-level names this function updates: call counts and the like."""
    declared = set()
    for node in scope.nodes():
        if isinstance(node, ast.Global):
            declared.update(node.names)
    counters = set()
    for node in scope.nodes():
        targets = []
        if isinstance(node, ast.AugAssign):
            targets = [node.target]
        elif isinstance(node, ast.Assign):
            targets = node.targets
        for target in targets:
            if isinstance(target, ast.Name) and target.id in declared:
                counters.add(target.id)
            elif (
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Name)
                and target.value.id in module_names
                and target.value.id not in scope.params
            ):
                counters.add(target.value.id)
    return counters


def _py_subject(node, scope: _PyScope):
    """(parameter, index, conversion, counter) for an input-like expression."""
    convert = ""
    if isinstance(node, ast.Call):
        name = _dotted(node.func)
        if len(node.args) == 1 and not node.keywords:
            if name and len(name) == 1 and name[0] in _PY_CONVERSIONS:
                convert, node = name[0], node.args[0]
            elif name[-1:] == ("dumps",):
                convert, node = "json_py", node.args[0]
            elif (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "join"
                and isinstance(node.func.value, ast.Constant)
                and isinstance(node.func.value.value, str)
            ):
                convert, node = "join:" + node.func.value.value, node.args[0]
            else:
                return None
        elif (
            not node.args
            and not node.keywords
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"lower", "upper", "strip"}
        ):
            convert, node = node.func.attr, node.func.value
        else:
            return None
    root = node
    while isinstance(root, (ast.Attribute, ast.Subscript)):
        root = root.value
    if not isinstance(root, ast.Name):
        return None
    counter = root.id in scope.counters
    if isinstance(node, ast.Name) and node.id in scope.params and not counter:
        return node.id, scope.params.index(node.id), convert, False
    return None, None, convert, counter


def _py_cond(node, scope: _PyScope) -> Cond | None:
    if not isinstance(node, ast.Compare) or len(node.ops) != 1:
        return None
    op, left, right = node.ops[0], node.left, node.comparators[0]
    if isinstance(op, ast.Eq):
        for subject, literal in ((left, right), (right, left)):
            value = _py_value(literal)
            if not _lit(value):
                continue
            found = _py_subject(subject, scope)
            if found is None:
                return None
            return Cond(
                scope.text(subject), found[0], found[1], found[2], (value,), found[3]
            )
        return None
    if isinstance(op, ast.In) and isinstance(right, (ast.Tuple, ast.List, ast.Set)):
        values = tuple(_py_value(e) for e in right.elts)
        if not values or any(not _lit(v) for v in values):
            return None
        found = _py_subject(left, scope)
        if found is None:
            return None
        return Cond(scope.text(left), found[0], found[1], found[2], values, found[3])
    return None


def _py_disjuncts(node, scope: _PyScope) -> list[list[Cond]]:
    """Literal comparisons a condition needs, one list per way it can hold."""
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
        out: list[list[Cond]] = []
        for value in node.values:
            out += _py_disjuncts(value, scope)
        return out[:_MAX_DISJUNCTS]
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
        combos: list[list[Cond]] = [[]]
        for value in node.values:
            parts = _py_disjuncts(value, scope)
            if parts:
                combos = [c + p for c in combos for p in parts][:_MAX_DISJUNCTS]
        return [c for c in combos if c]
    cond = _py_cond(node, scope)
    return [[cond]] if cond is not None else []


def _py_result(body, scope: _PyScope):
    """(value, as written, verb, line) of the answer a branch gives."""
    for stmt in body:
        if isinstance(stmt, ast.Return):
            if stmt.value is None:
                return None
            return (
                _py_value(stmt.value),
                scope.text(stmt.value),
                "returns",
                stmt.lineno,
            )
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            call = stmt.value
            name = _dotted(call.func)
            if name and name[-1] in _PY_OUTPUT and len(call.args) == 1:
                return (
                    _py_value(call.args[0]),
                    scope.text(call.args[0]),
                    "prints" if name[-1] != "append" else f"adds to {name[0]}",
                    stmt.lineno,
                )
            continue  # logging, bookkeeping
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
        ):
            return (
                _py_value(stmt.value),
                scope.text(stmt.value),
                f"sets {stmt.targets[0].id} to",
                stmt.lineno,
            )
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Tuple)
            and all(isinstance(e, ast.Name) for e in stmt.targets[0].elts)
        ):
            # A, M = 2, 7: the answer is the tuple
            return (
                _py_value(stmt.value),
                scope.text(stmt.value),
                f"sets {scope.text(stmt.targets[0])} to",
                stmt.lineno,
            )
        if isinstance(stmt, ast.Pass):
            continue
        return None
    return None


def _py_answer_like(node, scope: _PyScope, literal_names: set[str]) -> bool:
    """An answer fixed in the source: a literal, a table lookup, or a name
    only ever set to literals."""
    if node is None or _lit(_py_value(node)):
        return True
    if isinstance(node, ast.Name):
        return node.id in literal_names
    if isinstance(node, ast.Subscript):
        return _py_table(node.value, scope) is not None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and _py_table(node.func.value, scope) is not None
    ):
        return all(_py_answer_like(a, scope, literal_names) for a in node.args[1:])
    if isinstance(node, ast.IfExp):
        # A chain of literal comparisons is a table; any other condition
        # (n % 2 == 0) works the answer out.
        return (
            bool(_py_disjuncts(node.test, scope))
            and _py_answer_like(node.body, scope, literal_names)
            and _py_answer_like(node.orelse, scope, literal_names)
        )
    return False


def _py_general(scope: _PyScope) -> bool:
    """Whether the function computes an answer anywhere (not only literals)."""
    assigned: dict[str, bool] = {}
    for node in scope.nodes():
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    literal = _lit(_py_value(node.value))
                    assigned[target.id] = assigned.get(target.id, True) and literal
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)) and isinstance(
            node.target, ast.Name
        ):
            assigned[node.target.id] = False
        elif isinstance(node, (ast.For, ast.comprehension)):
            for target in ast.walk(node.target):
                if isinstance(target, ast.Name):
                    assigned[target.id] = False
    literal_names = {name for name, literal in assigned.items() if literal}
    for node in scope.nodes():
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            return True
        if isinstance(node, ast.Return) and node.value is not None:
            if not _py_answer_like(node.value, scope, literal_names):
                return True
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            name = _dotted(node.value.func)
            if (
                name
                and name[-1] in _PY_OUTPUT
                and any(
                    not _py_answer_like(a, scope, literal_names)
                    for a in node.value.args
                )
            ):
                return True
    return False


def _py_table(node, scope: _PyScope):
    if isinstance(node, ast.Dict):
        if len(node.keys) > _MAX_TABLE_ENTRIES:
            return None
        if node.keys and all(k is not None and _lit(_py_value(k)) for k in node.keys):
            return "", node
        return None
    if isinstance(node, ast.Name) and node.id in scope.tables:
        return node.id, scope.tables[node.id]
    return None


def _py_sites(scope: _PyScope, path: str, added: set[int] | None) -> list[Site]:
    sites: list[Site] = []

    def new(*lines: int) -> bool:
        return added is None or any(line in added for line in lines)

    def add(conds, result, line, condition):
        value, text, verb, result_line = result
        if not _lit(value) or not new(line, result_line):
            return
        sites.append(
            Site(
                path,
                line,
                scope.name,
                scope.owner,
                tuple(conds),
                value,
                text,
                verb,
                condition,
                scope.general,
            )
        )

    for node in scope.nodes():
        if isinstance(node, ast.If):
            result = _py_result(node.body, scope)
            if result is None:
                continue
            for conds in _py_disjuncts(node.test, scope):
                add(conds, result, node.test.lineno, scope.text(node.test))
        elif isinstance(node, ast.IfExp):
            value = _py_value(node.body)
            result = (value, scope.text(node.body), "returns", node.body.lineno)
            for conds in _py_disjuncts(node.test, scope):
                add(conds, result, node.test.lineno, scope.text(node.test))
        elif _MATCH is not None and isinstance(node, _MATCH):
            found = _py_subject(node.subject, scope)
            if found is None:
                continue
            for case in node.cases:
                values = _py_pattern(case.pattern)
                result = _py_result(case.body, scope)
                if not values or case.guard is not None or result is None:
                    continue
                cond = Cond(
                    scope.text(node.subject),
                    found[0],
                    found[1],
                    found[2],
                    values,
                    found[3],
                )
                add(
                    [cond],
                    result,
                    case.pattern.lineno,
                    f"{cond.subject} matches {scope.text(case.pattern)}",
                )
        else:
            lookup = _py_lookup(node, scope)
            if lookup is None:
                continue
            name, table, subject_node = lookup
            subjects = (
                subject_node.elts
                if isinstance(subject_node, ast.Tuple)
                else [subject_node]
            )
            found = [_py_subject(s, scope) for s in subjects]
            if any(f is None for f in found):
                continue
            for key_node, value_node in zip(table.keys, table.values):
                key = _py_value(key_node)
                if len(found) > 1:
                    if key[0] != "l" or len(key[1]) != len(found):
                        continue
                    keys = key[1]
                else:
                    keys = (key,)
                conds = [
                    Cond(scope.text(s), f[0], f[1], f[2], (k,), f[3])
                    for s, f, k in zip(subjects, found, keys)
                ]
                condition = " and ".join(
                    f"{c.subject} == {_show(c.values[0])}" for c in conds
                )
                if not new(key_node.lineno, value_node.lineno, node.lineno):
                    continue
                add(
                    conds,
                    (
                        _py_value(value_node),
                        scope.text(value_node),
                        f"answers {_clip(scope.text(value_node), 50)} from "
                        f"{name or 'a table'}",
                        key_node.lineno,
                    ),
                    key_node.lineno,
                    condition,
                )
    return sites


_MATCH = getattr(ast, "Match", None)


def _py_pattern(pattern) -> tuple:
    if type(pattern).__name__ == "MatchValue":
        value = _py_value(pattern.value)
        return (value,) if _lit(value) else ()
    if type(pattern).__name__ == "MatchOr":
        values = []
        for item in pattern.patterns:
            found = _py_pattern(item)
            if not found:
                return ()
            values.extend(found)
        return tuple(values)
    if type(pattern).__name__ == "MatchSequence":
        items = []
        for item in pattern.patterns:
            found = _py_pattern(item)
            if len(found) != 1:
                return ()
            items.append(found[0])
        return (("l", tuple(items)),)
    return ()


def _py_lookup(node, scope: _PyScope):
    """(table name, table, subject) for ``TABLE[x]`` and ``TABLE.get(x)``.
    A key built just before (``key = (n, k)``) is looked through."""
    found = None
    if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
        table = _py_table(node.value, scope)
        if table is not None:
            found = table[0], table[1], node.slice
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and node.args
    ):
        table = _py_table(node.func.value, scope)
        if table is not None:
            found = table[0], table[1], node.args[0]
    if found is not None and isinstance(found[2], ast.Name):
        built = scope.tuple_keys().get(found[2].id)
        if built is not None:
            found = found[0], found[1], built
    return found


_PY_COMPARISON_DUNDERS = frozenset({"__lt__", "__le__", "__gt__", "__ge__"})
# Classes meant to equal anything (unittest.mock.ANY and the like).
_WILDCARD_RE = re.compile(
    r"(?:(?:^|_)(?:any|Any|ANY)|(?<=[a-z0-9])Any)(?:thing|Thing|THING)?(?=$|_|[A-Z])"
    r"|[Ww]ildcard|WILDCARD|[Mm]atcher|MATCHER|[Dd]ont_?[Cc]are"
)


def _py_rigged(tree, source, added: set[int] | None) -> list[Marker]:
    """``__eq__`` and friends that cannot fail."""
    markers: list[Marker] = []

    def new(node) -> bool:
        if added is None:
            return True
        lines = {node.lineno}
        lines.update(n.lineno for n in ast.walk(node) if isinstance(n, ast.Return))
        if isinstance(node, ast.Lambda):
            lines.add(node.body.lineno)
        return bool(lines & added)

    def judge(owner: str, name: str, function, line: int) -> None:
        verdict = _py_constant_method(name, function)
        if verdict is None or not new(function):
            return
        text, blocking, expects = verdict
        if blocking and _WILDCARD_RE.search(owner or ""):
            blocking = False
            text += " (its name says it matches anything; check that it never stands in for a real value)"
        where = f"{owner}.{name}" if owner else name
        markers.append(
            Marker(
                RULE_RIGGED,
                line,
                ("rigged", owner, name),
                f"{'' if blocking else '(advice) '}{where} {text}",
                blocking,
                expects,
            )
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    judge(node.name, item.name, item, item.lineno)
                elif (
                    isinstance(item, ast.Assign)
                    and len(item.targets) == 1
                    and isinstance(item.targets[0], ast.Name)
                    and isinstance(item.value, ast.Lambda)
                ):
                    judge(node.name, item.targets[0].id, item.value, item.lineno)
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Lambda):
            for target in node.targets:
                if isinstance(target, ast.Attribute) and target.attr.startswith("__"):
                    owner = ".".join(_dotted(target.value)) or "?"
                    judge(owner, target.attr, node.value, node.lineno)
        elif (
            isinstance(node, ast.Call)
            and _dotted(node.func) == ("setattr",)
            and len(node.args) == 3
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
            and isinstance(node.args[2], ast.Lambda)
        ):
            owner = ".".join(_dotted(node.args[0])) or "?"
            judge(owner, node.args[1].value, node.args[2], node.lineno)
    return markers


def _py_constant_method(name: str, function):
    """(message, blocking, expected text) when a comparison method is rigged."""
    if isinstance(function, ast.Lambda):
        returns = [function.body]
        params = [a.arg for a in function.args.args]
        body_nodes = [function.body]
    else:
        returns = [
            n.value
            for n in _py_function_nodes(function)
            if isinstance(n, ast.Return) and n.value is not None
        ]
        params = [a.arg for a in function.args.args]
        body_nodes = function.body
    if not returns:
        return None
    constants = [_py_value(r) for r in returns]
    constant = constants[0] if all(c == constants[0] for c in constants) else _NONLIT
    if any(
        isinstance(r, ast.Name) and r.id == "NotImplemented" for r in returns
    ) or any(_dotted(r) == ("NotImplemented",) for r in returns):
        return None
    other = params[1] if len(params) > 1 else None
    uses_other = other is not None and any(
        isinstance(n, ast.Name) and n.id == other
        for stmt in body_nodes
        for n in ast.walk(stmt)
    )
    uses_self = bool(params) and any(
        isinstance(n, ast.Name) and n.id == params[0]
        for stmt in body_nodes
        for n in ast.walk(stmt)
    )
    if name == "__eq__":
        if constant == ("b", True):
            return (
                "always returns True: any comparison with it passes, so tests "
                "that compare values cannot fail",
                True,
                None,
            )
        if other is not None and not uses_other and constant != ("b", False):
            return (
                f"never looks at the value it is compared with ({other}): "
                "comparisons with it cannot fail the way they should",
                True,
                None,
            )
        return None
    if name == "__ne__" and constant == ("b", False):
        return (
            "always returns False: everything compares equal to it, so tests "
            "that compare values cannot fail",
            True,
            None,
        )
    if name == "__contains__" and constant == ("b", True):
        return (
            "always returns True: every `in` check passes, so tests that look "
            "for a value cannot fail",
            True,
            None,
        )
    if name in _PY_COMPARISON_DUNDERS and constant[0] == "b":
        return (
            f"always returns {constant[1]}: fine for a sentinel that "
            "sorts first or last, otherwise ordering checks cannot fail",
            False,
            None,
        )
    if name == "__hash__" and constant[0] == "n" and not uses_self:
        return (
            f"returns the constant {constant[1]}: every instance hashes "
            "alike; check that equality is not rigged with it",
            False,
            None,
        )
    if name in {"__str__", "__repr__"} and constant[0] == "s" and not uses_self:
        return (
            f"returns the constant {_show(constant)}, the text a test "
            "expects: a fixed string form passes the test without the value "
            "being right",
            False,
            constant[1],
        )
    return None


def _py_function_nodes(function):
    stack = list(function.body)
    while stack:
        node = stack.pop()
        yield node
        for child in ast.iter_child_nodes(node):
            if not isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
            ):
                stack.append(child)


_RUNNER_STRINGS = ("pytest", "py.test", "unittest")
# Variables pytest sets while it runs (PYTEST_ADDOPTS and the like are
# settings a tool that starts pytest may read).
_PYTEST_RUN_ENV = frozenset(
    {
        "PYTEST_CURRENT_TEST",
        "PYTEST_VERSION",
        "PYTEST_XDIST_WORKER",
        "PYTEST_XDIST_WORKER_COUNT",
        "PYTEST_XDIST_TESTRUNUID",
    }
)
_STACK_CALLS = frozenset(
    {
        ("inspect", "stack"),
        ("inspect", "currentframe"),
        ("inspect", "getouterframes"),
        ("sys", "_getframe"),
        ("traceback", "extract_stack"),
        ("traceback", "format_stack"),
    }
)


def _py_env_key(node) -> str | None:
    """The variable name of an ``os.environ``/``os.getenv`` read."""
    if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
        if _dotted(node.value)[-1:] == ("environ",) and isinstance(
            node.slice, ast.Constant
        ):
            value = node.slice.value
            return value if isinstance(value, str) else None
    if (
        isinstance(node, ast.Call)
        and node.args
        and isinstance(node.args[0], ast.Constant)
    ):
        name = _dotted(node.func)
        if name[-2:] == ("environ", "get") or name[-1:] == ("getenv",):
            value = node.args[0].value
            return value if isinstance(value, str) else None
    return None


def _py_markers(tree, source, added: set[int] | None) -> list[Marker]:
    """Production code that asks whether a test runner runs it."""
    markers: list[Marker] = []
    seen_lines: set[int] = set()
    for node, function in _py_marker_scopes(tree):
        line = getattr(node, "lineno", None)
        if line is None or (added is not None and line not in added):
            continue
        if function.startswith("pytest_"):
            continue  # a pytest hook: test infrastructure
        found = _py_marker(node)
        if found is None or line in seen_lines:
            continue
        seen_lines.add(line)
        detail, message, blocking = found
        markers.append(
            Marker(
                RULE_TEST_DETECTION,
                line,
                ("detect", function, detail),
                message,
                blocking,
            )
        )
    return markers


def _py_marker_scopes(tree):
    """(node, enclosing function name) for every expression node."""
    stack = [(tree, "")]
    while stack:
        node, function = stack.pop()
        for child in ast.iter_child_nodes(node):
            name = (
                child.name
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                else function
            )
            yield child, function
            stack.append((child, name))


def _py_marker(node):
    """(detail, message, blocking) for one node that detects the test run."""
    key = _py_env_key(node)
    if key in _PYTEST_RUN_ENV:
        return (
            key,
            f"reads the {key} environment variable, which only pytest sets: code "
            "that behaves differently under the test runner can pass tests it "
            "would fail in use",
            True,
        )
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        left, right = node.left, node.comparators[0]
        op = node.ops[0]
        if isinstance(op, (ast.In, ast.NotIn)) and isinstance(left, ast.Constant):
            value = left.value if isinstance(left.value, str) else ""
            target = _dotted(right)
            if target[-1:] == ("environ",) and value in _PYTEST_RUN_ENV:
                return (
                    value,
                    f"checks for the {value} environment variable, which only "
                    "pytest sets: code that behaves differently under the test "
                    "runner can pass tests it would fail in use",
                    True,
                )
            if target[-1:] == ("modules",) and value in {
                "pytest",
                "_pytest",
                "unittest",
            }:
                return (
                    f"modules:{value}",
                    f'checks whether {value} is loaded ("{value}" in sys.modules): '
                    "code that behaves differently under the test runner can pass "
                    "tests it would fail in use",
                    True,
                )
        if isinstance(op, (ast.Eq, ast.NotEq)):
            for env_side, other in ((left, right), (right, left)):
                env = _py_env_key(env_side)
                if (
                    env is not None
                    and isinstance(other, ast.Constant)
                    and isinstance(other.value, str)
                    and other.value.lower() in {"test", "testing"}
                ):
                    return (
                        f"env:{env}",
                        f'(advice) compares {env} with "{other.value}": code that '
                        "takes another path in tests leaves the real path untested",
                        False,
                    )
    if (
        isinstance(node, ast.Call)
        and _dotted(node.func)[-2:] == ("modules", "get")
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value in {"pytest", "_pytest", "unittest"}
    ):
        value = node.args[0].value
        return (
            f"modules:{value}",
            f"checks whether {value} is loaded (sys.modules.get({value!r})): code "
            "that behaves differently under the test runner can pass tests it "
            "would fail in use",
            True,
        )
    if (
        isinstance(node, ast.Attribute)
        and node.attr == "_called_from_test"
        and isinstance(node.ctx, ast.Load)
    ) or (
        isinstance(node, ast.Call)
        and _dotted(node.func) in {("hasattr",), ("getattr",)}
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
        and node.args[1].value == "_called_from_test"
    ):
        return (
            "_called_from_test",
            "checks sys._called_from_test, a flag only a test setup sets: code "
            "that behaves differently under the test runner can pass tests it "
            "would fail in use",
            True,
        )
    if isinstance(node, (ast.Compare, ast.Call, ast.BoolOp)):
        names = {_dotted(n) for n in ast.walk(node) if isinstance(n, ast.Attribute)}
        strings = [
            n.value
            for n in ast.walk(node)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
        ]
        if ("sys", "argv") in names and any(
            runner in s for s in strings for runner in _RUNNER_STRINGS
        ):
            return (
                "argv",
                "looks for the test runner in sys.argv: code that behaves "
                "differently under the test runner can pass tests it would fail "
                "in use",
                True,
            )
        calls = {
            _dotted(n.func)[-2:] for n in ast.walk(node) if isinstance(n, ast.Call)
        }
        if calls & _STACK_CALLS and any("test" in s.lower() for s in strings):
            return (
                "stack",
                "inspects the call stack for a test: code that behaves "
                "differently when a test calls it can pass tests it would fail in "
                "use",
                True,
            )
    return None


# -- JavaScript/TypeScript --------------------------------------------------------

# Variables a runner sets while it runs tests (not settings a tool passes on).
_JS_RUNNER_ENV = frozenset(
    {
        "JEST_WORKER_ID",
        "VITEST",
        "VITEST_WORKER_ID",
        "VITEST_POOL_ID",
        "NODE_TEST_CONTEXT",
        "TEST_WORKER_INDEX",
        "TEST_PARALLEL_INDEX",
    }
)
_JS_RUNNER_GLOBALS = frozenset(
    {
        "jest",
        "vi",
        "vitest",
        "mocha",
        "jasmine",
        "__vitest_worker__",
        "__vitest_environment__",
    }
)
# Also runner globals, but common enough as ordinary names that only
# ``globalThis.describe`` (not ``typeof describe``) counts.
_JS_TEST_GLOBALS = frozenset(
    {
        "describe",
        "it",
        "test",
        "expect",
        "beforeEach",
        "afterEach",
        "beforeAll",
        "afterAll",
    }
)
_JS_OUTPUT = frozenset({"log", "write", "push", "print"})
_JS_CONVERSIONS = {
    "String": "String",
    "Number": "Number",
    "parseInt": "int",
    "parseFloat": "float",
}


class _JsScope:
    """One function (or the module's own statements), analysed on demand."""

    def __init__(self, node, body, name, owner, params, module_tables, module_names):
        self.node = node
        self.body = body
        self.name = name
        self.owner = owner
        self.params = params
        self._module_tables = module_tables
        self._module_names = module_names
        self._nodes: list | None = None
        self._tables: dict | None = None
        self._counters: set[str] | None = None
        self._general: bool | None = None

    def nodes(self) -> list:
        if self._nodes is None:
            found = []
            stack = [self.body] if self.body is not None else []
            while stack:
                node = stack.pop()
                found.append(node)
                for child in reversed(node.children):
                    if child.type in _JS_FUNCTIONS or child.type == "class_declaration":
                        continue
                    stack.append(child)
            self._nodes = found
        return self._nodes

    @property
    def tables(self) -> dict:
        if self._tables is None:
            self._tables = dict(self._module_tables)
            if self.body is not None and self.body.type == "statement_block":
                if self.body is not self.node:
                    self._tables.update(_js_tables(self.body))
        return self._tables

    @property
    def counters(self) -> set[str]:
        if self._counters is None:
            self._counters = (
                _js_counters(self, self._module_names)
                if self.node.type in _JS_FUNCTIONS
                else set()
            )
        return self._counters

    @property
    def general(self) -> bool:
        if self._general is None:
            self._general = _js_general(self)
        return self._general


def _js_function_name(function) -> tuple[str, str]:
    """(name, owner class) of a function node."""
    if function.type in {
        "function_declaration",
        "generator_function_declaration",
        "method_definition",
        "function_expression",
    }:
        name = function.child_by_field_name("name")
        owner = ""
        if function.type == "method_definition":
            body = function.parent
            holder = body.parent if body is not None else None
            if holder is not None and holder.type in {"class_declaration", "class"}:
                owner = _text(holder.child_by_field_name("name"))
        if name is not None:
            return _text(name), owner
    parent = function.parent
    while parent is not None and parent.type in _JS_WRAPPERS:
        parent = parent.parent
    if parent is not None and parent.type == "variable_declarator":
        return _text(parent.child_by_field_name("name")), ""
    if parent is not None and parent.type == "pair":
        key = _js_key(parent.child_by_field_name("key"))
        return (key[1] if _lit(key) else ""), ""
    if parent is not None and parent.type == "assignment_expression":
        left = parent.child_by_field_name("left")
        return (_js_callee(left) or ""), ""
    return "", ""


def _js_tables(body) -> dict:
    tables = {}
    for name, value in _js_declarations(body).items():
        value = _js_unwrap(value)
        if value is None:
            continue
        if value.type == "object":
            entries = _js_object_entries(value)
            if entries:
                tables[name] = entries
        elif (
            value.type == "new_expression"
            and _text(value.child_by_field_name("constructor")) == "Map"
        ):
            args = _js_args(value)
            entries = _js_map_entries(args[0]) if args else []
            if entries:
                tables[name] = entries
    return tables


def _js_object_entries(node) -> list:
    """(key values, value node, key node) of an object literal table."""
    entries = []
    children = _js_named(node)
    if len(children) > _MAX_TABLE_ENTRIES:
        return []
    for child in children:
        if child.type != "pair":
            return []
        key_node = child.child_by_field_name("key")
        key = _js_key(key_node)
        if not _lit(key):
            return []
        keys = [key]
        number = _js_number(key[1])
        if (
            _lit(number)
            and key_node is not None
            and key_node.type in {"number", "string"}
        ):
            keys.append(number)
        entries.append((tuple(keys), child.child_by_field_name("value"), key_node))
    return entries


def _js_map_entries(node) -> list:
    node = _js_unwrap(node)
    if node is None or node.type != "array":
        return []
    entries = []
    rows = _js_named(node)
    if len(rows) > _MAX_TABLE_ENTRIES:
        return []
    for row in rows:
        row = _js_unwrap(row)
        items = _js_named(row) if row is not None and row.type == "array" else []
        if len(items) != 2:
            return []
        key = _js_value(items[0])
        if not _lit(key):
            return []
        entries.append(((key,), items[1], items[0]))
    return entries


def _js_scopes(root, added: set[int] | None, functions: set[str] | None):
    """The module's statements and every function. With ``added``, functions
    the change did not touch are skipped, unless a module-level table did;
    with ``functions``, only those names ("" for the module's statements)."""
    module_tables = _js_tables(root)
    module_names = set(_js_declarations(root))
    tables_changed = added is None or any(
        key.start_point[0] + 1 in added or value.start_point[0] + 1 in added
        for entries in module_tables.values()
        for _, value, key in entries
    )
    if functions is None or "" in functions:
        yield _JsScope(root, root, "", "", [], module_tables, module_names)
    stack = [root]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type not in _JS_FUNCTIONS:
            continue
        if not tables_changed and not any(
            line in added
            for line in range(node.start_point[0] + 1, node.end_point[0] + 2)
        ):
            continue
        name, owner = _js_function_name(node)
        name = name or ANONYMOUS  # a callback: never the module's own code
        if functions is not None and name not in functions:
            continue
        params = [p if isinstance(p, str) else "" for p in _js_param_names(node)]
        body = node.child_by_field_name("body")
        yield _JsScope(node, body, name, owner, params, module_tables, module_names)


def _js_counters(scope: _JsScope, module_names: set[str]) -> set[str]:
    counters = set()
    for node in scope.nodes():
        target = None
        if node.type == "update_expression":
            target = node.child_by_field_name("argument")
        elif node.type in {"augmented_assignment_expression", "assignment_expression"}:
            target = node.child_by_field_name("left")
        while target is not None and target.type in {
            "subscript_expression",
            "member_expression",
        }:
            target = target.child_by_field_name("object")
        if target is not None and target.type == "identifier":
            name = _text(target)
            if name in module_names and name not in scope.params:
                counters.add(name)
    return counters


def _js_subject(node, scope: _JsScope):
    node = _js_unwrap(node)
    if node is None:
        return None
    convert = ""
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        args = _js_args(node)
        text = _text(function)
        if text == "JSON.stringify" and len(args) == 1:
            convert, node = "json_js", args[0]
        elif text in _JS_CONVERSIONS and len(args) == 1:
            convert, node = _JS_CONVERSIONS[text], args[0]
        elif function is not None and function.type == "member_expression":
            method = _text(function.child_by_field_name("property"))
            target = function.child_by_field_name("object")
            if method in {"toLowerCase", "toUpperCase", "trim"} and not args:
                convert = {
                    "toLowerCase": "lower",
                    "toUpperCase": "upper",
                    "trim": "strip",
                }[method]
                node = target
            elif method == "join" and len(args) == 1 and args[0].type == "string":
                convert, node = "join:" + _string_value(args[0]), target
            else:
                return None
        else:
            return None
        node = _js_unwrap(node)
        if node is None:
            return None
    root = node
    while root is not None and root.type in {
        "member_expression",
        "subscript_expression",
    }:
        root = root.child_by_field_name("object")
    if root is None or root.type not in {"identifier", "this"}:
        return None
    counter = root.type == "identifier" and _text(root) in scope.counters
    if node.type == "identifier" and _text(node) in scope.params and not counter:
        return _text(node), scope.params.index(_text(node)), convert, False
    return None, None, convert, counter


def _js_cond(node, scope: _JsScope) -> Cond | None:
    node = _js_unwrap(node)
    if node is None:
        return None
    if node.type == "binary_expression" and _text(
        node.child_by_field_name("operator")
    ) in {"===", "=="}:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        for subject, literal in ((left, right), (right, left)):
            value = _js_value(literal)
            if not _lit(value):
                continue
            found = _js_subject(subject, scope)
            if found is None:
                return None
            return Cond(
                _clip(_text(subject)), found[0], found[1], found[2], (value,), found[3]
            )
        return None
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        args = _js_args(node)
        if (
            function is not None
            and function.type == "member_expression"
            and _text(function.child_by_field_name("property")) == "includes"
            and len(args) == 1
        ):
            values = _js_value(function.child_by_field_name("object"))
            if values[0] == "l" and values[1]:
                found = _js_subject(args[0], scope)
                if found is None:
                    return None
                return Cond(
                    _clip(_text(args[0])),
                    found[0],
                    found[1],
                    found[2],
                    values[1],
                    found[3],
                )
    return None


def _js_disjuncts(node, scope: _JsScope) -> list[list[Cond]]:
    node = _js_unwrap(node)
    if node is None:
        return []
    if node.type == "binary_expression":
        operator = _text(node.child_by_field_name("operator"))
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if operator == "||":
            return (_js_disjuncts(left, scope) + _js_disjuncts(right, scope))[
                :_MAX_DISJUNCTS
            ]
        if operator == "&&":
            combos: list[list[Cond]] = [[]]
            for side in (left, right):
                parts = _js_disjuncts(side, scope)
                if parts:
                    combos = [c + p for c in combos for p in parts][:_MAX_DISJUNCTS]
            return [c for c in combos if c]
    cond = _js_cond(node, scope)
    return [[cond]] if cond is not None else []


def _js_result(statement):
    """(value, as written, verb, line) of the answer a branch gives."""
    if statement is None:
        return None
    statements = (
        _js_named(statement) if statement.type == "statement_block" else [statement]
    )
    for item in statements:
        if item.type == "return_statement":
            values = _js_named(item)
            if not values:
                return None
            return (
                _js_value(values[0]),
                _clip(_text(values[0])),
                "returns",
                values[0].start_point[0] + 1,
            )
        if item.type == "expression_statement":
            inner = _js_named(item)
            expression = _js_unwrap(inner[0]) if inner else None
            if expression is None:
                continue
            if expression.type == "call_expression":
                function = expression.child_by_field_name("function")
                args = _js_args(expression)
                method = _js_callee(function)
                if method in _JS_OUTPUT and len(args) == 1:
                    return (
                        _js_value(args[0]),
                        _clip(_text(args[0])),
                        "prints" if method != "push" else "outputs",
                        item.start_point[0] + 1,
                    )
                continue
            if expression.type == "assignment_expression":
                left = expression.child_by_field_name("left")
                right = expression.child_by_field_name("right")
                return (
                    _js_value(right),
                    _clip(_text(right)),
                    f"sets {_clip(_text(left), 30)} to",
                    item.start_point[0] + 1,
                )
            return None
        if item.type in {"empty_statement"}:
            continue
        return None
    return None


def _js_answer_like(node, scope: _JsScope, literal_names: set[str]) -> bool:
    node = _js_unwrap(node)
    if node is None or _lit(_js_value(node)):
        return True
    if node.type == "identifier":
        return _text(node) in literal_names
    if node.type == "subscript_expression":
        return _js_table(node.child_by_field_name("object"), scope) is not None
    if node.type == "ternary_expression":
        # A chain of literal comparisons is a table; any other condition
        # (n % 2 === 0) works the answer out.
        return (
            bool(_js_disjuncts(node.child_by_field_name("condition"), scope))
            and _js_answer_like(
                node.child_by_field_name("consequence"), scope, literal_names
            )
            and _js_answer_like(
                node.child_by_field_name("alternative"), scope, literal_names
            )
        )
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        if (
            function is not None
            and function.type == "member_expression"
            and _text(function.child_by_field_name("property")) == "get"
            and _js_table(function.child_by_field_name("object"), scope) is not None
        ):
            return True
    return False


def _js_general(scope: _JsScope) -> bool:
    assigned: dict[str, bool] = {}
    for node in scope.nodes():
        if node.type == "variable_declarator":
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if name is not None and name.type == "identifier":
                literal = value is None or _lit(_js_value(value))
                assigned[_text(name)] = assigned.get(_text(name), True) and literal
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            if left is not None and left.type == "identifier":
                literal = _lit(_js_value(node.child_by_field_name("right")))
                assigned[_text(left)] = assigned.get(_text(left), True) and literal
        elif node.type in {"augmented_assignment_expression", "update_expression"}:
            target = node.child_by_field_name(
                "left" if node.type != "update_expression" else "argument"
            )
            if target is not None and target.type == "identifier":
                assigned[_text(target)] = False
    literal_names = {name for name, literal in assigned.items() if literal}
    body = scope.body
    if (
        body is not None
        and scope.node.type == "arrow_function"
        and body.type != "statement_block"
    ):
        if not _js_answer_like(body, scope, literal_names):
            return True
    for node in scope.nodes():
        if node.type in {"return_statement", "yield_expression"}:
            values = _js_named(node)
            if values and not _js_answer_like(values[0], scope, literal_names):
                return True
        elif (
            node.type == "call_expression"
            and _js_callee(node.child_by_field_name("function")) in _JS_OUTPUT
        ):
            if any(
                not _js_answer_like(a, scope, literal_names) for a in _js_args(node)
            ):
                return True
    return False


def _js_table(node, scope: _JsScope):
    node = _js_unwrap(node)
    if node is None:
        return None
    if node.type == "object":
        entries = _js_object_entries(node)
        return ("", entries) if entries else None
    if node.type == "identifier" and _text(node) in scope.tables:
        return _text(node), scope.tables[_text(node)]
    return None


def _js_sites(scope: _JsScope, path: str, added: set[int] | None) -> list[Site]:
    sites: list[Site] = []

    def new(*lines: int) -> bool:
        return added is None or any(line in added for line in lines)

    def add(conds, result, line, condition):
        value, text, verb, result_line = result
        if not _lit(value) or not new(line, result_line):
            return
        sites.append(
            Site(
                path,
                line,
                scope.name,
                scope.owner,
                tuple(conds),
                value,
                text,
                verb,
                _clip(condition),
                scope.general,
                js=True,
            )
        )

    for node in scope.nodes():
        if node.type == "if_statement":
            condition = node.child_by_field_name("condition")
            result = _js_result(node.child_by_field_name("consequence"))
            if condition is None or result is None:
                continue
            line = condition.start_point[0] + 1
            for conds in _js_disjuncts(condition, scope):
                add(conds, result, line, _text(_js_unwrap(condition)))
        elif node.type == "ternary_expression":
            condition = node.child_by_field_name("condition")
            consequence = node.child_by_field_name("consequence")
            if condition is None or consequence is None:
                continue
            result = (
                _js_value(consequence),
                _clip(_text(consequence)),
                "returns",
                consequence.start_point[0] + 1,
            )
            for conds in _js_disjuncts(condition, scope):
                add(conds, result, condition.start_point[0] + 1, _text(condition))
        elif node.type == "switch_statement":
            subject_node = node.child_by_field_name("value")
            body = node.child_by_field_name("body")
            found = _js_subject(subject_node, scope)
            if found is None or body is None:
                continue
            pending: list = []
            for case in _js_named(body):
                if case.type != "switch_case":
                    pending = []
                    continue
                value_node = case.child_by_field_name("value")
                value = _js_value(value_node)
                if not _lit(value):
                    pending = []
                    continue
                pending.append(value)
                statements = [
                    c
                    for c in case.children_by_field_name("body")
                    if c.type != "comment"
                ]
                if not statements:
                    continue
                first = statements[0]
                result = _js_result(first)
                if result is not None:
                    subject = _clip(_text(_js_unwrap(subject_node)))
                    cond = Cond(
                        subject, found[0], found[1], found[2], tuple(pending), found[3]
                    )
                    add(
                        [cond],
                        result,
                        case.start_point[0] + 1,
                        f"{subject} is {_clip(_text(value_node), 30)}",
                    )
                pending = []
        else:
            lookup = _js_lookup(node, scope)
            if lookup is None:
                continue
            name, entries, subject_node = lookup
            found = _js_subject(subject_node, scope)
            if found is None:
                continue
            subject = _clip(_text(_js_unwrap(subject_node)))
            for keys, value_node, key_node in entries:
                key_line = key_node.start_point[0] + 1
                if not new(
                    key_line, value_node.start_point[0] + 1, node.start_point[0] + 1
                ):
                    continue
                cond = Cond(subject, found[0], found[1], found[2], keys, found[3])
                add(
                    [cond],
                    (
                        _js_value(value_node),
                        _clip(_text(value_node)),
                        f"answers {_clip(_text(value_node), 50)} from "
                        f"{name or 'a table'}",
                        key_line,
                    ),
                    key_line,
                    f"{subject} is {_clip(_text(key_node), 30)}",
                )
    return sites


def _js_lookup(node, scope: _JsScope):
    if node.type == "subscript_expression":
        table = _js_table(node.child_by_field_name("object"), scope)
        if table is not None:
            return table[0], table[1], node.child_by_field_name("index")
    if node.type == "call_expression":
        function = node.child_by_field_name("function")
        args = _js_args(node)
        if (
            function is not None
            and function.type == "member_expression"
            and _text(function.child_by_field_name("property")) == "get"
            and len(args) >= 1
        ):
            table = _js_table(function.child_by_field_name("object"), scope)
            if table is not None:
                return table[0], table[1], args[0]
    return None


_JS_EQUALITY_METHODS = frozenset(
    {"equals", "isEqual", "eq", "equalTo", "sameAs", "isSame"}
)


def _js_rigged(root, added: set[int] | None) -> list[Marker]:
    markers = []
    stack = [root]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type == "method_definition":
            name_node = node.child_by_field_name("name")
            function = node
        elif node.type == "pair":
            name_node = node.child_by_field_name("key")
            function = _js_unwrap(node.child_by_field_name("value"))
            if function is None or function.type not in _JS_FUNCTIONS:
                continue
        else:
            continue
        if name_node is None:
            continue
        name = _text(name_node)
        if name_node.type == "computed_property_name":
            name = "[Symbol.toPrimitive]" if "toPrimitive" in name else name
        verdict = _js_constant_method(name, function)
        if verdict is None:
            continue
        lines = {node.start_point[0] + 1}
        for item in _js_function_returns(function):
            lines.add(item.start_point[0] + 1)
        if added is not None and not lines & added:
            continue
        owner = ""
        holder = node.parent.parent if node.parent is not None else None
        if holder is not None and holder.type in {"class_declaration", "class"}:
            owner = _text(holder.child_by_field_name("name"))
        message, blocking, expects = verdict
        if blocking and _WILDCARD_RE.search(owner):
            blocking = False
            message += " (its name says it matches anything; check that it never stands in for a real value)"
        where = f"{owner}.{name}()" if owner else f"{name}()"
        prefix = "" if blocking else "(advice) "
        markers.append(
            Marker(
                RULE_RIGGED,
                node.start_point[0] + 1,
                ("rigged", owner, name),
                f"{prefix}{where} {message}",
                blocking,
                expects,
            )
        )
    return markers


def _js_function_returns(function):
    body = function.child_by_field_name("body")
    if body is None:
        return []
    if body.type != "statement_block":
        return [body]
    found = []
    stack = [body]
    while stack:
        node = stack.pop()
        for child in node.children:
            if child.type in _JS_FUNCTIONS or child.type == "class_declaration":
                continue
            if child.type == "return_statement":
                values = _js_named(child)
                found.append(values[0] if values else child)
            stack.append(child)
    return found


def _js_constant_method(name: str, function):
    returns = _js_function_returns(function)
    if not returns or any(r.type == "return_statement" for r in returns):
        return None
    values = [_js_value(r) for r in returns]
    constant = values[0] if all(v == values[0] for v in values) else _NONLIT
    params = _js_param_names(function)
    other = params[0] if params and isinstance(params[0], str) else None
    body = function.child_by_field_name("body")
    names = set()
    uses_this = False
    if body is not None:
        for node in _js_scope_walk(body):
            if node.type == "identifier":
                names.add(_text(node))
            elif node.type == "this":
                uses_this = True
    if name in _JS_EQUALITY_METHODS:
        if constant == ("b", True):
            return (
                "always returns true: any comparison with it passes, so tests "
                "that compare values cannot fail",
                True,
                None,
            )
        if other and other not in names and constant != ("b", False):
            return (
                f"never looks at the value it is compared with ({other}): "
                "comparisons with it cannot fail the way they should",
                True,
                None,
            )
        return None
    if name in {"compareTo", "compare"} and constant == ("n", 0) and len(params) >= 1:
        return (
            "always returns 0: everything compares equal to it, so tests that "
            "compare values cannot fail",
            True,
            None,
        )
    if name in {"valueOf", "[Symbol.toPrimitive]"} and _lit(constant) and not uses_this:
        return (
            f"returns the constant {_show(constant, js=True)}: every instance "
            "converts to the same value, so comparisons and arithmetic in tests "
            "see that constant instead of the real value",
            True,
            None,
        )
    if name in {"toString", "toJSON"} and constant[0] == "s" and not uses_this:
        return (
            f"returns the constant {_show(constant, js=True)}, the text a "
            "test expects: a fixed string form passes the test without the value "
            "being right",
            False,
            constant[1],
        )
    return None


def _js_scope_walk(body):
    stack = [body]
    while stack:
        node = stack.pop()
        yield node
        for child in node.children:
            if child.type in _JS_FUNCTIONS or child.type == "class_declaration":
                continue
            stack.append(child)


def _js_markers(root, added: set[int] | None) -> list[Marker]:
    markers: list[Marker] = []
    seen: set[int] = set()
    stack = [root]
    in_source_tests = _js_in_source_test_blocks(root)
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        line = node.start_point[0] + 1
        if added is not None and line not in added:
            continue
        found = _js_marker(node)
        if found is None or line in seen:
            continue
        if found[0] == "import.meta.vitest" and any(
            start <= node.start_byte < end for start, end in in_source_tests
        ):
            continue
        seen.add(line)
        detail, message, blocking = found
        markers.append(
            Marker(
                RULE_TEST_DETECTION,
                line,
                ("detect", _js_enclosing(node), detail),
                message,
                blocking,
            )
        )
    return markers


def _js_enclosing(node) -> str:
    for ancestor in _js_ancestors(node):
        if ancestor.type in _JS_FUNCTIONS:
            return _js_function_name(ancestor)[0]
    return ""


def _js_in_source_test_blocks(root) -> list[tuple[int, int]]:
    """Byte ranges of ``if (import.meta.vitest) { ... }`` blocks that hold
    Vitest in-source tests: test code by design."""
    blocks = []
    stack = [root]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type != "if_statement":
            continue
        condition = _js_unwrap(node.child_by_field_name("condition"))
        if condition is None or _text(condition) != "import.meta.vitest":
            continue
        consequence = node.child_by_field_name("consequence")
        text = _text(consequence)
        if "import.meta.vitest" in text or re.search(
            r"\b(?:it|test|describe)\s*\(", text
        ):
            blocks.append((node.start_byte, node.end_byte))
    return blocks


_RUNNER_MESSAGE = (
    "code that behaves differently under the test runner can pass tests it "
    "would fail in use"
)


def _js_marker(node):
    kind = node.type
    if kind in {"member_expression", "subscript_expression"}:
        target = node.child_by_field_name("object")
        if kind == "member_expression":
            key = _text(node.child_by_field_name("property"))
        else:
            index = _js_unwrap(node.child_by_field_name("index"))
            key = (
                _string_value(index)
                if index is not None and index.type == "string"
                else ""
            )
        base = _text(target)
        if base in {"process.env", "import.meta.env"} and key in _JS_RUNNER_ENV:
            return (
                key,
                f"reads {base}.{key}, which only the test runner sets: {_RUNNER_MESSAGE}",
                True,
            )
        if base in {"globalThis", "global", "window", "self"} and (
            key in _JS_RUNNER_GLOBALS or key in _JS_TEST_GLOBALS
        ):
            return (
                key,
                f"checks for {base}.{key}, a test runner global: {_RUNNER_MESSAGE}",
                True,
            )
        if kind == "member_expression" and _text(node) == "import.meta.vitest":
            return (
                "import.meta.vitest",
                f"checks import.meta.vitest outside an in-source test block: {_RUNNER_MESSAGE}",
                True,
            )
    if (
        kind == "unary_expression"
        and _text(node.child_by_field_name("operator")) == "typeof"
    ):
        argument = _js_unwrap(node.child_by_field_name("argument"))
        name = _text(argument) if argument is not None else ""
        if (
            argument is not None
            and argument.type == "identifier"
            and name in _JS_RUNNER_GLOBALS
        ):
            return (
                f"typeof:{name}",
                f"checks typeof {name}, a test runner global: {_RUNNER_MESSAGE}",
                True,
            )
    if kind == "binary_expression" and _text(node.child_by_field_name("operator")) in {
        "===",
        "==",
        "!==",
        "!=",
    }:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        for env_side, other in ((left, right), (right, left)):
            text = _text(_js_unwrap(env_side))
            value = _js_value(other)
            if (
                text
                in {
                    "process.env.NODE_ENV",
                    "import.meta.env.MODE",
                    "process.env.APP_ENV",
                }
                and value[0] == "s"
                and value[1].lower() in {"test", "testing"}
            ):
                return (
                    f"env:{text}",
                    f'(advice) compares {text} with "{value[1]}": code that takes '
                    "another path in tests leaves the real path untested",
                    False,
                )
    return None


# ---------------------------------------------------------------------------
# Reading the tests' own files
# ---------------------------------------------------------------------------

_PY_READERS = frozenset(
    {
        "open",
        "Path",
        "PurePath",
        "PurePosixPath",
        "read_text",
        "read_bytes",
        "load",
        "loads",
        "join",
        "joinpath",
        "with_name",
        "exists",
        "isfile",
        "is_file",
        "resolve",
        "abspath",
        "realpath",
    }
)
_JS_READERS = frozenset(
    {
        "readFileSync",
        "readFile",
        "require",
        "join",
        "resolve",
        "open",
        "createReadStream",
    }
)


def _test_file_reads(
    path, tree_or_root, js: bool, names: set[str], added
) -> list[Marker]:
    """String literals naming a test file, passed to a file-reading call.

    Path pieces are joined first, so ``Path(...) / "tests" / "data" / "x.txt"``,
    ``os.path.join(..., "tests", "x.txt")`` and ``join(__dirname, "..", "test",
    "x.md")`` count, and a name bound to a string literal is followed one hop.
    """
    if not names:
        return []
    found: dict[tuple[int, str], None] = {}

    def consider(value: str, line: int) -> None:
        if _names_test_file(value, names) and (added is None or line in added):
            found.setdefault((line, value), None)

    if not js:
        # NAME = "test_cases.json" read later as open(NAME): one hop.
        named = {}
        for node in ast.walk(tree_or_root):
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                named[node.targets[0].id] = node.value

        def literal(arg):
            if isinstance(arg, ast.Name) and arg.id in named:
                arg = named[arg.id]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                return arg
            return None

        for node in ast.walk(tree_or_root):
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
                # Path(__file__).parent / "tests" / "x.txt": the whole chain.
                pieces, part = [], node
                while isinstance(part, ast.BinOp) and isinstance(part.op, ast.Div):
                    pieces.append(part.right)
                    part = part.left
                pieces.append(part)
                arguments = [literal(a) for a in reversed(pieces)]
                joined = True
            elif isinstance(node, ast.Call):
                callee = _dotted(node.func) or (
                    (node.func.attr,) if isinstance(node.func, ast.Attribute) else ()
                )
                if not callee or callee[-1] not in _PY_READERS or _writes(node):
                    continue
                arguments = [literal(a) for a in node.args]
                joined = callee[-1] in {"join", "joinpath"}
            else:
                continue
            constants = [a for a in arguments if a is not None]
            for arg in constants:
                consider(arg.value, arg.lineno)
            if joined and len(constants) >= 2:
                consider("/".join(a.value for a in constants), constants[-1].lineno)
    else:
        # const GOLDEN = "test/golden.txt" read later as readFileSync(GOLDEN).
        named_js = {}
        stack = [tree_or_root]
        while stack:
            node = stack.pop()
            stack.extend(node.children)
            if node.type == "variable_declarator":
                name = node.child_by_field_name("name")
                value = node.child_by_field_name("value")
                if (
                    name is not None
                    and value is not None
                    and name.type == "identifier"
                    and value.type == "string"
                ):
                    named_js[name.text.decode("utf-8", "replace")] = value
        stack = [tree_or_root]
        while stack:
            node = stack.pop()
            stack.extend(node.children)
            target, joined = None, False
            if node.type == "call_expression":
                callee = _js_callee(node.child_by_field_name("function"))
                if callee in _JS_READERS:
                    target = _js_args(node)
                    joined = callee in {"join", "resolve"}
            elif node.type == "import_statement":
                source = node.child_by_field_name("source")
                target = [source] if source is not None else []
            strings = []
            for arg in target or ():
                if arg.type == "identifier":
                    arg = named_js.get(arg.text.decode("utf-8", "replace"), arg)
                if arg.type == "string":
                    strings.append((_string_value(arg), arg.start_point[0] + 1))
            for value, line in strings:
                consider(value, line)
            if joined and len(strings) >= 2:
                consider("/".join(v for v, _ in strings), strings[-1][1])

    return [
        Marker(
            RULE_TEST_DETECTION,
            line,
            ("reads", value),
            f"reads the test file {value}: production code that uses the tests' "
            "own data passes them without doing the work",
        )
        for line, value in found
    ]


def _writes(call) -> bool:
    """open(path, "w") and the like: writing a file is not reading the tests."""
    mode = call.args[1] if len(call.args) > 1 else None
    for keyword in call.keywords:
        if keyword.arg == "mode":
            mode = keyword.value
    return (
        isinstance(mode, ast.Constant)
        and isinstance(mode.value, str)
        and bool(set(mode.value) & set("wax+"))
    )


def _names_test_file(value: str, names: set[str]) -> bool:
    cleaned = value.strip().replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    if not cleaned or "\n" in cleaned:
        return False
    if cleaned in names or PurePosixPath(cleaned).name in names:
        return True
    # A joined path such as ../test/fixtures/x.md: drop the relative steps and
    # match a known test file, but only when the path itself goes through a
    # test folder, so an app's own data/x.txt never matches tests/data/x.txt.
    parts = [p for p in cleaned.split("/") if p not in ("", ".", "..")]
    if len(parts) < 2 or not any(p in _TEST_DIRS for p in parts[:-1]):
        return False
    relative = "/".join(parts)
    return any(n == relative or n.endswith("/" + relative) for n in names)


# ---------------------------------------------------------------------------
# Which files count
# ---------------------------------------------------------------------------


def _is_test_code(path: str, python_tests: set[str]) -> bool:
    pure = PurePosixPath(path)
    name = pure.name
    return (
        path in python_tests
        or is_js_test_file(path)
        or name == "conftest.py"
        or name in {"test.py", "tests.py"}
        or is_pytest_file(path)
        or any(part in _TEST_DIRS or part in _SUPPORT_DIRS for part in pure.parts[:-1])
    )


def _is_test_setup(path: str, source: str | None) -> bool:
    """Setup, config and test-runner plugin files: where switching on the test
    run belongs."""
    pure = PurePosixPath(path)
    name = pure.name.lower()
    stem = name.split(".")[0]
    if ".config." in name or ".setup." in name or name.endswith(".config"):
        return True
    if stem in {
        "setuptests",
        "setup-tests",
        "setup_tests",
        "test-setup",
        "testsetup",
        "test_setup",
        "setup",
    }:
        return True
    if any(part.lower() in _CONFIG_DIRS for part in pure.parts[:-1]):
        return True
    if name.endswith(".py"):
        if (
            name in _PY_CONFIG_FILES
            or name.startswith("settings")
            or name.endswith("_settings.py")
        ):
            return True
        text = source or ""
        if re.search(
            r"^\s*(?:import pytest|from _?pytest\b|def pytest_\w+\()", text, re.M
        ):
            return True  # a pytest plugin
        return False
    return bool(_JS_TEST_IMPORTS.search(source or ""))


def _is_generated(path: str, source: str | None) -> bool:
    pure = PurePosixPath(path)
    if pure.name.endswith(_GENERATED_SUFFIXES) or any(
        part in _GENERATED_DIRS for part in pure.parts[:-1]
    ):
        return True
    head = (source or "")[:1500].lower()
    return any(
        marker in head
        for marker in (
            "@generated",
            "do not edit",
            "auto-generated",
            "autogenerated",
            "generated by",
        )
    )


def _code_kind(path: str) -> str | None:
    if path.endswith(".py"):
        return "py"
    pure = PurePosixPath(path)
    if pure.suffix in JS_SUFFIXES and not pure.name.endswith(
        (".d.ts", ".d.mts", ".d.cts")
    ):
        return "js"
    return None


# Text a file must hold for each kind of marker to be worth a parse.
_PY_MARKER_WORDS = (
    "environ",
    "getenv",
    "modules",
    "argv",
    "_called_from_test",
    "inspect",
    "_getframe",
    "traceback",
)
_PY_RIGGED_WORDS = (
    "__eq__",
    "__ne__",
    "__contains__",
    "__lt__",
    "__le__",
    "__gt__",
    "__ge__",
    "__hash__",
    "__str__",
    "__repr__",
)
_JS_MARKER_WORDS = (
    "process.env",
    "import.meta",
    "typeof",
    "globalThis",
    "global.",
    "window.",
    "self.",
)
_JS_RIGGED_WORDS = (
    "equals",
    "isEqual",
    "eq",
    "equalTo",
    "sameAs",
    "isSame",
    "compare",
    "valueOf",
    "toPrimitive",
    "toString",
    "toJSON",
)


def scan_source(
    path: str,
    source: str | None,
    added: set[int] | None,
    test_names: set[str] = frozenset(),
    *,
    functions: set[str] | None = None,
    markers: bool = True,
) -> Scan:
    """Special cases, test detection and rigged comparisons in one file.
    ``added`` limits it to those lines (None: the whole file); ``functions``
    to those functions ("" for module code); ``markers=False`` skips test
    detection and rigged comparisons."""
    kind = _code_kind(path)
    scan = Scan()
    if source is None or kind is None or _is_test_code(path, set()):
        return scan
    setup = _is_test_setup(path, source) if markers else True
    # A joined path never spells out the whole name: the file name is enough
    # to look closer.
    reads = not setup and any(
        name in source or PurePosixPath(name).name in source for name in test_names
    )
    if kind == "py":
        tree = _py_parse(path, source)
        if tree is None:
            scan.clean = False
            return scan
        if functions is None or functions:
            for scope in _py_scopes(tree, source, added, functions):
                scan.sites += _py_sites(scope, path, added)
        if markers and any(word in source for word in _PY_RIGGED_WORDS):
            scan.markers += _py_rigged(tree, source, added)
        if not setup and any(word in source for word in _PY_MARKER_WORDS):
            scan.markers += _py_markers(tree, source, added)
        if reads:
            scan.markers += _test_file_reads(path, tree, False, test_names, added)
        return scan
    root = _parse(path, source)
    if root is None:
        return scan
    if root.has_error:
        scan.clean = False
    if functions is None or functions:
        for scope in _js_scopes(root, added, functions):
            scan.sites += _js_sites(scope, path, added)
    if markers and any(word in source for word in _JS_RIGGED_WORDS):
        scan.markers += _js_rigged(root, added)
    if not setup and any(word in source for word in _JS_MARKER_WORDS):
        scan.markers += _js_markers(root, added)
    if reads:
        scan.markers += _test_file_reads(path, root, True, test_names, added)
    return scan
