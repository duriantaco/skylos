"""What the tests assert: a call with literal inputs and the literal answer
it must return, read from Python and JavaScript/TypeScript test files and from
JSON input/output test data. ``special_cases`` looks for code that answers
exactly these inputs with exactly these answers.

Literal values are normalized to tagged tuples so Python, JavaScript and JSON
values compare alike: ("n", number), ("s", text), ("b", bool), ("z",) for
None/null/undefined, ("l", items) for lists, tuples and arrays, ("d", pairs)
for dicts and objects, and ("S", items) for sets.
"""

from __future__ import annotations

import ast
import json
import math
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from skylos.done.js_inventory import _parse, _string_value, _text

# Bounds: reading the tests must stay cheap on big repositories.
_MAX_ROWS = 64
_MAX_CASES_PER_FILE = 5000

# A value that is not a literal. Normalized literals are tuples tagged by kind:
# ("n", number), ("s", text), ("b", bool), ("z",) for None/null/undefined,
# ("l", items) for lists/tuples/arrays, ("d", pairs) and ("S", items).
_NONLIT = ("?",)

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]*$")
_TEST_DIRS = frozenset({"test", "tests", "testing", "__tests__", "spec", "specs"})


def _clip(text: str, limit: int = 60) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


# ---------------------------------------------------------------------------
# Literal values
# ---------------------------------------------------------------------------


def _num(value) -> tuple:
    if isinstance(value, float):
        if not math.isfinite(value):
            return _NONLIT
        if value.is_integer() and abs(value) < 2**53:
            value = int(value)
    return ("n", value)


def _lit(value) -> bool:
    return value != _NONLIT


def _sequence(items: list) -> tuple:
    return _NONLIT if any(not _lit(item) for item in items) else ("l", tuple(items))


def _mapping(pairs: list) -> tuple:
    if any(not _lit(k) or not _lit(v) for k, v in pairs):
        return _NONLIT
    return ("d", tuple(sorted(pairs, key=repr)))


def _trivial(value) -> bool:
    """0, 1, -1, blank text, None, booleans and empty collections."""
    kind = value[0]
    if kind == "n":
        return value[1] in (0, 1, -1)
    if kind == "s":
        return not value[1].strip()
    if kind in {"b", "z", "?"}:
        return True
    return not value[1]


def _unusual(value) -> bool:
    """A value no recursive base case or predicate returns by accident."""
    kind = value[0]
    if kind == "n":
        return abs(value[1]) >= 100 or (
            isinstance(value[1], float) and not value[1].is_integer()
        )
    if kind == "s":
        return len(value[1]) >= 8 and not _IDENTIFIER_RE.match(value[1])
    if kind in {"l", "d", "S"}:
        return len(value[1]) >= 3
    return False


def _show(value, js: bool = False) -> str:
    kind = value[0]
    if kind == "n":
        return repr(value[1])
    if kind == "s":
        return _clip(json.dumps(value[1], ensure_ascii=False), 50)
    if kind == "b":
        return ("true" if value[1] else "false") if js else repr(value[1])
    if kind == "z":
        return "null" if js else "None"
    if kind == "l":
        return _clip("[" + ", ".join(_show(v, js) for v in value[1]) + "]", 50)
    if kind == "S":
        return _clip("{" + ", ".join(_show(v, js) for v in value[1]) + "}", 50)
    if kind == "d":
        inner = ", ".join(f"{_show(k, js)}: {_show(v, js)}" for k, v in value[1])
        return _clip("{" + inner + "}", 50)
    return "?"


def _python(value):
    """The Python value of a normalized literal."""
    kind = value[0]
    if kind in {"n", "s", "b"}:
        return value[1]
    if kind == "z":
        return None
    if kind == "l":
        return [_python(v) for v in value[1]]
    if kind == "S":
        return sorted((_python(v) for v in value[1]), key=repr)
    if kind == "d":
        return {str(_python(k)): _python(v) for k, v in value[1]}
    return None


def _convert(value, how: str):
    """``value`` after the conversion the code applies before comparing."""
    if not how:
        return value
    kind = value[0]
    try:
        if how in {"tuple", "list"}:
            return value if kind == "l" else _NONLIT
        if how == "sorted":
            if kind != "l":
                return _NONLIT
            return ("l", tuple(sorted(value[1], key=lambda v: (v[0], repr(v)))))
        if how in {"set", "frozenset"}:
            if kind != "l":
                return _NONLIT
            return ("S", tuple(sorted(set(value[1]), key=repr)))
        if how in {"lower", "upper", "strip"}:
            return ("s", getattr(value[1], how)()) if kind == "s" else _NONLIT
        if how in {"int", "float", "Number"}:
            if kind == "n":
                return value
            if kind == "s":
                return _num(float(value[1]) if how != "int" else int(value[1]))
            return _NONLIT
        if how == "str":
            return ("s", str(_python(value)))
        if how == "repr":
            return ("s", repr(_python(value)))
        if how == "json_py":
            return ("s", json.dumps(_python(value)))
        if how == "json_js":
            return ("s", json.dumps(_python(value), separators=(",", ":")))
        if how == "String":
            if kind == "l":
                return ("s", ",".join(str(_python(v)) for v in value[1]))
            if kind == "b":
                return ("s", "true" if value[1] else "false")
            if kind == "z":
                return ("s", "null")
            return ("s", str(_python(value)))
        if how.startswith("join:"):
            if kind != "l":
                return _NONLIT
            return ("s", how[5:].join(str(_python(v)) for v in value[1]))
    except (TypeError, ValueError, OverflowError):
        return _NONLIT
    return _NONLIT


# ---------------------------------------------------------------------------
# What the tests assert: one call with literal inputs and its literal answer
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Call:
    name: str
    args: tuple  # normalized literals, _NONLIT where not literal
    kwargs: tuple  # ((name, value), ...)
    star: bool = False  # *args or **kwargs: positions are unknown


@dataclass(frozen=True)
class Case:
    test: str  # "tests/test_math.py::test_factorial"
    calls: tuple[Call, ...]
    inputs: frozenset
    expected: frozenset  # acceptable answers (one, except for program output)
    stdin: bool = False  # a program run on input text, from a data file
    path: str = field(default="", compare=False)  # the test file

    @property
    def key(self) -> tuple:
        return (
            tuple(sorted({c.name for c in self.calls})),
            tuple(sorted(self.inputs, key=repr)),
            tuple(sorted(self.expected, key=repr)),
        )


def _inputs(calls: list[Call]) -> frozenset:
    values = set()
    for call in calls:
        for value in (*call.args, *(v for _, v in call.kwargs)):
            if not _lit(value):
                continue
            values.add(value)
            if value[0] == "l" and len(value[1]) <= 20:
                values.update(value[1])
            elif value[0] == "d" and len(value[1]) <= 20:
                values.update(v for _, v in value[1])
    return frozenset(values)


# Calls whose result is not what the function under test returned.
_OPAQUE_WRAPPERS = frozenset(
    {
        "len",
        "type",
        "isinstance",
        "bool",
        "any",
        "all",
        "sum",
        "max",
        "min",
        "abs",
        "round",
        "hasattr",
        "callable",
        "id",
        "hash",
    }
)


# -- Python tests -----------------------------------------------------------

_PY_EQUALITY = frozenset(
    {
        "assertEqual",
        "assertEquals",
        "failUnlessEqual",
        "assertListEqual",
        "assertTupleEqual",
        "assertDictEqual",
        "assertSetEqual",
        "assertSequenceEqual",
        "assertCountEqual",
        "assertAlmostEqual",
        "assertMultiLineEqual",
        "assert_equal",
        "assert_array_equal",
        "assert_almost_equal",
        "assert_allclose",
        "eq_",
    }
)


def _dotted(node) -> tuple[str, ...]:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return tuple(reversed(parts))
    return ()


def _py_value(node, env: dict | None = None):
    """The normalized literal value of an expression, else _NONLIT."""
    if isinstance(node, ast.Constant):
        value = node.value
        if value is None:
            return ("z",)
        if isinstance(value, bool):
            return ("b", value)
        if isinstance(value, (int, float)):
            return _num(value)
        if isinstance(value, str):
            return ("s", value)
        return _NONLIT
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        inner = _py_value(node.operand, env)
        if inner[0] != "n":
            return _NONLIT
        return _num(-inner[1]) if isinstance(node.op, ast.USub) else inner
    if isinstance(node, (ast.List, ast.Tuple)):
        if any(isinstance(e, ast.Starred) for e in node.elts):
            return _NONLIT
        return _sequence([_py_value(e, env) for e in node.elts])
    if isinstance(node, ast.Set):
        items = [_py_value(e, env) for e in node.elts]
        if any(not _lit(i) for i in items):
            return _NONLIT
        return ("S", tuple(sorted(set(items), key=repr)))
    if isinstance(node, ast.Dict):
        if any(k is None for k in node.keys):
            return _NONLIT
        return _mapping(
            [
                (_py_value(k, env), _py_value(v, env))
                for k, v in zip(node.keys, node.values)
            ]
        )
    if isinstance(node, ast.Name) and env and node.id in env:
        return env[node.id]
    if (
        isinstance(node, ast.Call)
        and _dotted(node.func)[-1:] == ("approx",)
        and len(node.args) == 1
    ):
        return _py_value(node.args[0], env)
    return _NONLIT


def _py_parse(path: str, source: str | None):
    if source is None:
        return None
    try:
        return ast.parse(source, filename=path)
    except (SyntaxError, ValueError, RecursionError):
        return None


def _py_functions(tree):
    """(function, qualified name) for every function, methods included.
    Functions are statements, so only statement bodies are walked."""
    stack = [(tree.body, ())]
    while stack:
        body, scope = stack.pop()
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield stmt, (*scope, stmt.name)
                stack.append((stmt.body, (*scope, stmt.name)))
            elif isinstance(stmt, ast.ClassDef):
                stack.append((stmt.body, (*scope, stmt.name)))
            else:
                for attribute in ("body", "orelse", "finalbody"):
                    inner = getattr(stmt, attribute, None)
                    if isinstance(inner, list):
                        stack.append((inner, scope))
                for handler in getattr(stmt, "handlers", ()) or ():
                    stack.append((handler.body, scope))
                for case in getattr(stmt, "cases", ()) or ():
                    stack.append((case.body, scope))


def _py_params(function) -> list[str]:
    args = function.args
    return [a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)]


def _py_module_constants(tree) -> tuple[dict, dict]:
    """Module-level ``NAME = literal`` values, and every module-level
    assignment's value node (for parametrize lists built from constants)."""
    values, nodes = {}, {}
    for stmt in tree.body:
        target = value = None
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target, value = stmt.targets[0], stmt.value
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            target, value = stmt.target, stmt.value
        if isinstance(target, ast.Name):
            nodes[target.id] = value
            literal = _py_value(value)
            if _lit(literal):
                values[target.id] = literal
    return values, nodes


def _py_aliases(tree) -> dict[tuple[str, str], str]:
    """``def check(candidate)`` called as ``check(factorial)``: inside
    ``check``, a call of ``candidate`` is a call of ``factorial``."""
    params = {
        node.name: _py_params(node)
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    aliases: dict[tuple[str, str], str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        names = params.get(node.func.id)
        if not names:
            continue
        for index, arg in enumerate(node.args[: len(names)]):
            target = _dotted(arg)
            if target:
                aliases[(node.func.id, names[index])] = target[-1]
            elif isinstance(arg, ast.Call) and _dotted(arg.func):
                # check(Solution().max_sum) is caught by the Attribute branch;
                # check(make()) cannot be followed.
                continue
    return aliases


def _py_rows(names_node, values_node, nodes: dict, env: dict) -> list[dict]:
    if isinstance(names_node, ast.Constant) and isinstance(names_node.value, str):
        names = [n.strip() for n in names_node.value.split(",") if n.strip()]
    elif isinstance(names_node, (ast.List, ast.Tuple)) and all(
        isinstance(e, ast.Constant) and isinstance(e.value, str)
        for e in names_node.elts
    ):
        names = [e.value for e in names_node.elts]
    else:
        return []
    if isinstance(values_node, ast.Name):
        values_node = nodes.get(values_node.id)
    if not isinstance(values_node, (ast.List, ast.Tuple)):
        return []
    rows = []
    for element in values_node.elts[:_MAX_ROWS]:
        if (
            isinstance(element, ast.Call)
            and _dotted(element.func)[-1:] == ("param",)
            and not any(isinstance(a, ast.Starred) for a in element.args)
        ):
            items = element.args
        elif len(names) == 1:
            items = [element]
        elif isinstance(element, (ast.List, ast.Tuple)):
            items = element.elts
        else:
            continue
        if len(items) != len(names):
            continue
        rows.append({n: _py_value(v, env) for n, v in zip(names, items)})
    return rows


def _py_parametrize(function, nodes: dict, env: dict) -> list[dict]:
    rows: list[dict] = [{}]
    for decorator in function.decorator_list:
        if not isinstance(decorator, ast.Call) or _dotted(decorator.func)[-1:] != (
            "parametrize",
        ):
            continue
        args = list(decorator.args)
        keywords = {k.arg: k.value for k in decorator.keywords if k.arg}
        names_node = args[0] if args else keywords.get("argnames")
        values_node = args[1] if len(args) > 1 else keywords.get("argvalues")
        if names_node is None or values_node is None:
            continue
        found = _py_rows(names_node, values_node, nodes, env)
        if found:
            rows = [{**r, **f} for r in rows for f in found][:_MAX_ROWS]
    return rows


def _py_assertion(stmt) -> tuple | None:
    """(one side, other side) of an equality assertion statement."""
    if isinstance(stmt, ast.Assert):
        test = stmt.test
        if (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Eq)
        ):
            return test.left, test.comparators[0]
        return None
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        call = stmt.value
        name = _dotted(call.func)
        if name and name[-1] in _PY_EQUALITY and len(call.args) >= 2:
            return call.args[0], call.args[1]
    return None


def _py_assertions(body, rows: list[dict], nodes: dict):
    """Equality assertions in a function body, with the loop rows that bind
    names they use (``for n, want in [(3, 6), ...]:``)."""
    for stmt in body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        pair = _py_assertion(stmt)
        if pair is not None:
            yield pair, rows
            continue
        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            loop = _py_loop_rows(stmt, rows, nodes)
            yield from _py_assertions(stmt.body, loop or rows, nodes)
            continue
        for attribute in ("body", "orelse", "finalbody"):
            inner = getattr(stmt, attribute, None)
            if isinstance(inner, list):
                yield from _py_assertions(inner, rows, nodes)
        for handler in getattr(stmt, "handlers", ()) or ():
            yield from _py_assertions(handler.body, rows, nodes)
        for case in getattr(stmt, "cases", ()) or ():
            yield from _py_assertions(case.body, rows, nodes)


def _py_loop_rows(loop, rows: list[dict], nodes: dict) -> list[dict]:
    target = loop.target
    if isinstance(target, ast.Name):
        names = [target.id]
    elif isinstance(target, (ast.Tuple, ast.List)) and all(
        isinstance(e, ast.Name) for e in target.elts
    ):
        names = [e.id for e in target.elts]
    else:
        return []
    source = loop.iter
    if isinstance(source, ast.Name):
        source = nodes.get(source.id)
    if not isinstance(source, (ast.List, ast.Tuple)):
        return []
    found = []
    for element in source.elts[:_MAX_ROWS]:
        if len(names) == 1:
            found.append({names[0]: _py_value(element)})
        elif isinstance(element, (ast.Tuple, ast.List)) and len(element.elts) == len(
            names
        ):
            found.append({n: _py_value(v) for n, v in zip(names, element.elts)})
    return [{**r, **f} for r in rows for f in found][:_MAX_ROWS]


def _py_locals(function) -> dict[str, ast.AST]:
    """Names assigned exactly once in a function, to the value assigned."""
    counts: dict[str, int] = {}
    values: dict[str, ast.AST] = {}
    for node in ast.walk(function):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    counts[target.id] = counts.get(target.id, 0) + 1
                    values[target.id] = node.value
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)) and (
            isinstance(node.target, ast.Name)
        ):
            counts[node.target.id] = counts.get(node.target.id, 0) + 1
            if node.value is not None and not isinstance(node, ast.AugAssign):
                values[node.target.id] = node.value
    return {
        name: values[name]
        for name, count in counts.items()
        if count == 1 and name in values
    }


def python_cases(path: str, source: str | None) -> list[Case]:
    """Equality assertions in a Python test file whose expected value and
    some inputs are literals."""
    tree = _py_parse(path, source)
    if tree is None:
        return []
    constants, nodes = _py_module_constants(tree)
    found_aliases: list[dict] = []

    def aliases() -> dict:
        if not found_aliases:
            found_aliases.append(_py_aliases(tree))
        return found_aliases[0]

    cases: list[Case] = []
    for function, qualified in _py_functions(tree):
        rows = _py_parametrize(function, nodes, constants)
        params = set(_py_params(function))
        found_locals: list[dict] = []

        def local(function=function, found_locals=found_locals) -> dict:
            if not found_locals:
                found_locals.append(_py_locals(function))
            return found_locals[0]

        for (left, right), loop_rows in _py_assertions(function.body, rows, nodes):
            for row in loop_rows[:_MAX_ROWS]:
                env = {**constants, **row}
                case = _py_case(
                    path,
                    qualified,
                    function.name,
                    params,
                    left,
                    right,
                    env,
                    local,
                    aliases,
                )
                if case is not None:
                    cases.append(case)
            if len(cases) >= _MAX_CASES_PER_FILE:
                return cases
    return cases


def _py_case(path, qualified, function, params, left, right, env, local, aliases):
    first, second = _py_value(left, env), _py_value(right, env)
    if _lit(first) and not _lit(second):
        actual, expected = right, first
    elif _lit(second) and not _lit(first):
        actual, expected = left, second
    else:
        return None
    if isinstance(actual, ast.Name):
        actual = local().get(actual.id, actual)
    if isinstance(actual, ast.Await):
        actual = actual.value
    if (
        isinstance(actual, ast.Call)
        and isinstance(actual.func, ast.Name)
        and actual.func.id in _OPAQUE_WRAPPERS
    ):
        return None
    calls = []
    for node in ast.walk(actual):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Attribute):
            callee = node.func.attr  # obj.method(...), Rect().area(...)
        elif isinstance(node.func, ast.Name):
            callee = node.func.id
            if node.func.id in params:  # check(candidate): candidate is a parameter
                callee = aliases().get((function, node.func.id), callee)
        else:
            continue
        star = any(isinstance(a, ast.Starred) for a in node.args) or any(
            k.arg is None for k in node.keywords
        )
        calls.append(
            Call(
                callee,
                tuple(_py_value(a, env) for a in node.args),
                tuple((k.arg, _py_value(k.value, env)) for k in node.keywords if k.arg),
                star,
            )
        )
    if not calls:
        return None
    return Case(
        f"{path}::{'::'.join(qualified)}",
        tuple(calls),
        _inputs(calls),
        frozenset({expected}),
    )


# -- JavaScript/TypeScript tests ----------------------------------------------

_JS_MATCHERS = frozenset(
    {"toBe", "toEqual", "toStrictEqual", "equal", "equals", "eql", "eq"}
)
_JS_ASSERT_METHODS = frozenset(
    {"equal", "strictEqual", "deepEqual", "deepStrictEqual", "is", "same", "equals"}
)
_JS_CHAIN_WORDS = frozenset({"to", "be", "deep", "resolves", "and", "been", "is"})
_JS_TEST_CALLS = frozenset(
    {"it", "test", "specify", "describe", "context", "suite", "fit", "fdescribe"}
)
_JS_FUNCTIONS = frozenset(
    {
        "arrow_function",
        "function_expression",
        "function",
        "function_declaration",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
    }
)
_JS_WRAPPERS = frozenset(
    {
        "parenthesized_expression",
        "as_expression",
        "satisfies_expression",
        "non_null_expression",
        "type_assertion",
    }
)


def _js_unwrap(node):
    while node is not None and node.type in _JS_WRAPPERS:
        named = [c for c in node.named_children if c.type != "comment"]
        if not named:
            return None
        node = named[0]
    return node


def _js_named(node) -> list:
    return [c for c in node.named_children if c.type != "comment"]


def _js_number(text: str):
    raw = text.replace("_", "").rstrip("n")
    try:
        if raw[:2].lower() in {"0x", "0o", "0b"}:
            return _num(int(raw, 0))
        number = float(raw)
    except ValueError:
        return _NONLIT
    return _num(number)


def _js_key(node):
    """An object key as JavaScript sees it: text."""
    if node is None:
        return _NONLIT
    if node.type in {"property_identifier", "identifier"}:
        return ("s", _text(node))
    if node.type == "string":
        return ("s", _string_value(node))
    if node.type == "number":
        value = _js_number(_text(node))
        return ("s", str(value[1])) if _lit(value) else _NONLIT
    return _NONLIT


def _js_value(node, env: dict | None = None):
    node = _js_unwrap(node)
    if node is None:
        return _NONLIT
    kind = node.type
    if kind == "number":
        return _js_number(_text(node))
    if kind == "string":
        return ("s", _string_value(node))
    if kind == "template_string":
        if any(c.type == "template_substitution" for c in node.children):
            return _NONLIT
        return ("s", _string_value(node))
    if kind in {"true", "false"}:
        return ("b", kind == "true")
    if kind in {"null", "undefined"}:
        return ("z",)
    if kind == "identifier":
        name = _text(node)
        if name == "undefined":
            return ("z",)
        return env.get(name, _NONLIT) if env else _NONLIT
    if kind == "unary_expression":
        operator = _text(node.child_by_field_name("operator"))
        inner = _js_value(node.child_by_field_name("argument"), env)
        if operator in {"-", "+"} and inner[0] == "n":
            return _num(-inner[1]) if operator == "-" else inner
        return _NONLIT
    if kind == "array":
        items = _js_named(node)
        if any(i.type == "spread_element" for i in items):
            return _NONLIT
        return _sequence([_js_value(i, env) for i in items])
    if kind == "object":
        pairs = []
        for child in _js_named(node):
            if child.type == "pair":
                pairs.append(
                    (
                        _js_key(child.child_by_field_name("key")),
                        _js_value(child.child_by_field_name("value"), env),
                    )
                )
            elif child.type == "shorthand_property_identifier":
                pairs.append(
                    (("s", _text(child)), (env or {}).get(_text(child), _NONLIT))
                )
            else:
                return _NONLIT
        return _mapping(pairs)
    return _NONLIT


def _js_callee(node) -> str | None:
    node = _js_unwrap(node)
    if node is None:
        return None
    if node.type == "identifier":
        return _text(node)
    if node.type == "member_expression":
        prop = node.child_by_field_name("property")
        return _text(prop) if prop is not None else None
    return None


def _js_args(node) -> list:
    arguments = node.child_by_field_name("arguments")
    if arguments is None or arguments.type != "arguments":
        return []
    return _js_named(arguments)


def _js_assertion(call) -> tuple | None:
    """(actual, expected) nodes of an equality assertion call."""
    function = call.child_by_field_name("function")
    if function is None or function.type != "member_expression":
        if function is not None and _text(function) == "assert":
            args = _js_args(call)
            if len(args) == 1:
                inner = _js_unwrap(args[0])
                if (
                    inner is not None
                    and inner.type == "binary_expression"
                    and _text(inner.child_by_field_name("operator")) in {"===", "=="}
                ):
                    return (
                        inner.child_by_field_name("left"),
                        inner.child_by_field_name("right"),
                    )
        return None
    matcher = _text(function.child_by_field_name("property"))
    target = function.child_by_field_name("object")
    # expect(actual)[.not|.to|.be|.resolves...].toBe(expected)
    node = target
    while node is not None and node.type == "member_expression":
        word = _text(node.child_by_field_name("property"))
        if word == "not" or word == "rejects":
            return None
        if word not in _JS_CHAIN_WORDS:
            break
        node = node.child_by_field_name("object")
    if (
        node is not None
        and node.type == "call_expression"
        and _js_callee(node.child_by_field_name("function")) == "expect"
    ):
        if matcher not in _JS_MATCHERS:
            return None
        actual = _js_args(node)
        expected = _js_args(call)
        if len(actual) == 1 and len(expected) >= 1:
            return actual[0], expected[0]
        return None
    if (
        matcher in _JS_ASSERT_METHODS
        and target is not None
        and target.type == "identifier"
    ):
        args = _js_args(call)
        if len(args) >= 2:
            return args[0], args[1]
    return None


def _js_ancestors(node):
    node = node.parent
    while node is not None:
        yield node
        node = node.parent


def _js_declarations(scope) -> dict:
    """``const``/``let``/``var`` declarations directly in a block."""
    found = {}
    for statement in _js_named(scope):
        if statement.type in {"export_statement"}:
            inner = statement.child_by_field_name("declaration")
            statement = inner if inner is not None else statement
        if statement.type not in {"lexical_declaration", "variable_declaration"}:
            continue
        for declarator in _js_named(statement):
            if declarator.type != "variable_declarator":
                continue
            name = declarator.child_by_field_name("name")
            value = declarator.child_by_field_name("value")
            if name is not None and name.type == "identifier" and value is not None:
                found[_text(name)] = value
    return found


def _js_param_names(function) -> list[str | tuple[str, ...]]:
    """Parameter names; an object pattern is the tuple of its names."""
    parameters = function.child_by_field_name("parameters")
    if parameters is None:
        parameter = function.child_by_field_name("parameter")
        return [_text(parameter)] if parameter is not None else []
    names: list = []
    for item in _js_named(parameters):
        pattern = (
            item.child_by_field_name("pattern")
            if item.type
            in {
                "required_parameter",
                "optional_parameter",
            }
            else item
        )
        if pattern is None:
            names.append("")
            continue
        if pattern.type == "assignment_pattern":
            pattern = pattern.child_by_field_name("left")
        if pattern is not None and pattern.type == "identifier":
            names.append(_text(pattern))
        elif pattern is not None and pattern.type == "object_pattern":
            names.append(
                tuple(
                    _text(c)
                    for c in _js_named(pattern)
                    if c.type == "shorthand_property_identifier_pattern"
                )
            )
        elif pattern is not None and pattern.type in {"rest_pattern", "this"}:
            break
        else:
            names.append("")
    return names


def _js_each_rows(function, env: dict) -> list[dict] | None:
    """Rows of ``it.each([...])(title, (a, b) => ...)`` bound to the callback's
    parameters; None when the callback is not an ``.each`` callback."""
    holder = function.parent
    if holder is None or holder.type != "arguments":
        return None
    call = holder.parent
    if call is None or call.type != "call_expression":
        return None
    inner = call.child_by_field_name("function")
    if inner is None or inner.type != "call_expression":
        return None
    member = inner.child_by_field_name("function")
    if member is None or member.type != "member_expression":
        return None
    if _text(member.child_by_field_name("property")) not in {"each", "for"}:
        return None
    table = _js_args(inner)
    if (
        not table
        or _js_unwrap(table[0]) is None
        or _js_unwrap(table[0]).type != "array"
    ):
        return []
    names = _js_param_names(function)
    rows = []
    for row in _js_named(_js_unwrap(table[0]))[:_MAX_ROWS]:
        row = _js_unwrap(row)
        if row is None:
            continue
        bound: dict = {}
        if row.type == "array" and names and not isinstance(names[0], tuple):
            for name, item in zip(names, _js_named(row)):
                if isinstance(name, str) and name:
                    bound[name] = _js_value(item, env)
        elif row.type == "object" and names and isinstance(names[0], tuple):
            value = _js_value(row, env)
            if value[0] == "d":
                entries = {k[1]: v for k, v in value[1] if k[0] == "s"}
                bound = {n: entries[n] for n in names[0] if n in entries}
        elif names and isinstance(names[0], str) and names[0]:
            bound[names[0]] = _js_value(row, env)
        rows.append(bound)
    return rows


def _js_test_title(node, path: str) -> str:
    titles = []
    for ancestor in _js_ancestors(node):
        if ancestor.type != "call_expression":
            continue
        function = ancestor.child_by_field_name("function")
        root = function
        while root is not None and root.type in {
            "member_expression",
            "call_expression",
        }:
            root = root.child_by_field_name(
                "object" if root.type == "member_expression" else "function"
            )
        if root is None or _text(root) not in _JS_TEST_CALLS:
            continue
        args = _js_args(ancestor)
        if args and args[0].type in {"string", "template_string"}:
            titles.append(_clip(_string_value(args[0]), 80))
    return f"{path}::{' > '.join(reversed(titles))}" if titles else path


def js_cases(path: str, source: str | None) -> list[Case]:
    """Equality assertions in a JS/TS test file whose expected value and some
    inputs are literals."""
    if source is None:
        return []
    root = _parse(path, source)
    if root is None:
        return []
    top = _js_declarations(root)
    constants = {}
    for name, node in top.items():
        value = _js_value(node)
        if _lit(value):
            constants[name] = value
    cases: list[Case] = []
    stack = [root]
    while stack and len(cases) < _MAX_CASES_PER_FILE:
        node = stack.pop()
        stack.extend(node.children)
        if node.type != "call_expression":
            continue
        pair = _js_assertion(node)
        if pair is None:
            continue
        declarations: dict = {}
        rows: list[dict] = [{}]
        for ancestor in _js_ancestors(node):
            if ancestor.type == "statement_block":
                for name, value in _js_declarations(ancestor).items():
                    declarations.setdefault(name, value)
            if ancestor.type in _JS_FUNCTIONS and rows == [{}]:
                each = _js_each_rows(ancestor, constants)
                if each:
                    rows = each
        for row in rows:
            env = dict(constants)
            for name, value in declarations.items():
                literal = _js_value(value, env)
                if _lit(literal):
                    env[name] = literal
            env.update(row)
            case = _js_case(path, node, pair, env, declarations)
            if case is not None:
                cases.append(case)
    return cases


def _js_case(path, node, pair, env, declarations):
    actual, expected_node = pair
    expected = _js_value(expected_node, env)
    if not _lit(expected):
        actual, expected_node = expected_node, actual
        expected = _js_value(expected_node, env)
    if not _lit(expected) or _lit(_js_value(actual, env)):
        return None
    actual = _js_unwrap(actual)
    if actual is not None and actual.type == "await_expression":
        actual = _js_unwrap(_js_named(actual)[0]) if _js_named(actual) else None
    if actual is not None and actual.type == "identifier":
        actual = _js_unwrap(declarations.get(_text(actual)))
        if actual is not None and actual.type == "await_expression":
            actual = _js_unwrap(_js_named(actual)[0]) if _js_named(actual) else None
    if actual is None:
        return None
    calls = []
    stack = [actual]
    while stack:
        current = stack.pop()
        stack.extend(current.children)
        if current.type not in {"call_expression", "new_expression"}:
            continue
        function = current.child_by_field_name(
            "function" if current.type == "call_expression" else "constructor"
        )
        name = _js_callee(function)
        if not name:
            continue
        if current is actual and name in {"length", "size"}:
            return None
        args = _js_args(current)
        calls.append(
            Call(
                name,
                tuple(_js_value(a, env) for a in args),
                (),
                any(a.type == "spread_element" for a in args),
            )
        )
    if not calls:
        return None
    return Case(
        _js_test_title(node, path), tuple(calls), _inputs(calls), frozenset({expected})
    )


# -- Program input and output kept in data files ------------------------------


def _token(text: str):
    try:
        return _num(int(text))
    except ValueError:
        pass
    try:
        return _num(float(text))
    except ValueError:
        return ("s", text)


def data_file_cases(path: str, text: str | None) -> list[Case]:
    """Program input/output pairs from a JSON test-data file
    (``[{"input": "3\\n", "output": "6\\n"}, ...]``)."""
    if not text:
        return []
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return []
    found: list[tuple[str, str]] = []

    def visit(value, depth: int) -> None:
        if depth > 4 or len(found) >= _MAX_ROWS * 8:
            return
        if isinstance(value, dict):
            given = value.get("input", value.get("stdin"))
            wanted = value.get(
                "output", value.get("expected_output", value.get("expected"))
            )
            if isinstance(given, str) and isinstance(wanted, str):
                found.append((given, wanted))
                return
            for item in value.values():
                visit(item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                visit(item, depth + 1)

    visit(data, 0)
    cases = []
    for index, (given, wanted) in enumerate(found):
        inputs: set = set()
        tokens = given.split()
        values = [_token(t) for t in tokens[:200]]
        inputs.update(values)
        inputs.add(("s", given.strip()))
        for line in given.strip().splitlines()[:50]:
            parts = line.split()
            inputs.add(("s", line.strip()))
            if len(parts) > 1:
                inputs.add(("l", tuple(_token(p) for p in parts)))
                inputs.add(("l", tuple(("s", p) for p in parts)))
            # Call-based problems give one JSON value per argument and line.
            value = _json_value(line)
            if _lit(value):
                inputs.add(value)
                if value[0] == "l" and len(value[1]) <= 20:
                    inputs.update(value[1])
        if 1 < len(values) <= 200:
            inputs.add(("l", tuple(values)))
            inputs.add(("l", tuple(("s", t) for t in tokens[:200])))
            # A count first and the items after it: "4\n3\n16\n1\n55".
            inputs.add(("l", tuple(values[1:])))
        rows = [line.split() for line in given.strip().splitlines()[:200]]
        if len(rows) > 1 and all(len(row) > 1 for row in rows[1:]):
            # One record per line after a header: [(2, 4), (3, 5), ...].
            records = tuple(("l", tuple(_token(p) for p in row)) for row in rows[1:])
            inputs.add(("l", records))
        answer = wanted.strip()
        expected = {("s", answer)}
        if answer and len(answer.split()) == 1:
            number = _token(answer)
            if number[0] == "n":
                expected.add(number)
        value = _json_value(answer)
        if _lit(value):
            expected.add(value)
        lines = [line.strip() for line in answer.splitlines() if line.strip()]
        if len(lines) > 1:
            for line in lines[:50]:
                value = _token(line) if len(line.split()) == 1 else ("s", line)
                if (value[0] == "s" and " " in value[1]) or (
                    value[0] == "n" and abs(value[1]) >= 10
                ):
                    expected.add(value)
        cases.append(
            Case(
                f"{path} case {index + 1}",
                (),
                frozenset(inputs),
                frozenset(expected),
                stdin=True,
            )
        )
    return cases


def _json_value(text: str):
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return _NONLIT
    return _from_json(data)


def _from_json(data, depth: int = 0):
    if depth > 8:
        return _NONLIT
    if data is None:
        return ("z",)
    if isinstance(data, bool):
        return ("b", data)
    if isinstance(data, (int, float)):
        return _num(data)
    if isinstance(data, str):
        return ("s", data)
    if isinstance(data, list):
        return _sequence([_from_json(item, depth + 1) for item in data[:200]])
    if isinstance(data, dict):
        return _mapping([(("s", k), _from_json(v, depth + 1)) for k, v in data.items()])
    return _NONLIT


def is_test_data_file(path: str) -> bool:
    pure = PurePosixPath(path)
    if pure.suffix != ".json" or "node_modules" in pure.parts:
        return False
    return "test" in pure.name.lower() or any(
        part in _TEST_DIRS for part in pure.parts[:-1]
    )


_CODE_SUFFIXES = frozenset(
    {
        ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts",
        ".cts", ".go", ".rs", ".java", ".kt", ".kts", ".rb", ".php", ".cs",
        ".c", ".cc", ".cpp", ".h", ".hpp", ".sh", ".dart", ".swift", ".scala",
    }
)  # fmt: skip


def is_test_fixture_file(path: str) -> bool:
    """Any file of the tests' own data: JSON test data, or a non-code file
    (golden output, fixture text, snapshot) under a test folder."""
    if is_test_data_file(path):
        return True
    pure = PurePosixPath(path)
    if pure.suffix.lower() in _CODE_SUFFIXES or "node_modules" in pure.parts:
        return False
    return "__snapshots__" in pure.parts or any(
        part in _TEST_DIRS for part in pure.parts[:-1]
    )
