"""Tests that pass whether or not the project works.

Each check reports only what the selected test's own syntax proves. A test
"runs no project code" only when every name it reads is one it bound itself
or a pure builtin that still resolves to the builtin; a parameter, decorator,
import or any other outside name leaves it alone. An assertion "is always
true" only when its condition is true for every value. Literal-only
assertions (SKY-L040) and placeholder bodies (SKY-L041) keep their own rules.
"""

from __future__ import annotations

import ast

from skylos.rules.danger.builtin_bindings import builtin_references
from skylos.rules.quality._test_quality_support import TestQualityRule
from skylos.rules.quality._test_subjects import scope_nodes, test_subjects
from skylos.rules.quality.test_assertions import _literal_condition

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_PURE_BUILTINS = frozenset(
    {
        "abs",
        "all",
        "any",
        "ascii",
        "bin",
        "bool",
        "bytearray",
        "bytes",
        "chr",
        "complex",
        "dict",
        "divmod",
        "enumerate",
        "float",
        "format",
        "frozenset",
        "hash",
        "hex",
        "int",
        "isinstance",
        "iter",
        "len",
        "list",
        "max",
        "min",
        "next",
        "oct",
        "ord",
        "pow",
        "range",
        "repr",
        "reversed",
        "round",
        "set",
        "slice",
        "sorted",
        "str",
        "sum",
        "tuple",
        "zip",
    }
)
_RESOLVED_BUILTINS = _PURE_BUILTINS | {"object"}
_UNITTEST_ASSERTIONS = frozenset(
    {
        "assertAlmostEqual",
        "assertCountEqual",
        "assertDictEqual",
        "assertEqual",
        "assertFalse",
        "assertGreater",
        "assertGreaterEqual",
        "assertIn",
        "assertIs",
        "assertIsInstance",
        "assertIsNone",
        "assertIsNot",
        "assertIsNotNone",
        "assertLess",
        "assertLessEqual",
        "assertListEqual",
        "assertNotAlmostEqual",
        "assertNotEqual",
        "assertNotIn",
        "assertNotIsInstance",
        "assertSequenceEqual",
        "assertSetEqual",
        "assertTrue",
        "assertTupleEqual",
    }
)
_OPAQUE_NODES = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.Lambda,
    ast.Import,
    ast.ImportFrom,
    ast.Global,
    ast.Nonlocal,
    ast.Raise,
    ast.Await,
    ast.Yield,
    ast.YieldFrom,
)
_CHECK_WORDS = (
    "assert",
    "check",
    "compare",
    "ensure",
    "equal",
    "expect",
    "fail",
    "match",
    "must",
    "raises",
    "should",
    "snapshot",
    "validate",
    "verify",
    "warns",
)
_CHECKING_FIXTURES = frozenset(
    {
        "benchmark",
        "data_regression",
        "file_regression",
        "image_regression",
        "num_regression",
        "regtest",
        "snapshot",
    }
)
_NAME_KEYED_FIXTURES = _CHECKING_FIXTURES | {
    "cassette",
    "request",
    "vcr",
    "vcr_cassette",
}
_NAME_KEYED_MARKS = ("betamax", "cassette", "recording", "vcr")
_COMPARISONS = {
    ast.Eq: lambda left, right: left == right,
    ast.NotEq: lambda left, right: left != right,
    ast.Lt: lambda left, right: left < right,
    ast.LtE: lambda left, right: left <= right,
    ast.Gt: lambda left, right: left > right,
    ast.GtE: lambda left, right: left >= right,
    ast.Is: lambda left, right: left is right,
    ast.IsNot: lambda left, right: left is not right,
    ast.In: lambda left, right: left in right,
    ast.NotIn: lambda left, right: left not in right,
}
_UNKNOWN = object()
_FACTS_KEY = "_test_effectiveness_facts"


def _call_name(func) -> str:
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _short(node, limit: int = 60) -> str:
    try:
        text = ast.unparse(node)
    except RecursionError:
        return "expression"
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def _body_without_docstring(function):
    body = list(function.body)
    if not body:
        return body
    first = body[0]
    if (
        isinstance(first, ast.Expr)
        and isinstance(first.value, ast.Constant)
        and isinstance(first.value.value, str)
    ):
        return body[1:]
    return body


def _placeholder_body(function) -> bool:
    return all(
        isinstance(statement, ast.Pass)
        or (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
        )
        for statement in _body_without_docstring(function)
    )


def _fold(node):
    """The value of a constant-only expression, or ``_UNKNOWN``."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        operand = _fold(node.operand)
        if operand is _UNKNOWN:
            return _UNKNOWN
        return not operand
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        compare = _COMPARISONS.get(type(node.ops[0]))
        left = _fold(node.left)
        right = _fold(node.comparators[0])
        if compare is None or left is _UNKNOWN or right is _UNKNOWN:
            return _UNKNOWN
        try:
            return compare(left, right)
        except Exception:
            return _UNKNOWN
    return _UNKNOWN


def _always_truthy(node) -> bool:
    """Whether a condition is true whatever its names hold."""
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.Or):
            return any(_always_truthy(value) for value in node.values)
        return all(_always_truthy(value) for value in node.values)
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return bool(node.elts) and not any(
            isinstance(item, ast.Starred) for item in node.elts
        )
    if isinstance(node, ast.Dict):
        return bool(node.keys) and all(key is not None for key in node.keys)
    folded = _fold(node)
    return folded is not _UNKNOWN and bool(folded)


def _is_zero(node) -> bool:
    return (
        isinstance(node, ast.Constant) and type(node.value) is int and node.value == 0
    )


class _ModuleFacts:
    """Builtin bindings and checking helpers, read once per test module."""

    def __init__(self, module: ast.Module):
        try:
            self.builtin_loads = builtin_references(module, _RESOLVED_BUILTINS)
        except RecursionError:
            self.builtin_loads = frozenset()
        functions = [node for node in ast.walk(module) if isinstance(node, _FUNCTIONS)]
        checking: set[str] = set()
        changed = True
        while changed:
            changed = False
            for function in functions:
                if function.name not in checking and _checks_something(
                    function, checking
                ):
                    checking.add(function.name)
                    changed = True
        self.checking_names = frozenset(checking)

    def is_builtin(self, node, name: str) -> bool:
        return (
            isinstance(node, ast.Name)
            and node.id == name
            and id(node) in self.builtin_loads
        )


def _module_facts(context) -> _ModuleFacts | None:
    module = context.get("_test_quality_module")
    if not isinstance(module, ast.Module):
        return None
    cached = context.get(_FACTS_KEY)
    if cached is None or cached[0] is not module:
        cached = (module, _ModuleFacts(module))
        context[_FACTS_KEY] = cached
    return cached[1]


def _checks_something(function, checking_names) -> bool:
    for node in ast.walk(function):
        if isinstance(node, (ast.Assert, ast.Raise)):
            return True
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name in checking_names:
                return True
            lowered = name.lower()
            if any(word in lowered for word in _CHECK_WORDS):
                return True
    return False


def _bound_instance(subject) -> str | None:
    """The receiver name of a method test, or None for a module function."""
    if subject.framework == "unittest" or "." in subject.name:
        positional = [*subject.node.args.posonlyargs, *subject.node.args.args]
        if positional:
            return positional[0].arg
    return None


def _takes_input(subject) -> bool:
    args = subject.node.args
    positional = [*args.posonlyargs, *args.args]
    if _bound_instance(subject) is not None:
        positional = positional[1:]
    return bool(positional or args.kwonlyargs or args.vararg or args.kwarg)


def _always_true_reason(test, facts: _ModuleFacts) -> str | None:
    if _literal_condition(test):
        return None
    if isinstance(test, ast.Tuple) and test.elts:
        return (
            "a parenthesised (condition, message) pair is a non-empty tuple, "
            "which is always true"
        )
    if _always_truthy(test):
        return f"`{_short(test)}` is always true"
    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        op = test.ops[0]
        left = test.left
        right = test.comparators[0]
        if (
            isinstance(op, ast.Is)
            and isinstance(left, ast.Name)
            and isinstance(right, ast.Name)
            and left.id == right.id
        ):
            return f"`{left.id}` is always itself"
        if isinstance(op, ast.GtE) and _is_len_call(left, facts) and _is_zero(right):
            return "a length is never negative"
        if isinstance(op, ast.LtE) and _is_zero(left) and _is_len_call(right, facts):
            return "a length is never negative"
    if (
        isinstance(test, ast.Call)
        and facts.is_builtin(test.func, "isinstance")
        and len(test.args) == 2
        and not test.keywords
        and facts.is_builtin(test.args[1], "object")
    ):
        return "every value is an instance of object"
    return None


def _is_len_call(node, facts: _ModuleFacts) -> bool:
    return (
        isinstance(node, ast.Call)
        and facts.is_builtin(node.func, "len")
        and len(node.args) == 1
        and not node.keywords
    )


def _unittest_always_passes(call: ast.Call, receiver: str | None) -> str | None:
    func = call.func
    if not (
        receiver
        and isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
        and func.value.id == receiver
    ):
        return None
    if call.keywords or any(isinstance(arg, ast.Starred) for arg in call.args):
        return None
    values = [_fold(arg) for arg in call.args[:2]]
    if any(value is _UNKNOWN for value in values):
        return None
    if func.attr == "assertTrue" and len(values) >= 1 and values[0]:
        return f"`{_short(call)}` always passes"
    if func.attr == "assertFalse" and len(values) >= 1 and not values[0]:
        return f"`{_short(call)}` always passes"
    if func.attr == "assertEqual" and len(values) == 2:
        try:
            equal = values[0] == values[1]
        except Exception:
            return None
        if equal:
            return f"`{_short(call)}` always passes"
    return None


def _always_true_assertions(subject, facts: _ModuleFacts):
    receiver = _bound_instance(subject)
    for node in scope_nodes(subject.node):
        if id(node) in subject.dead_nodes:
            continue
        reason = None
        if isinstance(node, ast.Assert):
            reason = _always_true_reason(node.test, facts)
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            reason = _unittest_always_passes(node.value, receiver)
        if reason:
            yield node, reason


def _function_locals(function) -> set[str]:
    bound: set[str] = set()
    pending = list(function.body)
    while pending:
        node = pending.pop()
        if isinstance(node, _COMPREHENSIONS):
            for inner in ast.walk(node):
                if isinstance(inner, ast.NamedExpr) and isinstance(
                    inner.target, ast.Name
                ):
                    bound.add(inner.target.id)
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bound.add(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            bound.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bound.add(node.rest)
        pending.extend(ast.iter_child_nodes(node))
    return bound


def _comprehension_targets(node) -> set[str]:
    names: set[str] = set()
    for generator in node.generators:
        for inner in ast.walk(generator.target):
            if isinstance(inner, ast.Name):
                names.add(inner.id)
    return names


def _self_contained(subject, facts: _ModuleFacts) -> bool:
    function = subject.node
    if function.decorator_list or _takes_input(subject):
        return False
    receiver = _bound_instance(subject)
    local_names = _function_locals(function)
    pending = [(statement, frozenset()) for statement in function.body]
    while pending:
        node, inner_names = pending.pop()
        if isinstance(node, _OPAQUE_NODES):
            return False
        if isinstance(node, _COMPREHENSIONS):
            inner_names = inner_names | _comprehension_targets(node)
        if isinstance(node, ast.Attribute) and receiver:
            value = node.value
            if isinstance(value, ast.Name) and value.id == receiver:
                if node.attr not in _UNITTEST_ASSERTIONS:
                    return False
                continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            known = (
                node.id in local_names
                or node.id in inner_names
                or id(node) in facts.builtin_loads
            )
            if not known or node.id == "object":
                return False
        for child in ast.iter_child_nodes(node):
            pending.append((child, inner_names))
    return True


def _has_own_assertion(function) -> bool:
    for node in ast.walk(function):
        if isinstance(node, ast.Assert):
            return True
        if isinstance(node, ast.Call) and _call_name(node.func) in _UNITTEST_ASSERTIONS:
            return True
    return False


class SelfContainedTestRule(TestQualityRule):
    """A test that reads nothing but its own values and pure builtins."""

    rule_id = "SKY-L044"
    name = "Test Runs No Project Code"

    def check(self, subject, context):
        facts = _module_facts(context)
        if facts is None or _placeholder_body(subject.node):
            return []
        if not _self_contained(subject, facts):
            return []
        if any(True for _ in _always_true_assertions(subject, facts)):
            return []
        if any(
            isinstance(node, ast.Assert) and _literal_condition(node.test)
            for node in scope_nodes(subject.node)
        ):
            return []
        if _has_own_assertion(subject.node):
            pattern = "asserts_on_own_values"
            message = (
                "This test asserts only on values it builds itself: it runs no "
                "code from the project, so it passes even when the project is "
                "broken. Call the code under test and assert on what it returns."
            )
        else:
            if subject.fixture_backed:
                return []
            pattern = "runs_and_checks_nothing"
            message = (
                "This test runs no code from the project and checks nothing, so "
                "it always passes. Call the code under test and assert on what "
                "it returns."
            )
        return [
            self._finding(
                subject.node,
                context,
                subject=subject,
                pattern=pattern,
                message=message,
                evidence={
                    "proof": "every name read is bound by the test or a pure builtin",
                    "review_action": "Call the code under test and assert on its result.",
                },
            )
        ]


class AlwaysTrueAssertionRule(TestQualityRule):
    """An assertion whose condition is true for every value of its names."""

    rule_id = "SKY-L045"
    name = "Test Assertion Always True"

    def check(self, subject, context):
        facts = _module_facts(context)
        if facts is None:
            return []
        findings = []
        for node, reason in _always_true_assertions(subject, facts):
            findings.append(
                self._finding(
                    node,
                    context,
                    subject=subject,
                    pattern="always_true_assertion",
                    message=(
                        f"This assertion cannot fail: {reason}. Assert on the "
                        "value the code is expected to produce."
                    ),
                    evidence={
                        "reason": reason,
                        "expression": _short(node, 120),
                        "review_action": "Assert on an observed result.",
                    },
                )
            )
        return findings


def _final_statement(body):
    if not body:
        return None
    last = body[-1]
    if isinstance(last, (ast.With, ast.AsyncWith)):
        return _final_statement(last.body)
    return last


def _assigned_call(statement):
    if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
        target = statement.targets[0]
        value = statement.value
    elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
        target = statement.target
        value = statement.value
    else:
        return None
    if isinstance(value, ast.Await):
        value = value.value
    if not isinstance(value, ast.Call):
        return None
    if isinstance(target, ast.Name):
        return [target.id], value
    if isinstance(target, (ast.Tuple, ast.List)) and target.elts:
        if all(isinstance(item, ast.Name) for item in target.elts):
            return [item.id for item in target.elts], value
    return None


def _parameter_names(function) -> set[str]:
    args = function.args
    names = {arg.arg for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]}
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    return names


def _decorator_names(function):
    for decorator in function.decorator_list:
        for node in ast.walk(decorator):
            if isinstance(node, (ast.Attribute, ast.Name)):
                yield _call_name(node).lower()


def _mentions_xfail(function) -> bool:
    return any(name == "xfail" for name in _decorator_names(function))


class UncheckedTestResultRule(TestQualityRule):
    """A test that ends by storing a result it never reads, and checks nothing."""

    rule_id = "SKY-L046"
    name = "Test Result Never Checked"

    def check(self, subject, context):
        facts = _module_facts(context)
        function = subject.node
        if facts is None or _mentions_xfail(function):
            return []
        if _parameter_names(function) & _CHECKING_FIXTURES:
            return []
        statement = _final_statement(function.body)
        assigned = _assigned_call(statement)
        if assigned is None:
            return []
        names, call = assigned
        if any(name.startswith("_") for name in names):
            return []
        for node in ast.walk(function):
            if isinstance(node, (ast.Global, ast.Nonlocal, ast.Return)):
                return []
            if isinstance(node, (ast.Yield, ast.YieldFrom)):
                return []
            if (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, ast.Load)
                and node.id in names
            ):
                return []
        if _checks_something(function, facts.checking_names):
            return []
        shown = ", ".join(f"`{name}`" for name in names)
        return [
            self._finding(
                statement,
                context,
                subject=subject,
                pattern="result_never_checked",
                message=(
                    f"This test stores the result of `{_short(call.func, 40)}(...)` "
                    f"in {shown} and never checks it; the test has no assertion. "
                    "Assert on the result."
                ),
                evidence={
                    "names": names,
                    "call": _short(call.func, 80),
                    "review_action": "Assert on the stored result.",
                },
            )
        ]


def _name_selects_data(function) -> bool:
    """Whether the test's own name picks a recording or snapshot it replays."""
    if _parameter_names(function) & _NAME_KEYED_FIXTURES:
        return True
    return any(
        mark in name
        for name in _decorator_names(function)
        for mark in _NAME_KEYED_MARKS
    )


def _shape(function):
    body = _body_without_docstring(function)
    if not any(
        isinstance(node, ast.Call) for statement in body for node in ast.walk(statement)
    ):
        return None
    try:
        return (
            type(function).__name__,
            ast.dump(function.args),
            tuple(ast.dump(item) for item in function.decorator_list),
            tuple(ast.dump(statement) for statement in body),
        )
    except RecursionError:
        return None


def _owner(subject) -> str:
    if "." in subject.name:
        return subject.name.rsplit(".", 1)[0]
    return ""


def _duplicates(module, context):
    """Map each repeated test to the earlier test it repeats, once per module."""
    cached = context.get("_test_effectiveness_duplicates")
    if cached is not None and cached[0] is module:
        return cached[1]
    subjects = test_subjects(module, context)
    names_per_owner: dict[tuple[str, str], int] = {}
    for subject in subjects:
        key = (_owner(subject), subject.node.name)
        names_per_owner[key] = names_per_owner.get(key, 0) + 1
    first: dict[tuple, object] = {}
    repeats: dict[int, object] = {}
    for subject in sorted(subjects, key=lambda item: item.node.lineno):
        if names_per_owner[(_owner(subject), subject.node.name)] > 1:
            continue
        if _name_selects_data(subject.node):
            continue
        shape = _shape(subject.node)
        if shape is None:
            continue
        key = (_owner(subject), shape)
        earlier = first.get(key)
        if earlier is None:
            first[key] = subject
        else:
            repeats[id(subject.node)] = earlier
    context["_test_effectiveness_duplicates"] = (module, repeats)
    return repeats


class DuplicateTestRule(TestQualityRule):
    """A test whose decorators, parameters and body repeat an earlier test."""

    rule_id = "SKY-L047"
    name = "Duplicate Test"

    def check(self, subject, context):
        module = context.get("_test_quality_module")
        if not isinstance(module, ast.Module):
            return []
        earlier = _duplicates(module, context).get(id(subject.node))
        if earlier is None:
            return []
        return [
            self._finding(
                subject.node,
                context,
                subject=subject,
                pattern="duplicate_test",
                message=(
                    f"This test repeats `{earlier.name}` (line "
                    f"{earlier.node.lineno}): same decorators, parameters and "
                    "body. Remove one, or change it to cover a different case."
                ),
                evidence={
                    "duplicate_of": earlier.name,
                    "duplicate_of_line": earlier.node.lineno,
                    "review_action": "Remove the copy or make it test another case.",
                },
            )
        ]


__all__ = [
    "AlwaysTrueAssertionRule",
    "DuplicateTestRule",
    "SelfContainedTestRule",
    "UncheckedTestResultRule",
]
