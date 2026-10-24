"""Source-proven unittest/Django discovery without importing test modules."""

from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from skylos.deadcode.framework_liveness import _bound_names, _eager_nodes, _module_name
from skylos.deadcode.signature_contracts import _merge_c3_mro

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_CASES = {
    "unittest.TestCase",
    "unittest.case.TestCase",
    "unittest.IsolatedAsyncioTestCase",
    "unittest.async_case.IsolatedAsyncioTestCase",
    "django.test.TestCase",
    "django.test.SimpleTestCase",
    "django.test.TransactionTestCase",
    "django.test.LiveServerTestCase",
    "django.test.testcases.TestCase",
    "django.test.testcases.SimpleTestCase",
    "django.test.testcases.TransactionTestCase",
    "django.test.testcases.LiveServerTestCase",
    "django.contrib.staticfiles.testing.StaticLiveServerTestCase",
}
_LIFECYCLE = {
    "setUp",
    "tearDown",
    "setUpClass",
    "tearDownClass",
}
_CLASS_DECORATORS = {"unittest.skip", "unittest.skipIf", "unittest.skipUnless"}
_BASE_NAMES = {
    "unittest.case.TestCase": "unittest.TestCase",
    "unittest.async_case.IsolatedAsyncioTestCase": "unittest.IsolatedAsyncioTestCase",
    "django.test.testcases.TestCase": "django.test.TestCase",
    "django.test.testcases.SimpleTestCase": "django.test.SimpleTestCase",
    "django.test.testcases.TransactionTestCase": "django.test.TransactionTestCase",
    "django.test.testcases.LiveServerTestCase": "django.test.LiveServerTestCase",
}
_BASE_PARENTS = {
    "unittest.TestCase": "builtins.object",
    "unittest.IsolatedAsyncioTestCase": "unittest.TestCase",
    "django.test.SimpleTestCase": "unittest.TestCase",
    "django.test.TransactionTestCase": "django.test.SimpleTestCase",
    "django.test.TestCase": "django.test.TransactionTestCase",
    "django.test.LiveServerTestCase": "django.test.TransactionTestCase",
    "django.contrib.staticfiles.testing.StaticLiveServerTestCase": "django.test.LiveServerTestCase",
}


@dataclass(frozen=True)
class _CaseBase:
    name: str


class _Discovery:
    def __init__(self, definitions, parsed, root):
        self.modules = {}
        self.paths = {}
        self.locations = defaultdict(list)
        self.exports = {}
        self.reading = set()
        self.bases = {}
        self.members = {}
        self.class_paths = {}
        self.mro_cache = {}
        self.shadowed = set()
        self.mutated_providers = set()
        self.mutated_cases = set()
        ambiguous = set()
        for module in parsed:
            path = Path(module.path).resolve()
            try:
                path.relative_to(root)
            except ValueError:
                continue
            name = _module_name(path, root)
            if name in self.modules:
                ambiguous.add(name)
            self.modules[name] = module
            self.paths[name] = path
            first = name.split(".", 1)[0]
            if first in {"unittest", "django"}:
                self.shadowed.add(first)
        for name in ambiguous:
            self.modules.pop(name)
            self.paths.pop(name)
        resolved_paths = {}
        for definition in definitions.values():
            if definition.type not in {"class", "method"}:
                continue
            raw_path = Path(definition.filename)
            path = resolved_paths.get(raw_path)
            if path is None:
                path = raw_path.resolve()
                resolved_paths[raw_path] = path
            self.locations[path, definition.line, definition.type].append(definition)

    def definition(self, path, node, kind):
        candidates = self.locations.get((path, node.lineno, kind), ())
        if len(candidates) == 1:
            return candidates[0]
        return None

    def resolve(self, value, active=()):
        if not isinstance(value, str):
            return value
        if value in active or len(active) >= 32:
            return None
        if any(
            value == name or value.startswith(name + ".")
            for name in self.mutated_providers
        ):
            return None
        parts = value.split(".")
        for end in range(len(parts), 0, -1):
            name = ".".join(parts[:end])
            if name not in self.modules:
                continue
            if end == len(parts):
                return value
            exported = self.module(name).get(parts[end])
            if end + 1 != len(parts):
                if not isinstance(exported, str):
                    return None
                exported += "." + ".".join(parts[end + 1 :])
            return self.resolve(exported, (*active, value))
        if parts[0] in self.shadowed:
            return None
        if value in _CASES:
            return _CaseBase(_BASE_NAMES.get(value, value))
        return value

    def expression(self, node, bindings):
        if isinstance(node, ast.Name):
            if node.id == "object" and node.id not in bindings:
                return _CaseBase("builtins.object")
            return bindings.get(node.id)
        if isinstance(node, ast.Attribute):
            parent = self.expression(node.value, bindings)
            if isinstance(parent, str):
                return parent + "." + node.attr
        return None

    def module(self, name):
        if name in self.exports:
            return self.exports[name]
        if name in self.reading:
            return {}
        self.reading.add(name)
        bindings = {}
        module = self.modules[name]
        path = self.paths[name]
        self.suite(module.tree.body, bindings, name, path)
        self.reading.remove(name)
        self.exports[name] = bindings
        return bindings

    def suite(self, statements, bindings, name, path):
        for statement in statements:
            if isinstance(statement, ast.If) and isinstance(
                statement.test, ast.Constant
            ):
                selected = statement.orelse
                if statement.test.value:
                    selected = statement.body
                self.suite(selected, bindings, name, path)
                continue
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    value = alias.name.split(".", 1)[0]
                    if alias.asname:
                        value = alias.name
                    bindings[alias.asname or alias.name.split(".", 1)[0]] = value
                    for imported in (alias.name.split(".", 1)[0], alias.name):
                        if imported in self.modules:
                            self.module(imported)
                continue
            if isinstance(statement, ast.ImportFrom):
                parent = statement.module or ""
                if statement.level:
                    package = name.split(".")
                    if path.name != "__init__.py":
                        package.pop()
                    if statement.level > len(package):
                        for alias in statement.names:
                            bindings[alias.asname or alias.name] = None
                        continue
                    else:
                        prefix = package[: len(package) - statement.level + 1]
                        parent = ".".join([*prefix, *parent.split(".")])
                for alias in statement.names:
                    if alias.name == "*":
                        bindings.update(dict.fromkeys(bindings))
                        continue
                    target = alias.name
                    if parent:
                        target = parent + "." + alias.name
                    bindings[alias.asname or alias.name] = self.resolve(target)
                continue
            if isinstance(statement, ast.ClassDef):
                bases = tuple(
                    self.resolve(self.expression(base, bindings))
                    for base in statement.bases
                )
                supported = not statement.keywords
                for decorator in statement.decorator_list:
                    function = decorator
                    if isinstance(decorator, ast.Call):
                        function = decorator.func
                    if self.expression(function, bindings) not in _CLASS_DECORATORS:
                        supported = False
                if supported:
                    self.bases[statement] = bases
                    self.class_paths[statement] = path
                    members = {}
                    class_bindings = bindings.copy()
                    for member in statement.body:
                        if isinstance(member, ast.AnnAssign) and member.value is None:
                            continue
                        for member_name in _bound_names(member):
                            members[member_name] = None
                        if isinstance(member, _FUNCTIONS) and all(
                            isinstance(decorator, ast.Name)
                            and decorator.id in {"staticmethod", "classmethod"}
                            and decorator.id not in class_bindings
                            for decorator in member.decorator_list
                        ):
                            members[member.name] = member
                        class_bindings.update(dict.fromkeys(_bound_names(member)))
                    self.members[statement] = members
                    bindings[statement.name] = statement
                else:
                    bindings[statement.name] = None
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                if isinstance(statement, ast.AnnAssign):
                    if statement.value is None:
                        continue
                    targets = [statement.target]
                else:
                    targets = statement.targets
                value = self.expression(statement.value, bindings)
                for target in targets:
                    if isinstance(target, ast.Name):
                        bindings[target.id] = value
                    else:
                        self.invalidate([target], bindings)
                continue
            self.invalidate([statement], bindings)

    def invalidate(self, statements, bindings):
        for statement in statements:
            for name in _bound_names(statement):
                bindings[name] = None
            # Mutating an imported provider invalidates all aliases to it.
            for node in _eager_nodes(statement):
                receiver = None
                member = None
                if isinstance(node, ast.Subscript) and isinstance(
                    node.ctx, (ast.Store, ast.Del)
                ):
                    if self.expression(node.value, bindings) == "sys.modules":
                        if isinstance(node.slice, ast.Constant) and isinstance(
                            node.slice.value, str
                        ):
                            self.mutated_providers.add(node.slice.value)
                        else:
                            self.mutated_providers.update({"unittest", "django"})
                if isinstance(node, ast.Attribute) and isinstance(
                    node.ctx, (ast.Store, ast.Del)
                ):
                    receiver = self.expression(node.value, bindings)
                    member = node.attr
                elif (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in {"setattr", "delattr"}
                    and node.func.id not in bindings
                    and node.args
                ):
                    receiver = self.expression(node.args[0], bindings)
                    if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                        member = node.args[1].value
                resolved = self.resolve(receiver)
                if isinstance(resolved, ast.ClassDef):
                    if isinstance(member, str):
                        self.members[resolved][member] = None
                    else:
                        self.members[resolved] = dict.fromkeys(self.members[resolved])
                elif isinstance(resolved, _CaseBase):
                    self.mutated_cases.add(resolved.name)
                elif isinstance(receiver, str):
                    invalid = receiver
                    if isinstance(member, str):
                        invalid += "." + member
                    self.mutated_providers.add(invalid)

    def mro(self, cls, active=()):
        if isinstance(cls, _CaseBase):
            if cls.name in self.mutated_cases:
                return None
            parent = _BASE_PARENTS.get(cls.name)
            if parent is None:
                return (cls,)
            ancestors = self.mro(_CaseBase(parent))
            if ancestors is None:
                return None
            return (cls, *ancestors)
        if cls in self.mro_cache:
            return self.mro_cache[cls]
        if cls not in self.bases or cls in active or len(active) >= 32:
            return None
        bases = self.bases[cls]
        orders = []
        for base in bases:
            order = self.mro(base, (*active, cls))
            if order is None:
                return None
            orders.append(list(order))
        merged = _merge_c3_mro([*orders, list(bases)])
        if merged is None:
            return None
        result = (cls, *merged)
        self.mro_cache[cls] = result
        return result

    def targets(self):
        discovered = []
        for name in self.modules:
            path = self.paths[name]
            if path.suffix != ".py" or not (
                path.name.startswith("test") or path.name.endswith("_test.py")
            ):
                continue
            discovered.append(self.module(name))
        for bindings in discovered:
            for value in bindings.values():
                cls = self.resolve(value)
                if not isinstance(cls, ast.ClassDef):
                    continue
                order = self.mro(cls)
                if order is None or not any(
                    isinstance(base, _CaseBase) and base.name in _CASES
                    for base in order
                ):
                    continue
                origins = {base.name for base in order if isinstance(base, _CaseBase)}
                asynchronous = "unittest.IsolatedAsyncioTestCase" in origins
                django = "django.test.SimpleTestCase" in origins
                lifecycle = set(_LIFECYCLE)
                if asynchronous:
                    lifecycle.update({"asyncSetUp", "asyncTearDown"})
                if django:
                    lifecycle.update({"_pre_setup", "_post_teardown"})
                if "django.test.TestCase" in origins:
                    lifecycle.add("setUpTestData")
                definition = self.definition(self.class_paths[cls], cls, "class")
                if definition is not None:
                    yield definition, "unittest_discovery"
                members = {}
                for base in order:
                    for member, node in self.members.get(base, {}).items():
                        members.setdefault(member, (base, node))
                has_tests = any(
                    member.startswith("test") and isinstance(node, _FUNCTIONS)
                    for member, (_, node) in members.items()
                )
                runnable = has_tests
                if "runTest" in members and isinstance(
                    members["runTest"][1], _FUNCTIONS
                ):
                    runnable = True
                if not runnable:
                    continue
                for member, (owner, node) in members.items():
                    if not isinstance(node, _FUNCTIONS):
                        continue
                    if not (
                        member.startswith("test")
                        or member in lifecycle
                        or (member == "runTest" and not has_tests)
                    ):
                        continue
                    if member in {"asyncSetUp", "asyncTearDown"} and not isinstance(
                        node, ast.AsyncFunctionDef
                    ):
                        continue
                    if isinstance(node, ast.AsyncFunctionDef):
                        awaited = False
                        if member in {"asyncSetUp", "asyncTearDown"}:
                            awaited = asynchronous
                        elif member.startswith("test") or member == "runTest":
                            awaited = asynchronous or django
                        if not awaited:
                            continue
                    if any(
                        isinstance(child, (ast.Yield, ast.YieldFrom))
                        for statement in node.body
                        for child in _eager_nodes(statement)
                    ):
                        continue
                    target = self.definition(self.class_paths[owner], node, "method")
                    if target is not None:
                        yield target, "unittest_discovery"


def find_unittest_entrypoint_targets(definitions, parsed_files, root):
    """Discover only source-proven TestCase classes in test module layouts."""
    root = Path(root).resolve()
    if root.is_file():
        root = root.parent
    parsed = list(parsed_files)
    if not any(
        module.path.suffix == ".py"
        and (
            module.path.name.startswith("test") or module.path.name.endswith("_test.py")
        )
        for module in parsed
    ):
        return []
    discovery = _Discovery(definitions, parsed, root)
    return list(
        {
            (id(target), reason): (target, reason)
            for target, reason in discovery.targets()
        }.values()
    )
