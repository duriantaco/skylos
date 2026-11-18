"""Finite native unittest contracts, without trusting a test filename.

TestCase calls its lifecycle hooks; it does not supply arbitrary arguments to
other helper methods or overwrite arbitrary fixture attributes. Custom dispatch,
provider replacement, instance escape and unknown bases invalidate this model.
"""

from __future__ import annotations

import ast

from skylos.rules.danger.import_proof import provider_binding_is_stable
from skylos.rules.danger.module_namespace import attribute_write_names

_DISPATCH = frozenset(
    {
        "__new__",
        "__init__",
        "__getattribute__",
        "__getattr__",
        "__setattr__",
        "__delattr__",
        "__call__",
        "__init_subclass__",
        "run",
        "debug",
        "_callTestMethod",
        "_callSetUp",
        "_callTearDown",
        "_callCleanup",
        "doCleanups",
    }
)
_HOOKS = _DISPATCH | frozenset({"setUp", "tearDown", "setUpClass", "tearDownClass"})


def native_testcase(project, cls):
    cache = getattr(project, "_native_testcase_contexts", None)
    if cache is None:
        cache = project._native_testcase_contexts = {}
    if id(cls) in cache:
        return cache[id(cls)]
    cache[id(cls)] = False
    order, external = project.mro(cls)
    if not external or set(external) != {"unittest.TestCase"}:
        return False
    for unit, candidate in order:
        if candidate.keywords or candidate.decorator_list:
            return False
        dynamic, _ = unit.rebinding()
        _, computed = attribute_write_names(unit.tree)
        if dynamic or computed:
            return False
        if unit.module.binds.get("load_tests") or not all(
            provider_binding_is_stable(name, unit.tree, unit.path, project.root)
            for name in (
                "unittest.TestCase",
                "unittest.TestLoader",
                "unittest.defaultTestLoader",
            )
        ):
            return False
        bindings = project.class_statements(candidate)
        if any(name in bindings for name in _DISPATCH):
            return False
        for method in candidate.body:
            if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            static = False
            for decorator in method.decorator_list:
                values = project.values(unit, unit.scope_of(decorator), decorator)
                if not values or any(
                    value.kind != "ext"
                    or value.name
                    not in {"builtins.staticmethod", "builtins.classmethod"}
                    for value in values
                ):
                    return False
                if not all(
                    provider_binding_is_stable(
                        value.name, unit.tree, unit.path, project.root
                    )
                    for value in values
                ):
                    return False
                static |= all(value.name == "builtins.staticmethod" for value in values)
            if static:
                continue
            positional = [*method.args.posonlyargs, *method.args.args]
            if not positional:
                continue
            receiver = positional[0].arg
            aliases = set()

            def fixture_value(expression, aliases=aliases, receiver=receiver):
                return any(
                    isinstance(part, ast.Name) and part.id in aliases | {receiver}
                    for part in ast.walk(expression)
                )

            changed = True
            while changed:
                changed = False
                for statement in ast.walk(method):
                    if (
                        not isinstance(statement, (ast.Assign, ast.AnnAssign))
                        or statement.value is None
                    ):
                        continue
                    targets = (
                        statement.targets
                        if isinstance(statement, ast.Assign)
                        else [statement.target]
                    )
                    if fixture_value(statement.value):
                        for target in targets:
                            if (
                                isinstance(target, ast.Name)
                                and target.id not in aliases
                            ):
                                aliases.add(target.id)
                                changed = True
            cleanup_aliases = set()
            changed = True
            while changed:
                changed = False
                for statement in ast.walk(method):
                    if (
                        not isinstance(statement, (ast.Assign, ast.AnnAssign))
                        or statement.value is None
                    ):
                        continue
                    cleanup_value = any(
                        isinstance(part, ast.Attribute)
                        and part.attr in {"cleanup", "__exit__"}
                        and fixture_value(part.value)
                        or isinstance(part, ast.Name)
                        and part.id in cleanup_aliases
                        for part in ast.walk(statement.value)
                    )
                    if not cleanup_value:
                        continue
                    targets = (
                        statement.targets
                        if isinstance(statement, ast.Assign)
                        else [statement.target]
                    )
                    for target in targets:
                        for part in ast.walk(target):
                            if (
                                isinstance(part, ast.Name)
                                and part.id not in cleanup_aliases
                            ):
                                cleanup_aliases.add(part.id)
                                changed = True
            for call in ast.walk(method):
                if not isinstance(call, ast.Call) or not any(
                    fixture_value(argument)
                    for argument in [
                        *call.args,
                        *(keyword.value for keyword in call.keywords),
                    ]
                ):
                    continue
                targets = project.values(unit, unit.scope_of(call), call.func)
                native = bool(targets) and all(
                    value.kind == "ext"
                    and value.name
                    in {
                        "pathlib.Path",
                        "pathlib.PosixPath",
                        "pathlib.WindowsPath",
                        "builtins.str",
                        "builtins.int",
                        "builtins.float",
                        "builtins.bool",
                        "builtins.len",
                        "builtins.isinstance",
                    }
                    and provider_binding_is_stable(
                        value.name, unit.tree, unit.path, project.root
                    )
                    for value in targets
                )
                if (
                    isinstance(call.func, ast.Attribute)
                    and isinstance(call.func.value, ast.Name)
                    and call.func.value.id == receiver
                ):
                    member = call.func.attr
                    if (
                        member.startswith("assert") or member == "addCleanup"
                    ) and not any(
                        member in project.class_statements(base)
                        for _source, base in order
                    ):
                        native = provider_binding_is_stable(
                            "unittest.TestCase." + member,
                            unit.tree,
                            unit.path,
                            project.root,
                        )
                if not native:
                    return False
            for node in ast.walk(method):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in cleanup_aliases
                    and method.name not in {"tearDown", "tearDownClass"}
                ):
                    return False
                if (
                    isinstance(node, ast.Attribute)
                    and node.attr
                    in {
                        "chmod",
                        "lchmod",
                        "chown",
                        "lchown",
                        "rename",
                        "replace",
                        "rmdir",
                        "unlink",
                    }
                    and fixture_value(node.value)
                ):
                    return False
                if (
                    node is not method
                    and isinstance(
                        node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
                    )
                    and fixture_value(node)
                ):
                    return False
                if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
                    node.ctx, (ast.Store, ast.Del)
                ):
                    receiver_value = node.value
                    if not (
                        isinstance(receiver_value, ast.Name)
                        and receiver_value.id == receiver
                    ) and fixture_value(receiver_value):
                        return False
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if (
                        isinstance(node.func.value, ast.Name)
                        and node.func.value.id == receiver
                        and node.func.attr in _HOOKS
                    ):
                        return False
                    if (
                        node.func.attr in {"cleanup", "__exit__"}
                        and fixture_value(node.func.value)
                        and method.name not in {"tearDown", "tearDownClass"}
                    ):
                        return False
            for node in ast.walk(method):
                if (
                    not isinstance(node, ast.Name)
                    or node.id != receiver
                    or not isinstance(node.ctx, ast.Load)
                ):
                    continue
                parent = unit.parents.get(id(node))
                if not isinstance(parent, ast.Attribute) or parent.attr in {
                    "__dict__",
                    "__class__",
                    "__getattribute__",
                    "__setattr__",
                }:
                    return False
                if isinstance(parent.ctx, ast.Load):
                    values = project.values(unit, unit.scope_of(parent), parent)
                    if values and any(value.kind == "fn" for value in values):
                        operation = unit.parents.get(id(parent))
                        if (
                            not isinstance(operation, ast.Call)
                            or operation.func is not parent
                        ):
                            return False
    cache[id(cls)] = True
    return True


def implicit_helper_call_is_excluded(project, cls, function):
    return (
        function.name not in _HOOKS
        and not function.name.startswith("test")
        and not function.name.startswith("__")
        and native_testcase(project, cls)
    )


def implicit_attribute_write_is_excluded(project, cls, attribute):
    return (
        not attribute.startswith("_")
        and attribute not in {"failureException", "longMessage", "maxDiff"}
        and native_testcase(project, cls)
    )
