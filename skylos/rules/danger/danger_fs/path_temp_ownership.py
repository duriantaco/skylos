"""Detect changes to a native temporary context's actual private root.

A mode change to a descendant does not remove the owner's private ancestor.
Root aliases are followed separately from descendant pathname expressions.
"""

from __future__ import annotations

import ast

from skylos.rules.danger.import_proof import provider_binding_is_stable

_ROOT_WRAPPERS = {
    "builtins.str",
    "os.fspath",
    "os.path.abspath",
    "os.path.realpath",
    "pathlib.Path",
    "pathlib.PosixPath",
    "pathlib.WindowsPath",
}
_MUTATORS = {
    "chmod",
    "lchmod",
    "chown",
    "lchown",
    "rename",
    "replace",
    "rmdir",
    "unlink",
}
_OS_MUTATORS = {"os." + member for member in _MUTATORS}
_PATH_READONLY = {
    "write_text",
    "write_bytes",
    "read_text",
    "read_bytes",
    "open",
    "mkdir",
    "exists",
    "is_file",
    "is_dir",
    "stat",
    "lstat",
    "joinpath",
    "resolve",
    "absolute",
    "as_posix",
}
_SCALAR_METHODS = {
    "write_text",
    "write_bytes",
    "read_text",
    "read_bytes",
    "mkdir",
    "exists",
    "is_file",
    "is_dir",
    "stat",
    "lstat",
}
_NATIVE_READONLY = _ROOT_WRAPPERS | {
    "builtins.open",
    "builtins.len",
    "builtins.int",
    "builtins.float",
    "builtins.bool",
    "builtins.isinstance",
}
_MAX_EFFECT_WORK = 4096
_MAX_EFFECT_DEPTH = 16


def context_root_was_changed(
    project, unit, owner, bind, name, *, seed=None, aliases=()
):
    cache = getattr(project, "_temporary_context_mutations", None)
    if cache is None:
        cache = project._temporary_context_mutations = {}
    key = (id(unit), id(owner), id(bind), name, id(seed))
    if key in cache:
        return cache[key]
    work = 0
    incomplete = False
    seed_text = ast.dump(seed) if seed is not None else None
    helpers = {}

    def native_readonly(values, call, call_unit=unit):
        if any(isinstance(argument, ast.Starred) for argument in call.args):
            return False
        if (
            values
            and any(
                value.kind == "ext" and value.name == "builtins.open"
                for value in values
            )
            and len(call.args) > 7
            and not (
                isinstance(call.args[7], ast.Constant) and call.args[7].value is None
            )
        ):
            return False
        return (
            bool(values)
            and all(
                value.kind == "ext"
                and value.name in _NATIVE_READONLY
                and provider_binding_is_stable(
                    value.name, call_unit.tree, call_unit.path, project.root
                )
                for value in values
            )
            and not any(
                keyword.arg is None
                or keyword.arg == "opener"
                and not (
                    isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is None
                )
                for keyword in call.keywords
            )
        )

    def root(expression, scope, active=()):
        nonlocal work, incomplete
        work += 1
        if work > _MAX_EFFECT_WORK or len(active) > 24:
            incomplete = True
            return True  # An exhausted alias proof cannot preserve ownership.
        if (
            seed_text is not None
            and ast.dump(expression) == seed_text
            and unit.scope_of(expression) is owner
        ):
            return True
        if (
            seed is not None
            and isinstance(expression, ast.Attribute)
            and expression.attr == seed.attr
            and isinstance(expression.value, ast.Name)
            and expression.value.id in aliases
        ):
            found = unit.lookup(scope, expression.value.id)
            if found is not None and found[0] is owner:
                return True
        if isinstance(expression, ast.Name):
            found = unit.lookup(scope, expression.id)
            if found is None:
                return False
            target_scope, bindings = found
            if target_scope is owner and expression.id == name:
                return True
            marker = (id(target_scope), expression.id)
            if marker in active:
                incomplete = True
                return True
            return any(
                binding.kind in {"assign", "unpack", "augassign"}
                and root(binding.value, binding.scope, (*active, marker))
                for binding in bindings
            )
        if (
            isinstance(expression, ast.Call)
            and len(expression.args) == 1
            and not expression.keywords
        ):
            values = project.values(unit, scope, expression.func)
            return (
                bool(values)
                and all(
                    value.kind == "ext" and value.name in _ROOT_WRAPPERS
                    for value in values
                )
                and root(expression.args[0], scope, active)
            )
        return False

    def reachable(expression, scope, active=()):
        nonlocal incomplete
        if isinstance(expression, ast.Name):
            found = unit.lookup(scope, expression.id)
            if found is not None:
                marker = (id(found[0]), expression.id)
                if marker in active or len(active) > 24:
                    incomplete = True
                    return True
                if any(
                    binding.kind in {"assign", "unpack", "augassign"}
                    and reachable(binding.value, binding.scope, (*active, marker))
                    for binding in found[1]
                ):
                    return True
        return root(expression, scope) or any(
            root(part, unit.scope_of(part))
            for part in ast.walk(expression)
            if part is not expression
            and isinstance(part, (ast.Name, ast.Attribute, ast.Call))
        )

    def helper_preserves(
        target, call, source_scope, relevant, depth=0, active=(), call_unit=unit
    ):
        nonlocal work, incomplete
        from .path_provenance import _function_params, _Site

        if target.kind != "fn":
            return False
        if depth > _MAX_EFFECT_DEPTH or id(target.node) in active:
            incomplete = True
            return False
        for decorator in target.node.decorator_list:
            values = project.values(
                target.unit, target.unit.scope_of(decorator), decorator
            )
            if not values or not all(
                value.kind == "ext"
                and value.name in {"builtins.staticmethod", "builtins.classmethod"}
                and provider_binding_is_stable(
                    value.name, target.unit.tree, target.unit.path, project.root
                )
                for value in values
            ):
                return False
        site = _Site(
            call_unit,
            source_scope,
            call,
            list(call.args),
            list(call.keywords),
            target.bound,
            "call",
        )
        names = {
            argument.arg
            for argument in _function_params(target.node)
            if any(
                expr_unit is call_unit and relevant(expr, expr_scope)
                for expr, expr_unit, expr_scope in project.bind_argument(
                    target.node, site, argument.arg
                )
            )
        }
        if not names and any(
            relevant(argument, source_scope)
            for argument in [*call.args, *[keyword.value for keyword in call.keywords]]
        ):
            return False
        result_discarded = isinstance(call_unit.parents.get(id(call)), ast.Expr)
        key = (id(target.node), frozenset(names), result_discarded)
        if key in helpers:
            return helpers[key]
        helpers[key] = False
        info = project.function_info.get(id(target.node))
        if info is None:
            return False
        helper_unit, helper_scope = info[:2]
        if helper_scope.globals or helper_scope.nonlocals:
            return False

        def derived(expression, _scope=None):
            return any(
                isinstance(part, ast.Name) and part.id in names
                for part in ast.walk(expression)
            )

        changed = True
        nodes = list(ast.walk(target.node))
        while changed:
            changed = False
            for node in nodes:
                work += 1
                if work > _MAX_EFFECT_WORK:
                    incomplete = True
                    return False
                if (
                    isinstance(node, (ast.Assign, ast.AnnAssign))
                    and node.value is not None
                    and derived(node.value)
                ):
                    targets = (
                        node.targets if isinstance(node, ast.Assign) else [node.target]
                    )
                    for stored in targets:
                        if not isinstance(stored, ast.Name):
                            return False
                        if stored.id not in names:
                            names.add(stored.id)
                            changed = True
        for node in nodes:
            if (
                isinstance(node, (ast.Attribute, ast.Subscript))
                and isinstance(node.ctx, (ast.Store, ast.Del))
                and derived(node.value)
            ):
                return False
            if (
                node is not target.node
                and isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
                )
                and derived(node)
            ):
                return False
            if (
                not result_discarded
                and isinstance(node, ast.Return)
                and node.value is not None
                and derived(node.value)
            ):
                value = node.value
                if not (
                    isinstance(value, ast.Compare)
                    or isinstance(value, ast.Call)
                    and isinstance(value.func, ast.Attribute)
                    and value.func.attr in _SCALAR_METHODS
                ):
                    return False
            if not isinstance(node, ast.Call):
                continue
            arguments = [*node.args, *[keyword.value for keyword in node.keywords]]
            receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
            has_receiver = receiver is not None and derived(receiver)
            carries_root = any(derived(argument) for argument in arguments)
            if not has_receiver and not carries_root and not derived(node.func):
                continue
            if has_receiver and node.func.attr in _MUTATORS:
                return False
            if has_receiver and node.func.attr in _PATH_READONLY:
                if not all(
                    provider_binding_is_stable(
                        name, helper_unit.tree, helper_unit.path, project.root
                    )
                    for name in (
                        "pathlib.Path",
                        "pathlib.PosixPath",
                        "pathlib.WindowsPath",
                        "io.open",
                    )
                ):
                    return False
                continue
            functions = project.values(
                helper_unit, helper_unit.scope_of(node), node.func
            )
            if native_readonly(functions, node, helper_unit):
                continue
            if not functions or not all(
                helper_preserves(
                    value,
                    node,
                    helper_unit.scope_of(node),
                    derived,
                    depth + 1,
                    (*active, id(target.node)),
                    helper_unit,
                )
                for value in functions
            ):
                return False
        helpers[key] = True
        return True

    changed = False
    for statement in ast.walk(unit.tree):
        if (
            isinstance(statement, (ast.Attribute, ast.Subscript))
            and isinstance(statement.ctx, (ast.Store, ast.Del))
            and reachable(statement.value, unit.scope_of(statement.value))
        ):
            changed = True
            break
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
        if any(not isinstance(target, ast.Name) for target in targets) and reachable(
            statement.value, unit.scope_of(statement.value)
        ):
            changed = True
            break
    for reference, scope in () if changed else unit.loads:
        if (
            isinstance(reference, ast.Attribute)
            and reference.attr in _MUTATORS
            and root(reference.value, scope)
        ):
            changed = True
            break
    for call, scope in () if changed else unit.calls:
        values = project.values(unit, scope, call.func)
        arguments = [*call.args, *[keyword.value for keyword in call.keywords]]
        native_mutator = values and any(
            value.kind == "ext" and value.name in _OS_MUTATORS for value in values
        )
        replacement = isinstance(call.func, ast.Attribute) and call.func.attr in {
            "replace",
            "rename",
        }
        if (native_mutator or replacement) and any(
            root(argument, scope) for argument in arguments
        ):
            changed = True
            break
        if any(reachable(argument, scope) for argument in arguments):
            if native_mutator:
                # Descendant permission changes retain the private ancestor.
                continue
            if native_readonly(values, call):
                continue
            if not values or not all(
                helper_preserves(value, call, scope, reachable) for value in values
            ):
                changed = True
                break
    result = "incomplete" if incomplete else changed
    cache[key] = result
    return result
