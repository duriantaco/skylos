"""Import-proven overload declarations belonging to one callable surface."""

import ast
from dataclasses import dataclass

from skylos.rules.quality._receivers import _scope_bindings


_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_TYPING_MODULES = {"typing", "typing_extensions"}
_BINDING_DECORATORS = {"classmethod", "staticmethod"}


@dataclass(frozen=True)
class OverloadGroup:
    signatures: tuple
    implementation: ast.FunctionDef | ast.AsyncFunctionDef | None = None

    @property
    def anchor(self):
        return self.implementation or self.signatures[0]

    @property
    def members(self):
        return self.signatures + ((self.implementation,) if self.implementation else ())


def _stub(node):
    body = node.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    return len(body) == 1 and (
        isinstance(body[0], ast.Pass)
        or (
            isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and body[0].value.value is Ellipsis
        )
    )


def _escaped_names(expression):
    """Names whose values escape, without treating a member lookup as its module."""
    if isinstance(expression, ast.Name):
        return {expression.id}
    if isinstance(expression, ast.Attribute) and expression.attr == "overload":
        return _escaped_names(expression.value)
    if isinstance(expression, (ast.Starred, ast.NamedExpr)):
        return _escaped_names(expression.value)
    if isinstance(expression, (ast.List, ast.Tuple, ast.Set)):
        return set().union(*(_escaped_names(item) for item in expression.elts))
    if isinstance(expression, ast.Dict):
        return set().union(
            *(
                _escaped_names(item)
                for item in [*expression.keys, *expression.values]
                if item is not None
            )
        )
    if isinstance(expression, ast.IfExp):
        return _escaped_names(expression.body) | _escaped_names(expression.orelse)
    if isinstance(expression, ast.BoolOp):
        return set().union(*(_escaped_names(item) for item in expression.values))
    return set()


def _mutated_names(module):
    """Reject direct monkeypatching and writes routed through another scope."""
    result = set()
    aliases = {}
    builtin_modules = {"__builtins__"}
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            builtin_modules.update(
                alias.asname or alias.name
                for alias in node.names
                if alias.name == "builtins"
            )
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if isinstance(node.value, ast.Name):
                for target in targets:
                    if isinstance(target, ast.Name):
                        aliases.setdefault(target.id, set()).add(node.value.id)
            if not isinstance(node.value, ast.Name) or any(
                not isinstance(target, ast.Name) for target in targets
            ):
                result.update(_escaped_names(node.value))
        if isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)):
            result.update(_escaped_names(node.value))
        if isinstance(node, ast.Call):
            for value in [*node.args, *(keyword.value for keyword in node.keywords)]:
                result.update(_escaped_names(value))
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "vars"
                and not node.args
            ):
                result.add("*")
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            result.update(node.names)
        elif isinstance(node, ast.Attribute) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            root = node.value
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                result.add(root.id)
        elif (
            isinstance(node, ast.Attribute)
            and node.attr == "__dict__"
            and isinstance(node.value, ast.Name)
        ):
            result.add(node.value.id)
        elif (
            isinstance(node, ast.Call)
            and (
                isinstance(node.func, ast.Name)
                and node.func.id in {"setattr", "delattr", "vars"}
                or isinstance(node.func, ast.Attribute)
                and node.func.attr in {"setattr", "delattr"}
            )
            and node.args
            and isinstance(node.args[0], ast.Name)
        ):
            result.add(node.args[0].id)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"exec", "eval", "globals", "locals"}
        ):
            result.add("*")
    pending = list(result)
    while pending:
        for source in aliases.get(pending.pop(), ()):
            if source not in result:
                result.add(source)
                pending.append(source)
    if result & builtin_modules:
        result.update(_BINDING_DECORATORS)
    return result


def _imports(scope, blocked):
    result = {}
    bindings = _scope_bindings(scope)
    if "*" in bindings.names or "*" in blocked:
        return result
    for statement in scope.body:
        if isinstance(statement, ast.ImportFrom) and not statement.level:
            if statement.module not in _TYPING_MODULES:
                continue
            for alias in statement.names:
                if alias.name == "overload":
                    result[alias.asname or alias.name] = ("function", statement.lineno)
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.name in _TYPING_MODULES:
                    result[alias.asname or alias.name] = ("module", statement.lineno)
    return {
        name: evidence
        for name, evidence in result.items()
        if bindings.counts[name] == 1 and name not in blocked
    }


def _parameters(scope):
    if not isinstance(scope, _FUNCTIONS):
        return set()
    args = scope.args
    names = {arg.arg for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
    names.update(arg.arg for arg in (args.vararg, args.kwarg) if arg is not None)
    return names


def _is_overload(node, aliases, blocked):
    proved = False
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Name):
            binding = aliases.get(decorator.id)
            if binding and binding[0] == "function" and binding[1] < decorator.lineno:
                proved = True
            elif decorator.id not in {"classmethod", "staticmethod"} or (
                decorator.id in blocked
            ):
                return False
        elif (
            isinstance(decorator, ast.Attribute)
            and isinstance(decorator.value, ast.Name)
            and decorator.attr == "overload"
            and (binding := aliases.get(decorator.value.id))
            and binding[0] == "module"
            and binding[1] < decorator.lineno
        ):
            proved = True
        else:
            return False
    return proved and _stub(node)


def _plain_implementation(node, blocked):
    return not _stub(node) and all(
        isinstance(decorator, ast.Name)
        and decorator.id in {"classmethod", "staticmethod"}
        and decorator.id not in blocked
        for decorator in node.decorator_list
    )


def overload_groups(module, *, filename=""):
    """Keep unknown decorators, shadowed imports and incomplete .py groups intact.

    Only consecutive declarations in the same statement list can form a group.
    A runtime module needs its implementation; a .pyi file may contain only the
    type declarations. Nested lexical scopes have independent alias bindings.
    """
    groups = []
    mutated = _mutated_names(module)
    stub_file = str(filename).endswith(".pyi")

    def scan_scope(scope, inherited, inherited_builtin_blocks=frozenset()):
        bindings = _scope_bindings(scope)
        parameters = _parameters(scope)
        builtin_blocks = inherited_builtin_blocks | (
            (bindings.names | parameters) & _BINDING_DECORATORS
        )
        blocked = bindings.names | parameters | mutated | inherited_builtin_blocks
        aliases = {
            name: evidence
            for name, evidence in inherited.items()
            if name not in blocked
        }
        if "*" in bindings.names or "*" in mutated:
            aliases.clear()
        aliases.update(_imports(scope, mutated))

        def scan_body(body):
            index = 0
            while index < len(body):
                first = body[index]
                if isinstance(first, _FUNCTIONS) and _is_overload(
                    first, aliases, blocked
                ):
                    signatures = [first]
                    end = index + 1
                    while end < len(body):
                        following = body[end]
                        if not (
                            isinstance(following, type(first))
                            and following.name == first.name
                            and _is_overload(following, aliases, blocked)
                        ):
                            break
                        signatures.append(following)
                        end += 1
                    implementation = None
                    if end < len(body):
                        candidate = body[end]
                        if (
                            isinstance(candidate, type(first))
                            and candidate.name == first.name
                            and _plain_implementation(candidate, blocked)
                        ):
                            implementation = candidate
                    if implementation is not None or (
                        stub_file and len(signatures) > 1
                    ):
                        groups.append(OverloadGroup(tuple(signatures), implementation))
                    index = end
                    continue
                if isinstance(first, (*_FUNCTIONS, ast.ClassDef)):
                    # A method's body and a nested class do not close over the
                    # surrounding class namespace.
                    scan_scope(
                        first,
                        inherited if isinstance(scope, ast.ClassDef) else aliases,
                        inherited_builtin_blocks
                        if isinstance(scope, ast.ClassDef)
                        else builtin_blocks,
                    )
                else:
                    # A branch is a statement list, not a new lexical scope.
                    for _field, value in ast.iter_fields(first):
                        if (
                            isinstance(value, list)
                            and value
                            and all(isinstance(item, ast.stmt) for item in value)
                        ):
                            scan_body(value)
                        elif isinstance(value, list):
                            for item in value:
                                if isinstance(
                                    item, (ast.ExceptHandler, ast.match_case)
                                ):
                                    scan_body(item.body)
                index += 1

        scan_body(scope.body)

    scan_scope(module, {})
    return tuple(groups)


def redundant_overload_definitions(module, *, filename=""):
    """Declarations that repeat an already-counted callable, never its anchor."""
    return {
        signature
        for group in overload_groups(module, filename=filename)
        for signature in group.signatures
        if signature is not group.anchor
    }
