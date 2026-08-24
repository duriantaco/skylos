import ast
import operator
from pathlib import Path

from skylos.rules.base import SkylosRule

MUTABLE_CONSTRUCTORS = {
    "list",
    "dict",
    "set",
    "defaultdict",
    "OrderedDict",
    "Counter",
    "deque",
    "array",
}


def _string_literal_value(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value

    value = getattr(node, "value", None)
    if isinstance(value, str):
        return value

    return None


class MutableDefaultRule(SkylosRule):
    rule_id = "SKY-L001"
    name = "Mutable Default Argument"

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None

        findings = []

        kw_defaults_filtered = []
        for d in node.args.kw_defaults:
            if d:
                kw_defaults_filtered.append(d)

        for default in node.args.defaults + kw_defaults_filtered:
            is_mutable = False

            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                is_mutable = True

            elif isinstance(default, (ast.ListComp, ast.DictComp, ast.SetComp)):
                is_mutable = True

            elif isinstance(default, ast.Call):
                if isinstance(default.func, ast.Name):
                    if default.func.id in MUTABLE_CONSTRUCTORS:
                        is_mutable = True

            if is_mutable:
                findings.append(
                    {
                        "rule_id": self.rule_id,
                        "kind": "logic",
                        "severity": "HIGH",
                        "type": "function",
                        "name": node.name,
                        "simple_name": node.name,
                        "value": "mutable",
                        "threshold": 0,
                        "message": "Mutable default argument detected. This causes state leaks between calls.",
                        "file": context.get("filename"),
                        "basename": Path(context.get("filename", "")).name,
                        "line": default.lineno,
                        "col": default.col_offset,
                    }
                )

        if findings:
            return findings
        return None


_MUTABLE_REPEAT_ELEMENTS = (
    ast.List,
    ast.Dict,
    ast.Set,
    ast.ListComp,
    ast.DictComp,
    ast.SetComp,
)
_BUILTIN_MUTABLE_REPEAT_CONSTRUCTORS = {"dict", "list", "set"}

_UNKNOWN_REPEAT_COUNT = object()
_NON_INTEGER_REPEAT_COUNT = object()
_MAX_STATIC_REPEAT_NODES = 16
_MAX_STATIC_REPEAT_BITS = 128
_MAX_PROVEN_SEQUENCE_NODES = 128

_STATIC_REPEAT_UNARY_OPS = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
    ast.Invert: operator.invert,
}
_STATIC_REPEAT_BINARY_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.LShift: operator.lshift,
    ast.RShift: operator.rshift,
    ast.BitOr: operator.or_,
    ast.BitXor: operator.xor,
    ast.BitAnd: operator.and_,
}


def _static_repeat_count(node: ast.AST):
    """Evaluate a small, bounded subset of constant integer expressions."""
    remaining = [_MAX_STATIC_REPEAT_NODES]

    def evaluate(current: ast.AST):
        remaining[0] -= 1
        if remaining[0] < 0:
            return _UNKNOWN_REPEAT_COUNT

        if isinstance(current, ast.Constant):
            value = current.value
            if type(value) is not int:
                return int(value) if type(value) is bool else _NON_INTEGER_REPEAT_COUNT
        elif isinstance(current, ast.UnaryOp):
            operation = _STATIC_REPEAT_UNARY_OPS.get(type(current.op))
            operands = (evaluate(current.operand),)
        elif isinstance(current, ast.BinOp):
            operation = _STATIC_REPEAT_BINARY_OPS.get(type(current.op))
            operands = (evaluate(current.left), evaluate(current.right))
        else:
            return _UNKNOWN_REPEAT_COUNT

        if isinstance(current, ast.Constant):
            result = current.value
        elif operation is None or any(
            value is _UNKNOWN_REPEAT_COUNT for value in operands
        ):
            return _UNKNOWN_REPEAT_COUNT
        elif any(value is _NON_INTEGER_REPEAT_COUNT for value in operands):
            return _NON_INTEGER_REPEAT_COUNT
        else:
            if isinstance(current, ast.BinOp) and isinstance(
                current.op, (ast.LShift, ast.RShift)
            ):
                left, right = operands
                if right < 0:
                    return _NON_INTEGER_REPEAT_COUNT
                if isinstance(current.op, ast.LShift):
                    if left == 0:
                        return 0
                    if left < 0 and (
                        right > _MAX_STATIC_REPEAT_BITS
                        or left.bit_length() + right > _MAX_STATIC_REPEAT_BITS
                    ):
                        return -1
                    if (
                        right > _MAX_STATIC_REPEAT_BITS
                        or left.bit_length() + right > _MAX_STATIC_REPEAT_BITS
                    ):
                        return _UNKNOWN_REPEAT_COUNT
                elif right > _MAX_STATIC_REPEAT_BITS:
                    return 0 if left >= 0 else -1
            try:
                result = operation(*operands)
            except (ArithmeticError, ValueError):
                return _NON_INTEGER_REPEAT_COUNT

        if type(result) is bool:
            result = int(result)
        if type(result) is not int:
            return _NON_INTEGER_REPEAT_COUNT
        if result.bit_length() > _MAX_STATIC_REPEAT_BITS:
            return _UNKNOWN_REPEAT_COUNT
        return result

    return evaluate(node)


def _repeat_count_may_be_integer(node: ast.AST) -> bool:
    return _static_repeat_count(node) is not _NON_INTEGER_REPEAT_COUNT


def _starred_contains_proven_mutable_element(
    node: ast.AST,
    cache: dict[ast.AST, tuple[type[ast.AST], bool] | None],
    *,
    builtin_bool_calls: set[ast.Call],
    builtin_mutable_constructor_calls: set[ast.Call],
    bool_count_loads: set[ast.Name],
    budget: list[int],
) -> bool:
    """Return whether unpacking *node can emit a known mutable value."""
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(
            _contains_proven_mutable_element(
                element,
                cache,
                builtin_bool_calls=builtin_bool_calls,
                builtin_mutable_constructor_calls=builtin_mutable_constructor_calls,
                bool_count_loads=bool_count_loads,
                budget=budget,
            )
            for element in node.elts
        )
    if isinstance(node, ast.Dict):
        return any(
            _contains_proven_mutable_element(
                key,
                cache,
                builtin_bool_calls=builtin_bool_calls,
                builtin_mutable_constructor_calls=builtin_mutable_constructor_calls,
                bool_count_loads=bool_count_loads,
                budget=budget,
            )
            for key in node.keys
            if key is not None
        )
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
        return _contains_proven_mutable_element(
            node.elt,
            cache,
            builtin_bool_calls=builtin_bool_calls,
            builtin_mutable_constructor_calls=builtin_mutable_constructor_calls,
            bool_count_loads=bool_count_loads,
            budget=budget,
        )
    if isinstance(node, ast.DictComp):
        return _contains_proven_mutable_element(
            node.key,
            cache,
            builtin_bool_calls=builtin_bool_calls,
            builtin_mutable_constructor_calls=builtin_mutable_constructor_calls,
            bool_count_loads=bool_count_loads,
            budget=budget,
        )

    fact = _proven_sequence_fact(
        node,
        cache,
        builtin_bool_calls=builtin_bool_calls,
        builtin_mutable_constructor_calls=builtin_mutable_constructor_calls,
        bool_count_loads=bool_count_loads,
        _budget=budget,
    )
    return fact is not None and fact[1]


def _contains_proven_mutable_element(
    node: ast.AST,
    cache: dict[ast.AST, tuple[type[ast.AST], bool] | None],
    *,
    builtin_bool_calls: set[ast.Call],
    builtin_mutable_constructor_calls: set[ast.Call],
    bool_count_loads: set[ast.Name],
    budget: list[int],
) -> bool:
    stack = [(node, budget[0])]
    while stack:
        current, remaining = stack.pop()
        if isinstance(current, _MUTABLE_REPEAT_ELEMENTS) or (
            isinstance(current, ast.Call)
            and current in builtin_mutable_constructor_calls
        ):
            return True
        if isinstance(current, ast.Starred):
            if remaining <= 0:
                continue
            if _starred_contains_proven_mutable_element(
                current.value,
                cache,
                builtin_bool_calls=builtin_bool_calls,
                builtin_mutable_constructor_calls=builtin_mutable_constructor_calls,
                bool_count_loads=bool_count_loads,
                budget=[remaining - 1],
            ):
                return True
            continue
        if isinstance(current, ast.Tuple):
            if remaining <= 0:
                continue
            stack.extend((element, remaining - 1) for element in current.elts)
            continue
        if isinstance(current, ast.BinOp) and isinstance(
            current.op, (ast.Add, ast.Mult)
        ):
            if remaining <= 0:
                continue
            fact = _proven_sequence_fact(
                current,
                cache,
                builtin_bool_calls=builtin_bool_calls,
                builtin_mutable_constructor_calls=builtin_mutable_constructor_calls,
                bool_count_loads=bool_count_loads,
                _budget=[remaining],
            )
            if fact is not None and (fact[0] is ast.List or fact[1]):
                return True
    return False


def _proven_sequence_fact(
    node: ast.AST,
    cache: dict[ast.AST, tuple[type[ast.AST], bool] | None],
    *,
    builtin_bool_calls: set[ast.Call] | None = None,
    builtin_mutable_constructor_calls: set[ast.Call] | None = None,
    bool_count_loads: set[ast.Name] | None = None,
    _budget: list[int] | None = None,
) -> tuple[type[ast.AST], bool] | None:
    builtin_bool_calls = builtin_bool_calls or set()
    builtin_mutable_constructor_calls = builtin_mutable_constructor_calls or set()
    bool_count_loads = bool_count_loads or set()
    budget = _budget if _budget is not None else [_MAX_PROVEN_SEQUENCE_NODES]
    if node in cache:
        return cache[node]
    stack = [(node, False)]
    touched: list[ast.AST] = []
    while stack:
        current, closing = stack.pop()
        if current in cache:
            continue
        if budget[0] <= 0:
            for pending in touched:
                cache.setdefault(pending, None)
            return None
        if not closing:
            budget[0] -= 1
            touched.append(current)
            if isinstance(current, (ast.List, ast.Tuple)):
                cache[current] = (
                    type(current),
                    any(
                        _contains_proven_mutable_element(
                            element,
                            cache,
                            builtin_bool_calls=builtin_bool_calls,
                            builtin_mutable_constructor_calls=builtin_mutable_constructor_calls,
                            bool_count_loads=bool_count_loads,
                            budget=[_MAX_PROVEN_SEQUENCE_NODES],
                        )
                        for element in current.elts
                    ),
                )
                continue
            if not isinstance(current, ast.BinOp) or not isinstance(
                current.op, (ast.Add, ast.Mult)
            ):
                cache[current] = None
                continue
            stack.append((current, True))
            stack.append((current.right, False))
            stack.append((current.left, False))
            continue

        left = cache.get(current.left)
        right = cache.get(current.right)
        if isinstance(current.op, ast.Add):
            cache[current] = (
                (left[0], left[1] or right[1])
                if left is not None and right is not None and left[0] is right[0]
                else None
            )
            continue
        if (left is None) == (right is None):
            cache[current] = None
            continue
        sequence, count = (
            (left, current.right) if left is not None else (right, current.left)
        )
        count_value = _static_repeat_count(count)
        if count_value == 1:
            cache[current] = sequence
        elif isinstance(count_value, int) and count_value <= 0:
            cache[current] = sequence[0], False
        elif count_value is _NON_INTEGER_REPEAT_COUNT:
            cache[current] = None
        elif (
            not sequence[1] and _repeat_count_may_be_integer(count)
        ) or not _repeat_count_can_alias(
            count,
            builtin_bool_calls=builtin_bool_calls,
            bool_count_loads=bool_count_loads,
        ):
            cache[current] = sequence
        else:
            cache[current] = None
    return cache.get(node)


def _repeat_count_can_alias(
    node: ast.AST,
    *,
    builtin_bool_calls: set[ast.Call],
    bool_count_loads: set[ast.Name] | None = None,
) -> bool:
    if bool_count_loads is not None and node in bool_count_loads:
        return False
    if isinstance(node, (ast.Compare, ast.UnaryOp)) and (
        isinstance(node, ast.Compare) or isinstance(node.op, ast.Not)
    ):
        return False
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "bool"
        and node in builtin_bool_calls
    ):
        return False
    value = _static_repeat_count(node)
    if value is _UNKNOWN_REPEAT_COUNT:
        return True
    if isinstance(value, int):
        return value > 1
    return False


def _is_exact_bool_annotation(node: ast.AST | None) -> bool:
    return (isinstance(node, ast.Name) and node.id == "bool") or (
        isinstance(node, ast.Constant) and node.value == "bool"
    )


def _has_statically_aliasing_default(node: ast.AST) -> bool:
    value = _static_repeat_count(node)
    return isinstance(value, int) and value > 1


def _import_binding(alias: ast.alias, *, from_import: bool) -> str:
    if alias.asname:
        return alias.asname
    return alias.name if from_import else alias.name.split(".", 1)[0]


class _BoolScope:
    __slots__ = (
        "annotation_bool_shadowed",
        "binding_positions",
        "bool_calls",
        "bound_names",
        "global_names",
        "kind",
        "mutable_constructor_calls",
        "name_loads",
        "nonlocal_names",
        "nonlocal_writes",
        "owner",
        "parent",
        "type_param_names",
        "typed_bool_names",
        "typing_parent",
        "walrus_owner",
        "wildcard_import",
        "written_names",
    )

    def __init__(
        self,
        kind: str,
        parent: "_BoolScope | None",
        owner: ast.AST | None = None,
    ):
        self.kind = kind
        self.parent = parent
        self.owner = owner
        self.typing_parent = parent
        self.walrus_owner = self
        self.bound_names: set[str] = set()
        self.global_names: set[str] = set()
        self.nonlocal_names: set[str] = set()
        self.nonlocal_writes: set[str] = set()
        self.wildcard_import = False
        self.binding_positions: dict[str, list[tuple[int, int] | None]] = {}
        self.bool_calls: list[ast.Call] = []
        self.mutable_constructor_calls: list[ast.Call] = []
        self.name_loads: list[ast.Name] = []
        self.typed_bool_names: set[str] = set()
        self.type_param_names: set[str] = set()
        self.written_names: set[str] = set()
        self.annotation_bool_shadowed = False


def _non_class_parent(scope: _BoolScope) -> _BoolScope:
    current = scope
    while current.kind == "class" and current.parent is not None:
        current = current.parent
    return current


_UNKNOWN_NAME_OWNER = object()


def _type_parameter_names(node: ast.AST) -> set[str]:
    names = set()
    for parameter in getattr(node, "type_params", ()):
        name = getattr(parameter, "name", None)
        if isinstance(name, str):
            names.add(name)
        elif isinstance(name, ast.Name):
            names.add(name.id)
    return names


def _scope_declarations(statements: list[ast.stmt]) -> tuple[set[str], set[str]]:
    """Collect declarations belonging to one statement scope."""
    global_names: set[str] = set()
    nonlocal_names: set[str] = set()
    stack: list[ast.AST] = list(reversed(statements))
    nested_scopes = (
        ast.FunctionDef,
        ast.AsyncFunctionDef,
        ast.ClassDef,
        ast.Lambda,
        ast.ListComp,
        ast.SetComp,
        ast.DictComp,
        ast.GeneratorExp,
    )
    while stack:
        current = stack.pop()
        if isinstance(current, ast.Global):
            global_names.update(current.names)
            continue
        if isinstance(current, ast.Nonlocal):
            nonlocal_names.update(current.names)
            continue
        if isinstance(current, nested_scopes):
            continue
        stack.extend(ast.iter_child_nodes(current))
    return global_names, nonlocal_names


def _node_position(node: ast.AST) -> tuple[int, int]:
    return getattr(node, "lineno", 0), getattr(node, "col_offset", 0)


def _scope_statement_position(
    node: ast.AST,
    scope: _BoolScope,
    parents: dict[ast.AST, ast.AST],
) -> tuple[int, int] | None:
    """Return the direct module/class statement containing a node."""
    if scope.owner is None:
        return None
    current = node
    while current in parents:
        parent = parents[current]
        if parent is scope.owner:
            return _node_position(current)
        current = parent
    return None


def _record_binding(
    name: str | None,
    scope: _BoolScope,
    module: _BoolScope,
    *,
    origin: ast.AST,
    parents: dict[ast.AST, ast.AST],
    execution_scope: _BoolScope | None = None,
) -> None:
    if not name:
        return
    if scope.kind != "module" and name in scope.global_names:
        target = module
    elif scope.kind != "module" and name in scope.nonlocal_names:
        scope.nonlocal_writes.add(name)
        return
    else:
        target = scope
    target.bound_names.add(name)
    target.written_names.add(name)
    if target.kind in {"module", "class"}:
        current = execution_scope or scope
        while current is not None and current.kind not in {"function", "generator"}:
            current = current.parent
        effective_position = (
            None
            if current is not None
            else _scope_statement_position(origin, target, parents)
        )
        target.binding_positions.setdefault(name, []).append(effective_position)


def _mark_wildcard_import(scope: _BoolScope) -> None:
    scope.wildcard_import = True


def _resolve_name(
    scope: _BoolScope,
    name: str,
    module_scope: _BoolScope,
    memo: dict[tuple[_BoolScope, str], _BoolScope | object | None],
) -> _BoolScope | object | None:
    """Resolve a load to its static owner, None for builtin, or unknown."""
    trail: list[tuple[_BoolScope, str]] = []
    current: _BoolScope | None = scope
    seen: set[int] = set()
    result: _BoolScope | object | None

    while current is not None:
        key = (current, name)
        if key in memo:
            result = memo[key]
            break
        if id(current) in seen:
            result = _UNKNOWN_NAME_OWNER
            break
        seen.add(id(current))
        trail.append(key)

        if current.kind != "module" and name in current.global_names:
            current = module_scope
            continue
        if current.kind != "module" and name in current.nonlocal_names:
            enclosing = current.parent
            while enclosing is not None and enclosing.kind != "module":
                if name in enclosing.bound_names:
                    result = enclosing
                    break
                if enclosing.wildcard_import:
                    result = _UNKNOWN_NAME_OWNER
                    break
                enclosing = enclosing.parent
            else:
                result = _UNKNOWN_NAME_OWNER
            break
        if name in current.bound_names:
            result = current
            break
        if current.wildcard_import:
            result = _UNKNOWN_NAME_OWNER
            break
        current = current.parent
    else:
        result = None

    for key in trail:
        memo[key] = result
    return result


def _binding_is_visible_at(
    scope: _BoolScope,
    name: str,
    node: ast.AST,
    parents: dict[ast.AST, ast.AST],
) -> bool:
    effects = scope.binding_positions.get(name)
    if not effects:
        return True
    position = _scope_statement_position(node, scope, parents)
    return position is None or any(
        effect is None or effect <= position for effect in effects
    )


def _name_resolves_to_builtin_at(
    scope: _BoolScope,
    name: str,
    node: ast.AST,
    module_scope: _BoolScope,
    parents: dict[ast.AST, ast.AST],
) -> bool:
    """Resolve a call-time name while preserving module/class execution order."""
    current: _BoolScope | None = scope
    deferred_execution = False
    seen: set[int] = set()

    while current is not None:
        if id(current) in seen:
            return False
        seen.add(id(current))
        if current.kind in {"function", "generator"}:
            deferred_execution = True

        if current.kind != "module" and name in current.global_names:
            current = module_scope
            continue
        if current.kind != "module" and name in current.nonlocal_names:
            enclosing = current.parent
            while enclosing is not None and enclosing.kind != "module":
                if name in enclosing.bound_names or enclosing.wildcard_import:
                    return False
                enclosing = enclosing.parent
            return False

        if name in current.bound_names:
            order_sensitive = current.kind in {"module", "class"} and not (
                deferred_execution
            )
            if not order_sensitive or _binding_is_visible_at(
                current, name, node, parents
            ):
                return False
        if current.wildcard_import:
            return False
        current = current.parent

    return True


def _bool_resolves_to_builtin(
    scope: _BoolScope,
    module_scope: _BoolScope,
    memo: dict[tuple[_BoolScope, str], _BoolScope | object | None],
) -> bool:
    return _resolve_name(scope, "bool", module_scope, memo) is None


def _function_scope(
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
    parent: _BoolScope,
) -> _BoolScope:
    scope = _BoolScope("function", _non_class_parent(parent))
    scope.typing_parent = parent
    parameters = (
        *node.args.posonlyargs,
        *node.args.args,
        *node.args.kwonlyargs,
    )
    if node.args.vararg is not None:
        parameters = (*parameters, node.args.vararg)
    if node.args.kwarg is not None:
        parameters = (*parameters, node.args.kwarg)
    scope.bound_names.update(parameter.arg for parameter in parameters)

    positional_parameters = (*node.args.posonlyargs, *node.args.args)
    defaults_by_name = {
        parameter.arg: default
        for parameter, default in zip(
            positional_parameters[-len(node.args.defaults) :],
            node.args.defaults,
        )
    }
    defaults_by_name.update(
        {
            parameter.arg: default
            for parameter, default in zip(node.args.kwonlyargs, node.args.kw_defaults)
            if default is not None
        }
    )
    scope.typed_bool_names = {
        parameter.arg
        for parameter in parameters
        if _is_exact_bool_annotation(parameter.annotation)
        and (
            parameter.arg not in defaults_by_name
            or not _has_statically_aliasing_default(defaults_by_name[parameter.arg])
        )
    }
    scope.type_param_names = _type_parameter_names(node)
    scope.bound_names.update(scope.type_param_names)
    scope.annotation_bool_shadowed = "bool" in scope.type_param_names
    if not isinstance(node, ast.Lambda):
        scope.global_names, scope.nonlocal_names = _scope_declarations(node.body)
    return scope


def _push_function_children(stack: list, node, outer, function_scope) -> None:
    stack.extend((statement, function_scope) for statement in reversed(node.body))
    annotation_nodes = [
        *(parameter.annotation for parameter in node.args.posonlyargs),
        *(parameter.annotation for parameter in node.args.args),
        *(parameter.annotation for parameter in node.args.kwonlyargs),
        node.args.vararg.annotation if node.args.vararg is not None else None,
        node.args.kwarg.annotation if node.args.kwarg is not None else None,
        getattr(node, "returns", None),
    ]
    stack.extend((annotation, outer) for annotation in annotation_nodes if annotation)
    stack.extend((default, outer) for default in reversed(node.args.defaults))
    stack.extend(
        (default, outer)
        for default in reversed(node.args.kw_defaults)
        if default is not None
    )
    stack.extend(
        (decorator, outer)
        for decorator in reversed(getattr(node, "decorator_list", []))
    )


def _push_comprehension_children(stack: list, node, outer, scope) -> None:
    generators = node.generators
    if generators:
        first, *rest = generators
        stack.append((first.iter, outer))
        stack.append((first.target, scope))
        stack.extend((condition, scope) for condition in reversed(first.ifs))
        for generator in reversed(rest):
            stack.append((generator.iter, scope))
            stack.append((generator.target, scope))
            stack.extend((condition, scope) for condition in reversed(generator.ifs))
    if isinstance(node, ast.DictComp):
        stack.append((node.value, scope))
        stack.append((node.key, scope))
    else:
        stack.append((node.elt, scope))


def _module_repeat_facts(
    tree: ast.Module,
) -> tuple[set[ast.Call], set[ast.Name], set[ast.Call]]:
    """Collect scope-aware facts used to prove safe counts and mutable values."""
    parents: dict[ast.AST, ast.AST] = {}
    parent_stack = [tree]
    while parent_stack:
        parent = parent_stack.pop()
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
            parent_stack.append(child)

    module_scope = _BoolScope("module", None, tree)
    scopes = [module_scope]
    stack: list[tuple[ast.AST, _BoolScope]] = [(tree, module_scope)]

    while stack:
        node, scope = stack.pop()

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _record_binding(
                node.name,
                scope,
                module_scope,
                origin=node,
                parents=parents,
            )
            child_scope = _function_scope(node, scope)
            scopes.append(child_scope)
            _push_function_children(stack, node, scope, child_scope)
            continue
        if isinstance(node, ast.Lambda):
            child_scope = _function_scope(node, scope)
            scopes.append(child_scope)
            stack.append((node.body, child_scope))
            stack.extend((default, scope) for default in reversed(node.args.defaults))
            stack.extend(
                (default, scope)
                for default in reversed(node.args.kw_defaults)
                if default is not None
            )
            continue
        if isinstance(node, ast.ClassDef):
            _record_binding(
                node.name,
                scope,
                module_scope,
                origin=node,
                parents=parents,
            )
            child_scope = _BoolScope("class", _non_class_parent(scope), node)
            child_scope.typing_parent = scope
            child_scope.type_param_names = _type_parameter_names(node)
            child_scope.bound_names.update(child_scope.type_param_names)
            child_scope.annotation_bool_shadowed = (
                "bool" in child_scope.type_param_names
            )
            child_scope.global_names, child_scope.nonlocal_names = _scope_declarations(
                node.body
            )
            scopes.append(child_scope)
            stack.extend((statement, child_scope) for statement in reversed(node.body))
            stack.extend((base, scope) for base in reversed(node.bases))
            stack.extend((keyword.value, scope) for keyword in reversed(node.keywords))
            stack.extend(
                (decorator, scope) for decorator in reversed(node.decorator_list)
            )
            continue
        if isinstance(
            node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
        ):
            kind = (
                "generator" if isinstance(node, ast.GeneratorExp) else "comprehension"
            )
            child_scope = _BoolScope(kind, _non_class_parent(scope))
            child_scope.walrus_owner = scope.walrus_owner
            scopes.append(child_scope)
            _push_comprehension_children(stack, node, scope, child_scope)
            continue

        if isinstance(node, ast.NamedExpr):
            if isinstance(node.target, ast.Name):
                _record_binding(
                    node.target.id,
                    scope.walrus_owner,
                    module_scope,
                    origin=node,
                    parents=parents,
                    execution_scope=scope,
                )
            stack.append((node.value, scope))
            continue

        if isinstance(node, ast.Global):
            scope.global_names.update(node.names)
            continue
        if isinstance(node, ast.Nonlocal):
            scope.nonlocal_names.update(node.names)
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            from_import = isinstance(node, ast.ImportFrom)
            for alias in node.names:
                if from_import and alias.name == "*":
                    _mark_wildcard_import(scope)
                else:
                    _record_binding(
                        _import_binding(alias, from_import=from_import),
                        scope,
                        module_scope,
                        origin=node,
                        parents=parents,
                    )
            continue
        if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)):
            _record_binding(
                node.name,
                scope,
                module_scope,
                origin=node,
                parents=parents,
            )
        elif isinstance(node, ast.MatchMapping):
            _record_binding(
                node.rest,
                scope,
                module_scope,
                origin=node,
                parents=parents,
            )
        elif isinstance(node, ast.Name):
            if isinstance(node.ctx, ast.Load):
                scope.name_loads.append(node)
            elif isinstance(node.ctx, (ast.Store, ast.Del)):
                _record_binding(
                    node.id,
                    scope,
                    module_scope,
                    origin=node,
                    parents=parents,
                )
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "bool":
                scope.bool_calls.append(node)
            elif node.func.id in _BUILTIN_MUTABLE_REPEAT_CONSTRUCTORS:
                scope.mutable_constructor_calls.append(node)
        stack.extend((child, scope) for child in ast.iter_child_nodes(node))

    resolution_memo: dict[tuple[_BoolScope, str], _BoolScope | object | None] = {}
    for scope in scopes:
        for name in scope.nonlocal_writes:
            owner = _resolve_name(scope, name, module_scope, resolution_memo)
            if isinstance(owner, _BoolScope):
                owner.written_names.add(name)

    builtin_calls = {
        call
        for scope in scopes
        for call in scope.bool_calls
        if _name_resolves_to_builtin_at(scope, "bool", call, module_scope, parents)
    }
    builtin_mutable_constructor_calls = {
        call
        for scope in scopes
        for call in scope.mutable_constructor_calls
        if _name_resolves_to_builtin_at(
            scope, call.func.id, call, module_scope, parents
        )
    }
    stable_loads = set()
    for scope in scopes:
        for load in scope.name_loads:
            owner = _resolve_name(scope, load.id, module_scope, resolution_memo)
            if (
                isinstance(owner, _BoolScope)
                and load.id in owner.typed_bool_names
                and load.id not in owner.written_names
                and not owner.annotation_bool_shadowed
                and owner.typing_parent is not None
                and _bool_resolves_to_builtin(
                    owner.typing_parent, module_scope, resolution_memo
                )
            ):
                stable_loads.add(load)
    return builtin_calls, stable_loads, builtin_mutable_constructor_calls


class RepeatedMutableAliasRule(SkylosRule):
    rule_id = "SKY-L034"
    name = "Repeated Mutable Alias"

    def __init__(self):
        self._bool_count_loads: set[ast.Name] = set()
        self._builtin_bool_calls: set[ast.Call] = set()
        self._builtin_mutable_constructor_calls: set[ast.Call] = set()
        self._sequence_fact_cache: dict[ast.AST, tuple[type[ast.AST], bool] | None] = {}

    def visit_node(self, node, context):
        if isinstance(node, ast.Module):
            (
                self._builtin_bool_calls,
                self._bool_count_loads,
                self._builtin_mutable_constructor_calls,
            ) = _module_repeat_facts(node)
            self._sequence_fact_cache = {}
            return None
        if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Mult):
            return None

        sequence_fact = None
        count = None
        left_fact = _proven_sequence_fact(
            node.left,
            self._sequence_fact_cache,
            builtin_bool_calls=self._builtin_bool_calls,
            builtin_mutable_constructor_calls=self._builtin_mutable_constructor_calls,
            bool_count_loads=self._bool_count_loads,
        )
        right_fact = _proven_sequence_fact(
            node.right,
            self._sequence_fact_cache,
            builtin_bool_calls=self._builtin_bool_calls,
            builtin_mutable_constructor_calls=self._builtin_mutable_constructor_calls,
            bool_count_loads=self._bool_count_loads,
        )
        if left_fact is not None and right_fact is None:
            sequence_fact, count = left_fact, node.right
        elif right_fact is not None and left_fact is None:
            sequence_fact, count = right_fact, node.left
        if (
            sequence_fact is None
            or count is None
            or not _repeat_count_can_alias(
                count,
                builtin_bool_calls=self._builtin_bool_calls,
                bool_count_loads=self._bool_count_loads,
            )
        ):
            return None
        if not sequence_fact[1]:
            return None

        return [
            {
                "rule_id": self.rule_id,
                "kind": "logic",
                "severity": "MEDIUM",
                "type": "expression",
                "name": "sequence repetition",
                "simple_name": "sequence repetition",
                "value": "mutable_alias",
                "threshold": 0,
                "message": (
                    "Sequence repetition reuses mutable elements across "
                    "repetitions; use a comprehension to create independent values."
                ),
                "file": context.get("filename"),
                "basename": Path(context.get("filename", "")).name,
                "line": node.lineno,
                "col": node.col_offset,
            }
        ]


class BareExceptRule(SkylosRule):
    rule_id = "SKY-L002"
    name = "Bare Except Block"

    def visit_node(self, node, context):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            return [
                {
                    "rule_id": self.rule_id,
                    "kind": "logic",
                    "severity": "MEDIUM",
                    "type": "block",
                    "name": "except",
                    "simple_name": "except",
                    "value": "bare",
                    "threshold": 0,
                    "message": "Bare 'except:' block swallows SystemExit and other critical errors.",
                    "file": context.get("filename"),
                    "basename": Path(context.get("filename", "")).name,
                    "line": node.lineno,
                    "col": node.col_offset,
                }
            ]
        return None


class DangerousComparisonRule(SkylosRule):
    rule_id = "SKY-L003"
    name = "Dangerous Comparison"

    def visit_node(self, node, context):
        if not isinstance(node, ast.Compare):
            return None

        findings = []
        for op, comparator in zip(node.ops, node.comparators):
            if isinstance(op, (ast.Eq, ast.NotEq)):
                if isinstance(comparator, ast.Constant):
                    val = comparator.value
                    if val is True or val is False or val is None:
                        findings.append(
                            {
                                "rule_id": self.rule_id,
                                "kind": "logic",
                                "severity": "LOW",
                                "type": "comparison",
                                "name": "==",
                                "simple_name": "==",
                                "value": str(comparator.value),
                                "threshold": 0,
                                "message": f"Comparison to {comparator.value} should use 'is' or 'is not'.",
                                "file": context.get("filename"),
                                "basename": Path(context.get("filename", "")).name,
                                "line": node.lineno,
                                "col": node.col_offset,
                            }
                        )

        if findings:
            return findings
        return None


def _walk_scope(nodes):
    stack = []

    if isinstance(nodes, list):
        for n in nodes:
            stack.append(n)
    else:
        stack.append(nodes)

    while stack:
        node = stack.pop()

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue

        yield node

        for child in ast.iter_child_nodes(node):
            stack.append(child)


def _is_empty_branch_body(body: list[ast.stmt]) -> bool:
    if not body:
        return True

    for stmt in body:
        if isinstance(stmt, ast.Pass):
            continue
        if isinstance(stmt, ast.Expr):
            value = stmt.value
            if isinstance(value, ast.Constant) and value.value is ...:
                continue
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                continue
        return False
    return True


def _substantive_branch_statement_count(body: list[ast.stmt]) -> int:
    count = 0
    for stmt in body:
        if isinstance(stmt, ast.Pass):
            continue
        if isinstance(stmt, ast.Expr):
            value = stmt.value
            if isinstance(value, ast.Constant) and value.value is ...:
                continue
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                continue
        count += 1
    return count


def _semantic_ast_key(node: ast.AST | list[ast.AST]) -> str:
    if isinstance(node, list):
        return "[" + ",".join(_semantic_ast_key(child) for child in node) + "]"
    return ast.dump(node, annotate_fields=True, include_attributes=False)


def _iter_function_scope_nodes(node: ast.FunctionDef | ast.AsyncFunctionDef):
    stack = list(reversed(node.body))

    while stack:
        current = stack.pop()
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue

        yield current

        children = list(ast.iter_child_nodes(current))
        stack.extend(reversed(children))


def _build_parent_map(node: ast.AST) -> dict[int, ast.AST]:
    parent_map = {}
    for parent in ast.walk(node):
        for child in ast.iter_child_nodes(parent):
            parent_map[id(child)] = parent
    return parent_map


def _is_elif_node(node: ast.If, parent_map: dict[int, ast.AST]) -> bool:
    parent = parent_map.get(id(node))
    return (
        isinstance(parent, ast.If)
        and len(parent.orelse) == 1
        and parent.orelse[0] is node
    )


def _branch_body_line(body: list[ast.stmt], fallback_line: int) -> int:
    for stmt in body:
        line = getattr(stmt, "lineno", None)
        if line is not None:
            return line
    return fallback_line


def _collect_if_chain(
    node: ast.If,
) -> list[tuple[ast.AST | None, list[ast.stmt], int]]:
    branches = []
    current = node

    while isinstance(current, ast.If):
        branches.append((current.test, current.body, current.lineno))
        if len(current.orelse) == 1 and isinstance(current.orelse[0], ast.If):
            current = current.orelse[0]
        else:
            if current.orelse:
                branches.append(
                    (
                        None,
                        current.orelse,
                        _branch_body_line(current.orelse, current.lineno),
                    )
                )
            break

    return branches


class DuplicateBranchRule(SkylosRule):
    rule_id = "SKY-Q305"
    name = "Duplicate Branch Logic"
    node_types = (ast.FunctionDef, ast.AsyncFunctionDef)

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None

        filename = context.get("filename", "")
        parent_map = _build_parent_map(node)
        findings = []
        reported = set()

        for child in _iter_function_scope_nodes(node):
            if not isinstance(child, ast.If):
                continue
            if _is_elif_node(child, parent_map):
                continue

            branches = _collect_if_chain(child)
            if len(branches) < 2:
                continue

            findings.extend(
                self._duplicate_condition_findings(node, branches, filename, reported)
            )
            findings.extend(
                self._duplicate_body_findings(node, branches, filename, reported)
            )

        return findings if findings else None

    def _duplicate_condition_findings(
        self,
        func_node,
        branches: list[tuple[ast.AST | None, list[ast.stmt], int]],
        filename: str,
        reported: set[tuple[str, int, str]],
    ) -> list[dict]:
        seen = {}
        findings = []

        for condition, _, line in branches:
            if condition is None:
                continue
            key = _semantic_ast_key(condition)
            if key not in seen:
                seen[key] = line
                continue

            report_key = ("condition", line, key)
            if report_key in reported:
                continue
            reported.add(report_key)
            findings.append(
                self._make_finding(
                    func_node,
                    filename,
                    line,
                    "duplicate_condition",
                    f"Function '{func_node.name}' repeats an if/elif condition first seen at line {seen[key]}.",
                )
            )

        return findings

    def _duplicate_body_findings(
        self,
        func_node,
        branches: list[tuple[ast.AST | None, list[ast.stmt], int]],
        filename: str,
        reported: set[tuple[str, int, str]],
    ) -> list[dict]:
        seen = {}
        findings = []

        for _, body, line in branches:
            if _is_empty_branch_body(body):
                continue
            if _substantive_branch_statement_count(body) < 2:
                continue
            if any(
                kind == "condition" and seen_line == line
                for kind, seen_line, _ in reported
            ):
                continue

            key = _semantic_ast_key(body)
            if key not in seen:
                seen[key] = line
                continue

            report_key = ("body", line, key)
            if report_key in reported:
                continue
            reported.add(report_key)
            findings.append(
                self._make_finding(
                    func_node,
                    filename,
                    line,
                    "duplicate_body",
                    f"Function '{func_node.name}' has duplicate branch bodies first seen at line {seen[key]}.",
                )
            )

        return findings

    def _make_finding(self, func_node, filename, line, value, message):
        return {
            "rule_id": self.rule_id,
            "kind": "quality",
            "severity": "MEDIUM",
            "type": "function",
            "name": func_node.name,
            "simple_name": func_node.name,
            "value": value,
            "threshold": 0,
            "message": message,
            "file": filename,
            "basename": Path(filename).name,
            "line": line,
            "col": func_node.col_offset,
        }


def _is_function_level_try(node: ast.Try, parent_body: list[ast.stmt]) -> bool:
    if len(parent_body) == 1 and parent_body[0] is node:
        return True
    if (
        len(parent_body) == 2
        and isinstance(parent_body[0], ast.Expr)
        and isinstance(parent_body[0].value, ast.Constant)
        and isinstance(parent_body[0].value.value, str)
        and parent_body[1] is node
    ):
        return True
    return False


class TryBlockPatternsRule(SkylosRule):
    rule_id = "SKY-L004"
    name = "Anti-Pattern Try Block"

    def __init__(self, max_lines=15, max_control_flow=3):
        self.max_lines = max_lines
        self.max_control_flow = max_control_flow

    def visit_node(self, node, context):
        if not isinstance(node, ast.Try):
            return None

        parent_body = context.get("_parent_body")
        is_func_level = parent_body is not None and _is_function_level_try(
            node, parent_body
        )

        findings = []

        if node.body and not is_func_level:
            start = node.body[0].lineno
            end = getattr(node.body[-1], "end_lineno", start)
            length = end - start + 1

            if length > self.max_lines:
                findings.append(
                    self._create_finding(
                        node,
                        context,
                        severity="LOW",
                        value=length,
                        msg=f"Try block covers {length} lines (limit: {self.max_lines}). Reduce scope to the risky operation only.",
                    )
                )

        control_flow_count = 0
        has_nested_try = False

        for stmt in node.body:
            for child in _walk_scope([stmt]):
                if child is stmt:
                    continue
                if isinstance(child, ast.Try):
                    has_nested_try = True
                if isinstance(child, (ast.If, ast.For, ast.While)):
                    control_flow_count += 1

        if has_nested_try:
            findings.append(
                self._create_finding(
                    node,
                    context,
                    severity="MEDIUM",
                    value="nested",
                    msg="Nested 'try' block detected. Flatten logic or move inner try to a helper function.",
                )
            )

        if control_flow_count > self.max_control_flow:
            findings.append(
                self._create_finding(
                    node,
                    context,
                    severity="HIGH",
                    value=control_flow_count,
                    msg=f"Try block contains {control_flow_count} control flow statements. Don't wrap complex logic in error handling.",
                )
            )

        if findings:
            return findings
        return None

    def _create_finding(self, node, context, severity, value, msg):
        return {
            "rule_id": self.rule_id,
            "kind": "quality",
            "severity": severity,
            "type": "block",
            "name": "try",
            "simple_name": "try",
            "value": value,
            "threshold": 0,
            "message": msg,
            "file": context.get("filename"),
            "basename": Path(context.get("filename", "")).name,
            "line": node.lineno,
            "col": node.col_offset,
        }


class UnusedExceptVarRule(SkylosRule):
    rule_id = "SKY-L005"
    name = "Unused Exception Variable"

    def visit_node(self, node, context):
        if not isinstance(node, ast.ExceptHandler):
            return None
        if not node.name:
            return None
        if node.name == "_":
            return None

        use_count = 0
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id == node.name:
                use_count += 1

        if use_count == 0:
            return [
                {
                    "rule_id": self.rule_id,
                    "kind": "logic",
                    "severity": "LOW",
                    "type": "variable",
                    "name": node.name,
                    "simple_name": node.name,
                    "value": "unused",
                    "threshold": 0,
                    "message": f"Exception variable '{node.name}' is captured but never used. Use '_' or remove it.",
                    "file": context.get("filename"),
                    "basename": Path(context.get("filename", "")).name,
                    "line": node.lineno,
                    "col": node.col_offset,
                }
            ]
        return None


def _annotation_allows_none(annotation) -> bool:
    if annotation is None:
        return False

    if isinstance(annotation, ast.Constant) and annotation.value is None:
        return True

    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        if _annotation_allows_none(annotation.left):
            return True
        if _annotation_allows_none(annotation.right):
            return True

    if isinstance(annotation, ast.Subscript):
        func = annotation.value
        name = None
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr

        if name in ("Optional",):
            return True

        if name in ("Union",):
            slice_node = annotation.slice
            if isinstance(slice_node, ast.Tuple):
                for elt in slice_node.elts:
                    if isinstance(elt, ast.Constant) and elt.value is None:
                        return True
                    if isinstance(elt, ast.Name) and elt.id == "None":
                        return True

    if isinstance(annotation, ast.Name) and annotation.id == "None":
        return True

    return False


class ReturnConsistencyRule(SkylosRule):
    rule_id = "SKY-L006"
    name = "Inconsistent Return"

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None

        if _annotation_allows_none(node.returns):
            return None

        returns_value = False
        returns_none = False

        for child in _walk_scope(node.body):
            if isinstance(child, ast.Return):
                if child.value is None:
                    returns_none = True
                elif (
                    isinstance(child.value, ast.Constant) and child.value.value is None
                ):
                    returns_none = True
                else:
                    returns_value = True

        if returns_value and returns_none:
            return [
                {
                    "rule_id": self.rule_id,
                    "kind": "logic",
                    "severity": "MEDIUM",
                    "type": "function",
                    "name": node.name,
                    "simple_name": node.name,
                    "value": "inconsistent",
                    "threshold": 0,
                    "message": f"Function '{node.name}' has inconsistent returns: some paths return a value, others return None.",
                    "file": context.get("filename"),
                    "basename": Path(context.get("filename", "")).name,
                    "line": node.lineno,
                    "col": node.col_offset,
                }
            ]
        return None


_LOGGING_NAMES = {"logger", "logging", "log"}
_INTENTIONAL_EXCEPTIONS = {"KeyboardInterrupt", "SystemExit"}
_BROAD_EXCEPTION_TYPES = {"Exception", "BaseException"}


def _is_logging_call(node):
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
        func = node.value.func
        if isinstance(func, ast.Attribute):
            val = func.value
            if isinstance(val, ast.Name) and val.id in _LOGGING_NAMES:
                return True
    return False


def _is_reraise(node):
    if isinstance(node, ast.Raise):
        return True
    return False


def _handler_body_is_trivial(body):
    for stmt in body:
        if isinstance(stmt, ast.Pass):
            continue
        if isinstance(stmt, ast.Continue):
            continue
        if isinstance(stmt, ast.Expr):
            if isinstance(stmt.value, ast.Constant) and stmt.value.value is ...:
                continue
            if isinstance(stmt.value, ast.Constant) and isinstance(
                stmt.value.value, str
            ):
                continue
        if isinstance(stmt, ast.Return):
            if _return_value_is_trivial_placeholder(stmt.value):
                continue
        return False
    return True


def _return_value_is_trivial_placeholder(value):
    if value is None:
        return True
    if isinstance(value, ast.Constant):
        return value.value is None or value.value == ""
    if isinstance(value, (ast.List, ast.Dict, ast.Set, ast.Tuple)):
        if isinstance(value, ast.Dict):
            return not value.keys and not value.values
        return not value.elts
    if isinstance(value, ast.Call):
        if value.args or value.keywords:
            return False
        if isinstance(value.func, ast.Name):
            return value.func.id in {"dict", "list", "set", "tuple"}
    return False


def _handler_has_real_work(body):
    for stmt in body:
        if _is_logging_call(stmt):
            return True
        if _is_reraise(stmt):
            return True
    return False


def _exception_type_name(exc_type):
    if exc_type is None:
        return None
    if isinstance(exc_type, ast.Name):
        return exc_type.id
    if isinstance(exc_type, ast.Attribute):
        return exc_type.attr
    if isinstance(exc_type, ast.Tuple):
        names = []
        for elt in exc_type.elts:
            n = _exception_type_name(elt)
            if n:
                names.append(n)
        return ", ".join(names) if names else None
    return None


def _exception_type_names(exc_type):
    if exc_type is None:
        return []
    if isinstance(exc_type, ast.Name):
        return [exc_type.id]
    if isinstance(exc_type, ast.Attribute):
        return [exc_type.attr]
    if isinstance(exc_type, ast.Tuple):
        names = []
        for elt in exc_type.elts:
            names.extend(_exception_type_names(elt))
        return names
    return []


def _handler_is_narrow_trivial_fallback(node):
    exc_names = _exception_type_names(node.type)
    if not exc_names:
        return False
    if any(exc_name in _BROAD_EXCEPTION_TYPES for exc_name in exc_names):
        return False
    return _handler_body_is_trivial(node.body)


class EmptyErrorHandlerRule(SkylosRule):
    rule_id = "SKY-L007"
    name = "Empty Error Handler"

    def visit_node(self, node, context):
        findings = []

        if isinstance(node, ast.ExceptHandler):
            except_finding = self._check_except_handler(node, context)
            if except_finding is None and _exception_type_name(node.type) in (
                _INTENTIONAL_EXCEPTIONS
            ):
                return None
            if except_finding:
                findings.append(except_finding)

        if isinstance(node, ast.With):
            findings.extend(self._check_with_suppress(node, context))

        return findings if findings else None

    def _check_except_handler(self, node, context):
        exc_name = _exception_type_name(node.type)
        if exc_name in _INTENTIONAL_EXCEPTIONS:
            return None

        if not node.body:
            return self._make_finding(node, context, "MEDIUM", "empty")

        if _handler_has_real_work(node.body):
            return None

        if _handler_is_narrow_trivial_fallback(node):
            return None

        if _handler_body_is_trivial(node.body):
            has_return = any(isinstance(stmt, ast.Return) for stmt in node.body)
            severity = "HIGH" if has_return else "MEDIUM"
            return self._make_finding(node, context, severity, "trivial")

        return None

    def _check_with_suppress(self, node, context):
        findings = []
        for item in node.items:
            ctx_expr = item.context_expr
            if not isinstance(ctx_expr, ast.Call):
                continue

            if not self._is_contextlib_suppress_call(ctx_expr):
                continue

            for arg_name in self._iter_broad_suppress_args(ctx_expr):
                findings.append(
                    {
                        "rule_id": self.rule_id,
                        "kind": "logic",
                        "severity": "MEDIUM",
                        "type": "block",
                        "name": "suppress",
                        "simple_name": "suppress",
                        "value": "broad",
                        "threshold": 0,
                        "message": f"contextlib.suppress({arg_name}) silently swallows all errors.",
                        "file": context.get("filename"),
                        "basename": Path(context.get("filename", "")).name,
                        "line": node.lineno,
                        "col": node.col_offset,
                    }
                )
        return findings

    def _is_contextlib_suppress_call(self, call):
        func = call.func
        if isinstance(func, ast.Attribute) and func.attr == "suppress":
            return isinstance(func.value, ast.Name) and func.value.id == "contextlib"
        return isinstance(func, ast.Name) and func.id == "suppress"

    def _iter_broad_suppress_args(self, call):
        for arg in call.args:
            arg_name = None
            if isinstance(arg, ast.Name):
                arg_name = arg.id
            elif isinstance(arg, ast.Attribute):
                arg_name = arg.attr
            if arg_name in ("Exception", "BaseException"):
                yield arg_name

    def _make_finding(self, node, context, severity, value):
        return {
            "rule_id": self.rule_id,
            "kind": "logic",
            "severity": severity,
            "type": "block",
            "name": "except",
            "simple_name": "except",
            "value": value,
            "threshold": 0,
            "message": "Empty error handler silently swallows exceptions.",
            "file": context.get("filename"),
            "basename": Path(context.get("filename", "")).name,
            "line": node.lineno,
            "col": node.col_offset,
        }


RESOURCE_FUNCTIONS = {
    "open",
    "sqlite3.connect",
    "socket.socket",
    "requests.Session",
    "tempfile.NamedTemporaryFile",
    "tempfile.TemporaryFile",
    "tempfile.SpooledTemporaryFile",
    "psycopg2.connect",
    "pymysql.connect",
    "cx_Oracle.connect",
    "urllib3.PoolManager",
    "http.client.HTTPConnection",
    "http.client.HTTPSConnection",
}

_RESOURCE_SIMPLE_NAMES = set()
_RESOURCE_ATTR_NAMES = {}

for _fn in RESOURCE_FUNCTIONS:
    if "." in _fn:
        parts = _fn.rsplit(".", 1)
        _RESOURCE_ATTR_NAMES.setdefault(parts[1], set()).add(parts[0])
    else:
        _RESOURCE_SIMPLE_NAMES.add(_fn)


def _call_matches_resource(call_node):
    func = call_node.func
    if isinstance(func, ast.Name) and func.id in _RESOURCE_SIMPLE_NAMES:
        return func.id
    if isinstance(func, ast.Attribute) and func.attr in _RESOURCE_ATTR_NAMES:
        if isinstance(func.value, ast.Name):
            expected_modules = _RESOURCE_ATTR_NAMES[func.attr]
            if func.value.id in expected_modules:
                return f"{func.value.id}.{func.attr}"
        if isinstance(func.value, ast.Attribute):
            parts = []
            node = func.value
            while isinstance(node, ast.Attribute):
                parts.append(node.attr)
                node = node.value
            if isinstance(node, ast.Name):
                parts.append(node.id)
            parts.reverse()
            full_mod = ".".join(parts)
            expected_modules = _RESOURCE_ATTR_NAMES[func.attr]
            if full_mod in expected_modules:
                return f"{full_mod}.{func.attr}"
    if isinstance(func, ast.Attribute) and func.attr == "open":
        if isinstance(func.value, ast.Call):
            inner = func.value.func
            if isinstance(inner, ast.Name) and inner.id == "Path":
                return "Path.open"
            if isinstance(inner, ast.Attribute) and inner.attr == "Path":
                return "Path.open"
        if isinstance(func.value, ast.Name):
            return None
    return None


class MissingResourceCleanupRule(SkylosRule):
    rule_id = "SKY-L008"
    name = "Missing Resource Cleanup"

    def visit_node(self, node, context):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            return None

        filename = context.get("filename", "")
        basename = Path(filename).name
        if basename == "__enter__.py":
            return None

        body = node.body if hasattr(node, "body") else []
        findings = []

        for stmt in body:
            self._check_stmt(stmt, context, findings, body)

        return findings if findings else None

    def _check_stmt(self, stmt, context, findings, scope_body):
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return

        if isinstance(stmt, ast.Try):
            self._check_try_stmt(stmt, context, findings, scope_body)
            return

        assignment_finding = self._check_resource_assignment(stmt, context, scope_body)
        if assignment_finding:
            findings.append(assignment_finding)

        expression_finding = self._check_resource_expression(stmt, context, scope_body)
        if expression_finding:
            findings.append(expression_finding)

        self._check_nested_statements(stmt, context, findings, scope_body)

    def _check_try_stmt(self, stmt, context, findings, scope_body):
        for sub in stmt.body:
            self._check_stmt(sub, context, findings, scope_body)
        for sub in stmt.orelse:
            self._check_stmt(sub, context, findings, scope_body)

    def _check_resource_assignment(self, stmt, context, scope_body):
        if not isinstance(stmt, ast.Assign):
            return None
        if not isinstance(stmt.value, ast.Call):
            return None

        resource_name = _call_matches_resource(stmt.value)
        if not resource_name or self._is_inside_with(stmt, scope_body):
            return None

        var_name = self._get_assign_name(stmt)
        if var_name:
            if self._is_returned_or_yielded(var_name, scope_body):
                return None
            if self._has_close_in_finally(var_name, scope_body):
                return None

        return self._make_finding(stmt, context, resource_name)

    def _check_resource_expression(self, stmt, context, scope_body):
        if not isinstance(stmt, ast.Expr):
            return None
        if not isinstance(stmt.value, ast.Call):
            return None

        resource_name = _call_matches_resource(stmt.value)
        if not resource_name or self._is_inside_with(stmt, scope_body):
            return None

        return self._make_finding(stmt, context, resource_name)

    def _check_nested_statements(self, stmt, context, findings, scope_body):
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(child, (ast.With, ast.AsyncWith)):
                continue
            if hasattr(child, "body") and isinstance(child.body, list):
                for sub in child.body:
                    self._check_stmt(sub, context, findings, scope_body)
            if hasattr(child, "orelse") and isinstance(child.orelse, list):
                for sub in child.orelse:
                    self._check_stmt(sub, context, findings, scope_body)

    def _is_inside_with(self, stmt, scope_body):
        for top_stmt in scope_body:
            if isinstance(top_stmt, (ast.With, ast.AsyncWith)):
                for node in ast.walk(top_stmt):
                    if node is stmt:
                        return True
        return False

    def _get_assign_name(self, assign_node):
        if assign_node.targets and isinstance(assign_node.targets[0], ast.Name):
            return assign_node.targets[0].id
        return None

    def _is_returned_or_yielded(self, var_name, scope_body):
        for node in ast.walk(ast.Module(body=scope_body, type_ignores=[])):
            if isinstance(node, ast.Return) and node.value:
                if isinstance(node.value, ast.Name) and node.value.id == var_name:
                    return True
            if isinstance(node, ast.Yield) and node.value:
                if isinstance(node.value, ast.Name) and node.value.id == var_name:
                    return True
        return False

    def _has_close_in_finally(self, var_name, scope_body):
        for stmt in scope_body:
            if isinstance(stmt, ast.Try) and stmt.finalbody:
                for final_stmt in stmt.finalbody:
                    for node in ast.walk(final_stmt):
                        if (
                            isinstance(node, ast.Call)
                            and isinstance(node.func, ast.Attribute)
                            and node.func.attr == "close"
                            and isinstance(node.func.value, ast.Name)
                            and node.func.value.id == var_name
                        ):
                            return True
        return False

    def _make_finding(self, node, context, resource_name):
        return {
            "rule_id": self.rule_id,
            "kind": "logic",
            "severity": "MEDIUM",
            "type": "resource",
            "name": resource_name,
            "simple_name": resource_name,
            "value": "no_cleanup",
            "threshold": 0,
            "message": f"Resource '{resource_name}' opened without 'with' statement. Use a context manager to ensure cleanup.",
            "file": context.get("filename"),
            "basename": Path(context.get("filename", "")).name,
            "line": node.lineno,
            "col": node.col_offset,
        }
