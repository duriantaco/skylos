"""Bounded source proof that a descriptor calls its function with an instance."""

import ast

from skylos.rules.quality._receivers import FUNCTION_NODES, method_kind


def _instance_descriptor(node, *, bindings=None, kinds=None):
    """Accept a small, ordered descriptor contract; unknown effects reject proof."""
    if node.bases or node.keywords or node.decorator_list:
        return False
    methods = {
        item.name: item for item in node.body if isinstance(item, FUNCTION_NODES)
    }
    init, getter = methods.get("__init__"), methods.get("__get__")
    if (
        init is None
        or getter is None
        or {"__new__", "__getattr__", "__getattribute__", "__setattr__", "__delattr__"}
        & methods.keys()
    ):
        return False
    if any(method.decorator_list for method in (init, getter)):
        return False
    initial_fields = {}
    for item in node.body:
        if isinstance(item, FUNCTION_NODES):
            if item.name in {"__init__", "__set_name__", "__get__"}:
                continue
            # Additional method bodies must have no successful mutable effects.
            if item.decorator_list and method_kind(item, kinds=kinds) not in {
                "static",
                "class",
            }:
                return False
            if any(
                not (
                    isinstance(child, (ast.Pass, ast.Raise))
                    or isinstance(child, ast.Expr)
                    and isinstance(child.value, ast.Constant)
                    and isinstance(child.value.value, str)
                )
                for child in item.body
            ):
                return False
        elif (
            isinstance(item, ast.Assign)
            and isinstance(item.value, ast.Constant)
            and all(isinstance(target, ast.Name) for target in item.targets)
        ):
            for target in item.targets:
                initial_fields[target.id] = ("literal", item.value.value)
        elif (
            isinstance(item, ast.Expr)
            and isinstance(item.value, ast.Constant)
            and isinstance(item.value.value, str)
        ):
            continue
        elif (
            isinstance(item, ast.AnnAssign)
            and isinstance(item.target, ast.Name)
            and (item.value is None or isinstance(item.value, ast.Constant))
        ):
            if item.value is not None:
                initial_fields[item.target.id] = ("literal", item.value.value)
        else:
            return False
    unknown = ("unknown", None)
    decorated_function = ("function", None)
    calls = []
    builtin_getattr = bindings is None or bindings.get("getattr") == "builtin-getattr"

    class Unsupported(Exception):
        pass

    def run(method, fields, *, constructor=False, getter_method=False):
        if not isinstance(method, ast.FunctionDef):
            raise Unsupported
        args = [*method.args.posonlyargs, *method.args.args]
        if len(args) < 2 or method.decorator_list:
            raise Unsupported
        receiver, second = args[0].arg, args[1].arg
        if any(
            default is not None and not isinstance(default, ast.Constant)
            for default in (*method.args.defaults, *method.args.kw_defaults)
        ):
            raise Unsupported
        local = {argument.arg: unknown for argument in (*args, *method.args.kwonlyargs)}
        local[receiver] = ("receiver", None)
        if constructor:
            local[second] = decorated_function
        elif getter_method:
            local[second] = ("instance", None)

        def expression(expr, fields, names):
            if expr is None:
                return ("literal", None)
            if isinstance(expr, ast.Constant):
                return ("literal", expr.value)
            if isinstance(expr, ast.Name):
                return names.get(expr.id, unknown)
            if (
                isinstance(expr, ast.Attribute)
                and isinstance(expr.value, ast.Name)
                and names.get(expr.value.id) == ("receiver", None)
            ):
                return fields.get(expr.attr, unknown)
            if (
                isinstance(expr, ast.Compare)
                and len(expr.ops) == 1
                and len(expr.comparators) == 1
            ):
                left = expression(expr.left, fields, names)
                right = expression(expr.comparators[0], fields, names)
                if left[0] == right[0] == "literal":
                    op = expr.ops[0]
                    if isinstance(op, ast.Is):
                        if (
                            left[1] is None
                            or right[1] is None
                            or type(left[1]) is bool
                            or type(right[1]) is bool
                        ):
                            return ("literal", left[1] is right[1])
                    if isinstance(op, ast.IsNot):
                        if (
                            left[1] is None
                            or right[1] is None
                            or type(left[1]) is bool
                            or type(right[1]) is bool
                        ):
                            return ("literal", left[1] is not right[1])
                    if isinstance(op, ast.Eq):
                        return ("literal", left[1] == right[1])
                    if isinstance(op, ast.NotEq):
                        return ("literal", left[1] != right[1])
                return unknown
            if isinstance(expr, ast.Call):
                if (
                    isinstance(expr.func, ast.Name)
                    and expr.func.id == "getattr"
                    and builtin_getattr
                    and len(expr.args) == 2
                    and not expr.keywords
                    and expression(expr.args[0], fields, names) == decorated_function
                    and isinstance(expr.args[1], ast.Constant)
                    and expr.args[1].value == "__doc__"
                ):
                    return unknown
                function = expression(expr.func, fields, names)
                if (
                    function == decorated_function
                    and getter_method
                    and len(expr.args) == 1
                    and not expr.keywords
                    and expression(expr.args[0], fields, names) == ("instance", None)
                ):
                    calls.append(True)
                    return unknown
                raise Unsupported
            raise Unsupported

        def assign(target, value, fields, names):
            if isinstance(target, ast.Name):
                if target.id == receiver:
                    raise Unsupported
                names[target.id] = value
            elif (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and names.get(target.value.id) == ("receiver", None)
            ):
                fields[target.attr] = value
            elif (
                getter_method
                and isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Attribute)
                and target.value.attr == "__dict__"
                and isinstance(target.value.value, ast.Name)
                and names.get(target.value.value.id) == ("instance", None)
            ):
                # The property result may be cached on the accessing instance.
                expression(target.slice, fields, names)
            else:
                raise Unsupported

        def statements(body, states):
            for statement in body:
                next_states = []
                for state_fields, names, status in states:
                    if status != "live":
                        next_states.append((state_fields, names, status))
                        continue
                    if (
                        isinstance(statement, ast.Expr)
                        and isinstance(statement.value, ast.Constant)
                        and isinstance(statement.value.value, str)
                        or isinstance(statement, ast.Pass)
                    ):
                        next_states.append((state_fields, names, status))
                    elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
                        if statement.value is not None:
                            value = expression(statement.value, state_fields, names)
                            targets = (
                                statement.targets
                                if isinstance(statement, ast.Assign)
                                else [statement.target]
                            )
                            for target in targets:
                                assign(target, value, state_fields, names)
                        next_states.append((state_fields, names, status))
                    elif isinstance(statement, ast.If):
                        condition = expression(statement.test, state_fields, names)
                        branches = [statement.body, statement.orelse]
                        if condition[0] == "literal":
                            branches = [
                                statement.body if condition[1] else statement.orelse
                            ]
                        for branch in branches:
                            next_states.extend(
                                statements(
                                    branch, [(dict(state_fields), dict(names), "live")]
                                )
                            )
                    elif isinstance(statement, ast.Return):
                        expression(statement.value, state_fields, names)
                        next_states.append((state_fields, names, "return"))
                    elif isinstance(statement, ast.Raise):
                        next_states.append((state_fields, names, "raise"))
                    else:
                        raise Unsupported
                states = next_states
                if len(states) > 64:
                    raise Unsupported
            return states

        outcomes = [
            fields
            for fields, _, status in statements(
                method.body, [(dict(fields), local, "live")]
            )
            if status != "raise"
        ]
        if not outcomes:
            raise Unsupported
        return {
            name: outcomes[0].get(name, unknown)
            if all(
                outcome.get(name, unknown) == outcomes[0].get(name, unknown)
                for outcome in outcomes
            )
            else unknown
            for name in set().union(*(outcome.keys() for outcome in outcomes))
        }

    try:
        fields = run(init, initial_fields, constructor=True)
        if "__set_name__" in methods:
            fields = run(methods["__set_name__"], fields)
        run(getter, fields, getter_method=True)
    except (Unsupported, TypeError, ValueError):
        return False
    return bool(calls)
