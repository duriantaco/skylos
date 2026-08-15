import ast


def ellipsis_type_bindings(module):
    names = set()
    modules = set()
    for stmt in module.body:
        if isinstance(stmt, ast.ImportFrom) and stmt.module == "types":
            for imported in stmt.names:
                if imported.name == "EllipsisType":
                    names.add(imported.asname or imported.name)
        elif isinstance(stmt, ast.Import):
            for imported in stmt.names:
                if imported.name == "types":
                    modules.add(imported.asname or imported.name)
    return names, modules


def iter_arg_defaults(func_node):
    args = func_node.args
    positional_args = [*args.posonlyargs, *args.args]
    offset = len(positional_args) - len(args.defaults)

    for index, default in enumerate(args.defaults):
        if default:
            yield positional_args[offset + index], default
    for arg, default in zip(args.kwonlyargs, args.kw_defaults):
        if default:
            yield arg, default


def is_ellipsis_literal(node):
    return isinstance(node, ast.Constant) and node.value is Ellipsis


def annotation_accepts_ellipsis(annotation, *, type_names, type_modules):
    """Return whether an annotation explicitly accepts types.EllipsisType."""
    if annotation is None:
        return False
    if _is_bound_ellipsis_type(annotation, type_names, type_modules):
        return True
    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        return _annotations_accept_ellipsis(
            (annotation.left, annotation.right),
            type_names,
            type_modules,
        )
    if isinstance(annotation, ast.Subscript):
        return _subscript_accepts_ellipsis(annotation, type_names, type_modules)
    return False


def _is_bound_ellipsis_type(annotation, type_names, type_modules):
    if isinstance(annotation, ast.Name):
        return annotation.id in type_names
    return (
        isinstance(annotation, ast.Attribute)
        and annotation.attr == "EllipsisType"
        and isinstance(annotation.value, ast.Name)
        and annotation.value.id in type_modules
    )


def _annotations_accept_ellipsis(annotations, type_names, type_modules):
    return any(
        annotation_accepts_ellipsis(
            annotation,
            type_names=type_names,
            type_modules=type_modules,
        )
        for annotation in annotations
    )


def _subscript_accepts_ellipsis(annotation, type_names, type_modules):
    members = _subscript_members(annotation.slice)
    container = _qualified_tail(annotation.value)
    if container in {"Union", "Optional"}:
        return _annotations_accept_ellipsis(members, type_names, type_modules)
    if container not in {"Annotated", "Required", "NotRequired"} or not members:
        return False
    return annotation_accepts_ellipsis(
        members[0],
        type_names=type_names,
        type_modules=type_modules,
    )


def function_handles_ellipsis_parameter(node, parameter):
    """Recognize explicit sentinel handling or transparent keyword delegation."""
    nodes, parents = _function_body_graph(node)
    if any(
        isinstance(candidate, ast.Compare)
        and _compares_parameter_to_ellipsis(candidate, parameter)
        for candidate in nodes
    ):
        return True

    loads = [
        candidate
        for candidate in nodes
        if isinstance(candidate, ast.Name)
        and isinstance(candidate.ctx, ast.Load)
        and candidate.id == parameter
    ]
    return bool(loads) and all(
        _is_same_name_keyword_passthrough(load, parents, parameter) for load in loads
    )


def _qualified_tail(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _subscript_members(node):
    return list(node.elts) if isinstance(node, ast.Tuple) else [node]


def _is_ellipsis_reference(node):
    if is_ellipsis_literal(node):
        return True
    if isinstance(node, ast.Name):
        return node.id == "Ellipsis"
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "Ellipsis"
        and isinstance(node.value, ast.Name)
        and node.value.id == "builtins"
    )


def _compares_parameter_to_ellipsis(node, parameter):
    operands = [node.left, *node.comparators]
    for left, operator, right in zip(operands, node.ops, operands[1:]):
        if not isinstance(operator, (ast.Is, ast.IsNot, ast.Eq, ast.NotEq)):
            continue
        if (
            isinstance(left, ast.Name)
            and left.id == parameter
            and _is_ellipsis_reference(right)
        ) or (
            isinstance(right, ast.Name)
            and right.id == parameter
            and _is_ellipsis_reference(left)
        ):
            return True
    return False


def _function_body_graph(node):
    nodes = []
    parents = {}
    pending = [(stmt, node) for stmt in reversed(node.body)]
    while pending:
        candidate, parent = pending.pop()
        nodes.append(candidate)
        parents[id(candidate)] = parent
        if isinstance(
            candidate,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
        ):
            continue
        pending.extend(
            (child, candidate)
            for child in reversed(list(ast.iter_child_nodes(candidate)))
        )
    return nodes, parents


def _is_same_name_keyword_passthrough(node, parents, parameter):
    keyword = parents.get(id(node))
    if not (
        isinstance(keyword, ast.keyword)
        and keyword.arg == parameter
        and keyword.value is node
    ):
        return False
    call = parents.get(id(keyword))
    return (
        isinstance(call, ast.Call)
        and keyword in call.keywords
        and _call_has_passthrough_context(call, parents)
    )


def _call_has_passthrough_context(node, parents):
    current = node
    while (parent := parents.get(id(current))) is not None:
        if isinstance(parent, ast.Await):
            current = parent
            continue
        if isinstance(parent, ast.keyword) and parent.value is current:
            current = parent
            continue
        if isinstance(parent, ast.Starred) and parent.value is current:
            current = parent
            continue
        if isinstance(parent, ast.Call) and (
            current in parent.args or current in parent.keywords
        ):
            current = parent
            continue
        return isinstance(parent, (ast.Expr, ast.Return, ast.Assign, ast.AnnAssign))
    return False
