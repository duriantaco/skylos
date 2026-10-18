"""Conservative proof that an empty default is only used to create fresh copies."""

import ast

from skylos.rules.quality._function_defaults import iter_arg_defaults


# Add APIs here only when they allocate independent storage without retaining
# their input. Empty literal defaults avoid shallow-copy aliases in their items.
_COPY_CONSTRUCTORS = {
    "builtins.dict": (ast.Dict, ast.List),
    "builtins.list": (ast.Dict, ast.List),
    "builtins.set": (ast.Dict, ast.List),
    # requests/structures.py: __init__ creates its own OrderedDict, then update
    # inserts the supplied entries. It does not retain the input mapping.
    "requests.structures.CaseInsensitiveDict": (ast.Dict,),
}
_REFLECTION_CALLS = {
    "locals",
    "globals",
    "vars",
    "eval",
    "exec",
    "getattr",
    "setattr",
    "delattr",
    "__import__",
    "__builtins__",
    "currentframe",
    "_getframe",
    "signature",
    "from_callable",
    "getfullargspec",
    "getargspec",
    "attrgetter",
    "getmembers",
    "getmembers_static",
    "__getattribute__",
    "__getattr__",
}
_REFLECTION_ATTRIBUTES = {
    "__defaults__",
    "__kwdefaults__",
    "__dict__",
    "__globals__",
    "__closure__",
    "__code__",
    "f_locals",
    "f_globals",
}
_NESTED_SCOPES = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.Lambda,
    ast.ListComp,
    ast.DictComp,
    ast.SetComp,
    ast.GeneratorExp,
)


def _dotted_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else ""
    return ""


def _imported_name(node, imports):
    name = _dotted_name(node)
    head, dot, tail = name.partition(".")
    return imports.get(head, head) + (dot + tail if dot else "")


def _names_copy_constructor(name):
    return any(
        constructor == name
        or constructor.startswith(f"{name}.")
        or name.startswith(f"{constructor}.")
        for constructor in _COPY_CONSTRUCTORS
    )


def _patches_copy_constructor(call, imports):
    name = _imported_name(call.func, imports)
    keywords = {keyword.arg: keyword.value for keyword in call.keywords}
    target = call.args[0] if call.args else keywords.get("target")
    if name.endswith("patch"):
        return (
            isinstance(target, ast.Constant)
            and isinstance(target.value, str)
            and _names_copy_constructor(target.value)
        )
    if name.endswith("patch.object"):
        attribute = call.args[1] if len(call.args) > 1 else keywords.get("attribute")
        return (
            isinstance(attribute, ast.Constant)
            and isinstance(attribute.value, str)
            and _names_copy_constructor(
                f"{_imported_name(target, imports)}.{attribute.value}"
            )
        )
    return False


def _copy_bindings(module):
    imports = {}
    for statement in module.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                local = alias.asname or alias.name.split(".")[0]
                imports[local] = alias.name if alias.asname else local
        elif isinstance(statement, ast.ImportFrom) and not statement.level:
            for alias in statement.names:
                imports[alias.asname or alias.name] = f"{statement.module}.{alias.name}"

    rebound = set()
    for node in ast.walk(module):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            source = _imported_name(node.value, imports)
            if source and (
                _names_copy_constructor(source)
                or source in {"dict", "list", "set"}
                or source.endswith(".patch")
                or source.endswith(".patch.object")
            ):
                return None
        if isinstance(node, ast.Call) and _patches_copy_constructor(node, imports):
            return None
        if isinstance(node, (ast.Name, ast.Attribute)):
            name = _dotted_name(node)
            head, dot, tail = name.partition(".")
            resolved = imports.get(head, head) + (dot + tail if dot else "")
            if (
                name.rsplit(".", 1)[-1] in _REFLECTION_CALLS
                or resolved.rsplit(".", 1)[-1] in _REFLECTION_CALLS
            ):
                return None
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            rebound.add(node.id)
        elif isinstance(node, ast.arg):
            rebound.add(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            rebound.add(node.name)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            rebound.add(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            rebound.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            rebound.add(node.rest)
        elif isinstance(node, ast.Attribute) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            head = _dotted_name(node).split(".")[0]
            if head in imports:
                # Another alias may refer to the same imported module object.
                return None
        elif isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                resolved = alias.name if alias.asname else local
                if imports.get(local) != resolved:
                    rebound.add(local)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    return None
                local = alias.asname or alias.name
                if node.level or imports.get(local) != f"{node.module}.{alias.name}":
                    rebound.add(local)
        elif isinstance(node, ast.Attribute) and node.attr in _REFLECTION_ATTRIBUTES:
            return None
        elif isinstance(node, ast.Call) and _dotted_name(node.func).rsplit(".", 1)[-1] in {
            "exec", "eval", "setattr", "delattr",
        }:
            return None
    return imports, rebound


def _resolved_constructor(node, bindings):
    imports, rebound = bindings
    name = _dotted_name(node)
    head, dot, tail = name.partition(".")
    if not head or head in rebound:
        return ""
    if head in imports:
        return imports[head] + (dot + tail if dot else "")
    if not dot and head in {"dict", "list", "set"}:
        return f"builtins.{head}"
    return ""


def _only_copies_parameter(function, parameter, default, bindings):
    uses = 0
    pending = [(statement, None, False) for statement in function.body]
    while pending:
        node, parent, nested = pending.pop()
        if isinstance(node, ast.Call):
            name = _dotted_name(node.func).rsplit(".", 1)[-1]
            if name in _REFLECTION_CALLS:
                return False
        if isinstance(node, ast.Attribute) and node.attr in _REFLECTION_ATTRIBUTES:
            return False
        if isinstance(node, (ast.Global, ast.Nonlocal)) and parameter in node.names:
            return False
        if isinstance(node, ast.arg) and node.arg == parameter:
            return False
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == parameter:
                return False
        if isinstance(node, ast.ExceptHandler) and node.name == parameter:
            return False
        if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name == parameter:
            return False
        if isinstance(node, ast.MatchMapping) and node.rest == parameter:
            return False
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                local = alias.asname or (
                    alias.name.split(".")[0] if isinstance(node, ast.Import) else alias.name
                )
                if local == parameter:
                    return False
        if isinstance(node, ast.Name) and node.id == parameter:
            if nested or not isinstance(node.ctx, ast.Load):
                return False
            constructor = (
                _resolved_constructor(parent.func, bindings)
                if isinstance(parent, ast.Call)
                else ""
            )
            if not (
                isinstance(parent, ast.Call)
                and len(parent.args) == 1
                and parent.args[0] is node
                and not parent.keywords
                and isinstance(default, _COPY_CONSTRUCTORS.get(constructor, ()))
            ):
                return False
            uses += 1
        child_nested = nested or isinstance(node, _NESTED_SCOPES)
        pending.extend((child, node, child_nested) for child in ast.iter_child_nodes(node))
    return uses > 0


def copy_only_default_ids(module):
    """Return IDs only for defaults with complete module and body evidence."""
    candidates = [
        (function, argument.arg, default)
        for function in ast.walk(module)
        if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
        for argument, default in iter_arg_defaults(function)
        if isinstance(default, (ast.List, ast.Dict))
        and not (default.elts if isinstance(default, ast.List) else default.keys)
    ]
    if not candidates:
        return set()
    bindings = _copy_bindings(module)
    if bindings is None:
        return set()
    return {
        id(default)
        for function, parameter, default in candidates
        if _only_copies_parameter(function, parameter, default, bindings)
    }
