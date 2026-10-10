"""Bounded before/after proofs for Python authentication control changes.

Only direct, unshadowed Django imports are safety evidence. Similar helper
names, comments, and a check in another function do not preserve a control.
"""

from __future__ import annotations

import ast
import re
from collections import Counter

_LOGIN = "django.contrib.auth.decorators.login_required"
_DENIED = "django.core.exceptions.PermissionDenied"
_FORBIDDEN = "django.http.HttpResponseForbidden"
_RESPONSE = "django.http.HttpResponse"
_HEADER = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _stored_root(node):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name
    if isinstance(node, ast.arg):
        return node.arg
    if not isinstance(getattr(node, "ctx", None), ast.Store):
        return None
    if isinstance(node, ast.Name):
        return node.id
    value = node.value if isinstance(node, ast.Subscript) else node
    path = _dotted(value)
    return path.split(".")[0] if path else None


def _import_bindings(node, module_level, names, imports):
    if isinstance(node, ast.Import):
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            names[name] += 1
            if module_level:
                imports[name] = alias.name if alias.asname else name
        return False
    if not isinstance(node, ast.ImportFrom) or not node.module or node.level:
        return False
    for alias in node.names:
        name = alias.asname or alias.name
        names[name] += 1
        if module_level and alias.name != "*":
            imports[name] = f"{node.module}.{alias.name}"
    return any(alias.name == "*" for alias in node.names)


def _call_mutations(node, names):
    if not isinstance(node, ast.Call):
        return False
    target = _dotted(node.func)
    if target in {"setattr", "delattr"} and node.args:
        path = _dotted(node.args[0])
        if path:
            names[path.split(".")[0]] += 1
    return target in {"exec", "globals", "locals", "vars"}


def _escape_values(node):
    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
        return (node.value,)
    if isinstance(node, ast.Call):
        return (*node.args, *(kw.value for kw in node.keywords))
    return ()


def _bindings(tree):
    names = Counter()
    imports = {}
    dynamic = False
    nodes = list(ast.walk(tree))
    for node in nodes:
        stored = _stored_root(node)
        if stored:
            names[stored] += 1
        dynamic_import = _import_bindings(node, node in tree.body, names, imports)
        dynamic_call = _call_mutations(node, names)
        dynamic = dynamic or dynamic_import or dynamic_call
    # Containers and aliases can escape an imported callable to code that
    # mutates it. Such escapes are outside the direct-import proof.
    for node in nodes:
        for value in _escape_values(node):
            names.update(_escaped_imports(value, imports))
    if dynamic:
        names["*dynamic*"] += 1
        return {}, names
    return {name: path for name, path in imports.items() if names[name] == 1}, names


def _escaped_imports(value, imports):
    return (
        {
            node.id
            for node in ast.walk(value)
            if isinstance(node, ast.Name) and node.id in imports
        }
        if value is not None
        else set()
    )


def _resolve(node, imports):
    name = _dotted(node)
    if not name:
        return None
    root, _, suffix = name.partition(".")
    path = imports.get(root)
    return path + ("." + suffix if suffix else "") if path else None


def _login(node, imports):
    call = node if isinstance(node, ast.Call) else None
    if _resolve(call.func if call else node, imports) != _LOGIN:
        return False
    return call is None or (
        not call.args
        and all(
            kw.arg in {"login_url", "redirect_field_name"}
            and isinstance(kw.value, ast.Constant)
            and (kw.value.value is None or isinstance(kw.value.value, str))
            for kw in call.keywords
        )
    )


def _literal_arguments(call):
    return all(isinstance(arg, ast.Constant) for arg in call.args) and all(
        kw.arg is not None and isinstance(kw.value, ast.Constant)
        for kw in call.keywords
    )


def _deny(statement, imports):
    if isinstance(statement, ast.Raise) and statement.cause is None:
        value = statement.exc
        if isinstance(value, ast.Call):
            return _resolve(value.func, imports) == _DENIED and _literal_arguments(
                value
            )
        return _resolve(value, imports) == _DENIED
    if isinstance(statement, ast.Return) and isinstance(statement.value, ast.Call):
        call = statement.value
        target = _resolve(call.func, imports)
        if not _literal_arguments(call):
            return False
        if target == _FORBIDDEN:
            return len(call.args) <= 1 and not any(
                kw.arg == "status" for kw in call.keywords
            )
        return target == _RESPONSE and any(
            kw.arg == "status" and kw.value.value in {401, 403} for kw in call.keywords
        )
    return False


def _guard(function, imports):
    args = function.args.posonlyargs + function.args.args
    if not args:
        return None
    body = function.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    if not body or not isinstance(body[0], ast.If):
        return None
    guard = body[0]
    if not isinstance(guard.test, ast.UnaryOp) or not isinstance(
        guard.test.op, ast.Not
    ):
        return None
    if _dotted(guard.test.operand) != f"{args[0].arg}.user.is_authenticated":
        return None
    if guard.orelse or len(guard.body) != 1 or not _deny(guard.body[0], imports):
        return None
    return guard


def _removed_positions(diff_text):
    old = new = 0
    removed = {}
    for line in diff_text.splitlines():
        match = _HEADER.match(line)
        if match:
            old, new = map(int, match.groups())
        elif line.startswith(("---", "+++", "diff ", "index ")):
            continue
        elif line.startswith("-"):
            removed[old] = max(new, 1)
            old += 1
        elif line.startswith("+"):
            new += 1
        elif line.startswith(" "):
            old += 1
            new += 1
    return removed


def _only_removed_definition(function, old_tree, new_tree, new_bindings):
    if new_bindings[function.name] or new_bindings["*dynamic*"]:
        return False
    # Name disappearance alone is insufficient: a renamed handler, lambda or
    # new route registration can preserve its sensitive implementation. Only
    # deletion with no added/changed module statements proves this body gone.
    available = Counter(
        ast.dump(node) for node in old_tree.body if node is not function
    )
    remaining = Counter(ast.dump(node) for node in new_tree.body)
    return not (remaining - available)


def _function_controls(function, imports, bindings):
    if function is None or bindings[function.name] != 1:
        return False, False
    decorators = function.decorator_list
    login = bool(decorators and _login(decorators[0], imports))
    guard = bool(not decorators and _guard(function, imports))
    return login, guard


def _deletion_anchors(node, removed):
    lines = set(range(node.lineno, node.end_lineno + 1)).intersection(removed)
    return {removed[line] for line in lines}, lines


def _decorator_name(decorator, imports, auth_names):
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    name = _dotted(target)
    if name and (name.split(".")[-1] in auth_names or _login(decorator, imports)):
        return name
    return None


def _decorator_change(
    decorator, function, current, kept, removed, imports, auth_names, deleted
):
    name = _decorator_name(decorator, imports, auth_names)
    if name is None:
        return None, set()
    anchors, lines = _deletion_anchors(decorator, removed)
    proven_login = _login(decorator, imports)
    if not anchors and not (proven_login and current is not None and not kept):
        return None, set()
    if deleted or (proven_login and kept):
        return None, lines
    anchor = min(anchors) if anchors else current.lineno
    message = (
        f"Auth decorator @{name} was removed from '{function.name}'"
        if anchors
        else f"Authentication decorator @{name} in '{function.name}' no longer resolves to a proven control"
    )
    return (anchor, message), lines


def _guard_change(function, current, kept, removed, imports, deleted):
    guard = _guard(function, imports)
    if guard is None:
        return None, set()
    anchors, _ = _deletion_anchors(guard, removed)
    if deleted or kept:
        return None, anchors
    fallback = current.lineno if current else function.lineno
    anchor = min(anchors) if anchors else fallback
    message = (
        f"Authentication guard was removed from '{function.name}'"
        if anchors
        else f"Authentication guard in '{function.name}' is no longer a proven rejecting boundary"
    )
    return (anchor, message), anchors


def _function_changes(function, current, trees, bindings, imports, removed, auth_names):
    old_tree, new_tree = trees
    old_imports, new_imports = imports
    login, guard = _function_controls(current, new_imports, bindings)
    deleted = current is None and _only_removed_definition(
        function, old_tree, new_tree, bindings
    )
    changes, decorators = [], set()
    for decorator in function.decorator_list:
        change, lines = _decorator_change(
            decorator,
            function,
            current,
            login or guard,
            removed,
            old_imports,
            auth_names,
            deleted,
        )
        decorators.update(lines)
        if change:
            changes.append(change)
    change, handled = _guard_change(
        function, current, login or guard, removed, old_imports, deleted
    )
    if change:
        changes.append(change)
    return changes, handled, decorators


def python_auth_changes(
    diff_text, old_source, new_source, auth_names, *, allow_django_proofs=True
):
    """Return losses plus handled deletion anchors, or None without full context."""
    if old_source is None or new_source is None:
        return None
    try:
        old_tree, new_tree = ast.parse(old_source), ast.parse(new_source)
    except (SyntaxError, ValueError, TypeError, RecursionError):
        return None
    old_imports, _ = _bindings(old_tree)
    new_imports, new_bindings = _bindings(new_tree)
    if not allow_django_proofs:
        new_imports = {}
    function_types = (ast.FunctionDef, ast.AsyncFunctionDef)
    old_functions = [node for node in old_tree.body if isinstance(node, function_types)]
    new_functions = {
        node.name: node for node in new_tree.body if isinstance(node, function_types)
    }
    removed = _removed_positions(diff_text)
    changes, handled, decorators = [], set(), set()
    for function in old_functions:
        losses, guards, lines = _function_changes(
            function,
            new_functions.get(function.name),
            (old_tree, new_tree),
            new_bindings,
            (old_imports, new_imports),
            removed,
            auth_names,
        )
        changes.extend(losses)
        handled.update(guards)
        decorators.update(lines)
    return changes, handled, decorators
