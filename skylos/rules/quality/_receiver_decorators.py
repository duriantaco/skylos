"""Lexical decorator bindings and bounded, snapshot-aware source resolution."""

import ast
import os
from pathlib import Path

from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.rules.quality._receiver_descriptors import _instance_descriptor
from skylos.rules.quality._receivers import FUNCTION_NODES, _Bindings, _bound_names


def resolve_method_kinds(
    node: ast.Module | ast.ClassDef,
    *,
    filename=None,
    project_root=None,
    source_reader=None,
    _exports=None,
    _import_cache=None,
    _budget=None,
    _depth=0,
):
    """Resolve known descriptor constructors at their lexical definition site.

    Unknown decorators do not establish an implicit receiver. This deliberately
    does not execute decorators or infer descriptors from their spelling.
    """
    result = {}
    import_cache = {} if _import_cache is None else _import_cache
    budget = [16] if _budget is None else _budget
    builtin_bindings = {
        "staticmethod": "static",
        "classmethod": "class",
        "property": "property",
        "getattr": "builtin-getattr",
    }

    def stdlib_unshadowed(module):
        if module == "builtins" or not project_root:
            return True
        key = ("stdlib", module)
        if key in import_cache:
            return import_cache[key]
        root = Path(os.path.abspath(project_root))
        for base in (root, root / "src"):
            for path in (base / (module + ".py"), base / module / "__init__.py"):
                if budget[0] <= 0:
                    import_cache[key] = False
                    return False
                budget[0] -= 1
                if source_reader is not None:
                    try:
                        source = source_reader(path.relative_to(root))
                    except (OSError, ValueError, UnicodeError):
                        import_cache[key] = False
                        return False
                    present = source is not None
                else:
                    source = read_project_text_no_symlink(
                        root, path, max_bytes=2_000_000
                    )
                    present = source is not None
                    if not present:
                        try:
                            # Metadata alone suffices to reject an unreadable,
                            # oversized or symlinked potential module shadow.
                            path.lstat()
                            present = True
                        except FileNotFoundError:
                            pass
                        except OSError:
                            present = True
                if present:
                    import_cache[key] = False
                    return False
        import_cache[key] = True
        return True

    def relative_export(statement, name):
        if not filename or not project_root or _depth >= 4:
            return "unknown"
        parts = (statement.module or "").split(".")
        if not parts or not all(part.isidentifier() for part in parts):
            return "unknown"
        base = Path(filename).parent
        for _ in range(statement.level - 1):
            base = base.parent
        base = base.joinpath(*parts)
        for path in (base / "__init__.py", base.with_suffix(".py")):
            key = str(path)
            if key not in import_cache:
                if budget[0] <= 0:
                    return "unknown"
                budget[0] -= 1
                import_cache[key] = None  # Active import: cycles stay unresolved.
                if source_reader is None:
                    source = read_project_text_no_symlink(
                        project_root, path, max_bytes=2_000_000
                    )
                else:
                    # Historical/diff scans must read the same source snapshot
                    # as the current AST, never mix it with working-tree files.
                    try:
                        root_path = Path(os.path.abspath(project_root))
                        relative = Path(os.path.abspath(path)).relative_to(root_path)
                        source = source_reader(relative)
                    except (OSError, ValueError, UnicodeError):
                        source = None
                    if (
                        not isinstance(source, str)
                        or len(source.encode("utf-8")) > 2_000_000
                    ):
                        source = None
                if source is None:
                    if source_reader is None:
                        try:
                            path.lstat()
                        except FileNotFoundError:
                            continue
                        except OSError:
                            pass
                        # An unreadable/unsafe package is not permission to
                        # resolve a different same-name module instead.
                        import_cache[key] = {}
                        return "unknown"
                    continue
                try:
                    imported_tree = ast.parse(source)
                except (SyntaxError, ValueError, RecursionError):
                    import_cache[key] = {}
                    return "unknown"
                exports = {}
                resolve_method_kinds(
                    imported_tree,
                    filename=str(path),
                    project_root=project_root,
                    source_reader=source_reader,
                    _exports=exports,
                    _import_cache=import_cache,
                    _budget=budget,
                    _depth=_depth + 1,
                )
                import_cache[key] = exports
            exports = import_cache[key]
            if exports is not None:
                return exports.get(name, "unknown")
        return "unknown"

    def value_kind(expr, env):
        if isinstance(expr, ast.Name):
            return env.get(expr.id, "unknown")
        if isinstance(expr, ast.Attribute):
            base = value_kind(expr.value, env)
            if base == "builtins":
                return builtin_bindings.get(expr.attr, "unknown")
            if base == "property-value" and expr.attr in {
                "getter",
                "setter",
                "deleter",
            }:
                return "preserve"
            if base == "abc" and expr.attr in {"abstractmethod", "abstractproperty"}:
                return "preserve"
            if base == "functools" and expr.attr == "cached_property":
                return "property"
            if base == "contextlib" and expr.attr in {
                "contextmanager",
                "asynccontextmanager",
            }:
                return "preserve"
        return "unknown"

    def bind(target, value, env):
        if isinstance(target, ast.Name):
            env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            for child in target.elts:
                bind(child, "unknown", env)

    def identity_function(function):
        body = list(function.body)
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            body = body[1:]
        positional = [*function.args.posonlyargs, *function.args.args]
        return (
            isinstance(function, ast.FunctionDef)
            and not function.decorator_list
            and len(positional) == 1
            and not function.args.kwonlyargs
            and function.args.vararg is None
            and function.args.kwarg is None
            and len(body) == 1
            and isinstance(body[0], ast.Return)
            and isinstance(body[0].value, ast.Name)
            and body[0].value.id == positional[0].arg
        )

    def scan(statements, env, scope, closure_env):
        for statement in statements:
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    local = alias.asname or alias.name.split(".")[0]
                    env[local] = (
                        alias.name
                        if alias.name in {"builtins", "abc", "functools", "contextlib"}
                        and stdlib_unshadowed(alias.name)
                        else "unknown"
                    )
            elif isinstance(statement, ast.ImportFrom):
                for alias in statement.names:
                    module_env = {"_module": statement.module or "unknown"}
                    if statement.module in {
                        "builtins",
                        "abc",
                        "functools",
                        "contextlib",
                    } and not stdlib_unshadowed(statement.module):
                        module_env["_module"] = "unknown"
                    env[alias.asname or alias.name] = (
                        value_kind(
                            ast.Attribute(
                                value=ast.Name(id="_module"), attr=alias.name
                            ),
                            module_env,
                        )
                        if statement.level == 0
                        else relative_export(statement, alias.name)
                    )
            elif isinstance(statement, ast.Assign):
                kind = value_kind(statement.value, env)
                for target in statement.targets:
                    bind(target, kind, env)
            elif isinstance(statement, ast.AnnAssign):
                if statement.value is not None:
                    bind(statement.target, value_kind(statement.value, env), env)
            elif isinstance(statement, FUNCTION_NODES):
                kind = "instance"
                property_value = False
                for decorator in reversed(statement.decorator_list):
                    constructor = value_kind(decorator, env)
                    if constructor in {"static", "class"}:
                        if kind != "unknown":
                            kind = constructor
                    elif constructor == "property":
                        if kind != "unknown":
                            kind = "instance"
                            property_value = True
                    elif constructor != "preserve":
                        kind = "unknown"
                if scope == "class":
                    result[statement] = kind
                # Method bodies do not close over their class namespace.
                inner = dict(closure_env if scope == "class" else env)
                for name in _bound_names(statement):
                    inner[name] = "unknown"
                scan(statement.body, inner, "function", inner)
                env[statement.name] = (
                    "preserve"
                    if identity_function(statement)
                    else "property-value"
                    if property_value
                    else "unknown"
                )
            elif isinstance(statement, ast.ClassDef):
                inherited = closure_env if scope == "class" else env
                scan(statement.body, dict(inherited), "class", dict(inherited))
                env[statement.name] = (
                    "property"
                    if _instance_descriptor(statement, bindings=env, kinds=result)
                    else "unknown"
                )
            elif isinstance(statement, ast.If):
                left, right = dict(env), dict(env)
                scan(statement.body, left, scope, closure_env)
                scan(statement.orelse, right, scope, closure_env)
                if isinstance(statement.test, ast.Constant) and isinstance(
                    statement.test.value, bool
                ):
                    env.update(left if statement.test.value else right)
                else:
                    for name in left.keys() | right.keys():
                        env[name] = (
                            left.get(name, "unknown")
                            if left.get(name) == right.get(name)
                            else "unknown"
                        )
            elif isinstance(statement, ast.Try):
                normal = dict(env)
                scan(statement.body, normal, scope, closure_env)
                scan(statement.orelse, normal, scope, closure_env)
                outcomes = [normal]
                for handler in statement.handlers:
                    branch = dict(env)
                    if handler.name:
                        branch[handler.name] = "unknown"
                    scan(handler.body, branch, scope, closure_env)
                    outcomes.append(branch)
                for name in set().union(*(branch.keys() for branch in outcomes)):
                    values = {branch.get(name, "unknown") for branch in outcomes}
                    env[name] = values.pop() if len(values) == 1 else "unknown"
                scan(statement.finalbody, env, scope, closure_env)
            else:
                blocks = []
                for field in ("body", "orelse", "finalbody"):
                    blocks.append(getattr(statement, field, []))
                blocks.extend(
                    handler.body for handler in getattr(statement, "handlers", [])
                )
                blocks.extend(case.body for case in getattr(statement, "cases", []))
                bindings = _Bindings()
                bindings.visit(statement)
                for block in blocks:
                    scan(block, dict(env), scope, closure_env)
                for name in bindings.names:
                    env[name] = "unknown"

    initial = dict(builtin_bindings)
    if isinstance(node, ast.ClassDef):
        scan(node.body, initial, "class", dict(initial))
    else:
        scan(node.body, initial, "module", initial)
    if _exports is not None:
        _exports.update(initial)
    return result
