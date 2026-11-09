"""TLS provider identities and conservative context configuration evidence."""

from __future__ import annotations

import ast

from pathlib import Path

from .import_proof import (
    import_environment_is_stable,
    provider_binding_is_stable,
    project_provider_effects_are_stable,
)
from .module_namespace import module_rebinding, module_name_for
from .project_source import project_source_snapshot

_SCOPES = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
_BROWSER_MODULES = ("playwright.", "crawl4ai.", "browser_use.")
_VALUE_FIELDS = frozenset(
    {
        "verify_mode",
        "check_hostname",
        "protocol",
        "minimum_version",
        "maximum_version",
        "options",
        "verify_flags",
        "security_level",
        "hostname_checks_common_name",
        "num_tickets",
        "post_handshake_auth",
    }
)
_CONTEXT_METHODS = frozenset(
    {
        "load_cert_chain",
        "load_default_certs",
        "load_verify_locations",
        "set_ciphers",
        "set_alpn_protocols",
        "set_npn_protocols",
        "get_ciphers",
        "get_ca_certs",
        "cert_store_stats",
        "session_stats",
        "wrap_socket",
        "wrap_bio",
    }
)


def _scope(node):
    current = getattr(node, "parent", None)
    while current is not None and not isinstance(current, _SCOPES):
        current = getattr(current, "parent", None)
    return current


class _Bindings:
    def __init__(self, tree):
        self.tree = tree
        self.bound = {}
        self.scope_loads = {}
        self.inert_definitions = {}
        for node in ast.walk(tree):
            scope = _scope(node)
            pairs = []
            if isinstance(node, ast.Import):
                pairs = [
                    (
                        a.asname or a.name.split(".")[0],
                        a.name if a.asname else a.name.split(".")[0],
                    )
                    for a in node.names
                ]
            elif isinstance(node, ast.ImportFrom):
                pairs = [
                    (
                        a.asname or a.name,
                        f"{node.module}.{a.name}" if not node.level else None,
                    )
                    for a in node.names
                    if a.name != "*"
                ]
            elif isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                pairs = [(node.name, node)]
            elif isinstance(node, ast.arg):
                pairs = [(node.arg, None)]
            elif isinstance(node, ast.Name) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                parent = getattr(node, "parent", None)
                value = None
                if isinstance(parent, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                    value = parent.value
                elif isinstance(parent, ast.withitem):
                    value = parent.context_expr
                pairs = [(node.id, value)]
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                pairs = [(name, None) for name in node.names]
            for name, value in pairs:
                self.bound.setdefault((id(scope), name), []).append(value)

    def name(self, node, seen=frozenset()):
        if node is None or id(node) in seen or len(seen) > 32:
            return None
        seen = seen | {id(node)}
        if isinstance(node, ast.Call):
            return self.name(node.func, seen)
        if isinstance(node, ast.Attribute):
            base = self.name(node.value, seen)
            return f"{base}.{node.attr}" if base else None
        if not isinstance(node, ast.Name):
            return None
        scope = _scope(node)
        inside_function = False
        while scope is not None:
            if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                inside_function = True
            if not (inside_function and isinstance(scope, ast.ClassDef)):
                values = self.bound.get((id(scope), node.id))
                if values is not None:
                    if len(values) != 1:
                        return None
                    value = values[0]
                    if isinstance(
                        value, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                    ):
                        return "!local"
                    return value if isinstance(value, str) else self.name(value, seen)
            scope = _scope(scope)
        return None

    def value(self, node, seen=frozenset()):
        if node is None or id(node) in seen or len(seen) > 32:
            return None
        if not isinstance(node, ast.Name):
            return node
        seen = seen | {id(node)}
        scope = _scope(node)
        while scope is not None:
            values = self.bound.get((id(scope), node.id))
            if values is not None:
                return self.value(values[0], seen) if len(values) == 1 else None
            scope = _scope(scope)
        return None


def _bindings(node):
    tree = node
    while getattr(tree, "parent", None) is not None:
        tree = tree.parent
    cached = getattr(tree, "_skylos_tls_bindings", None)
    if cached is None:
        cached = _Bindings(tree)
        tree._skylos_tls_bindings = cached
    return cached


def _safe_native_name(node, bindings, filename=None, project_root=None):
    """Imports used to suppress a finding must also survive visible writes."""
    if node is None:
        return None
    name = bindings.name(node)
    if (
        name
        and name != "!local"
        and provider_binding_is_stable(
            name, bindings.tree, filename or "<tree-only>", project_root
        )
    ):
        return name
    return None


def _constant_bool(node, value, bindings=None):
    if bindings is not None:
        node = bindings.value(node)
    return isinstance(node, ast.Constant) and node.value is value


def _uses(node, names):
    if node is None:
        return False
    pending = [node]
    steps = 0
    while pending:
        part = pending.pop()
        steps += 1
        if steps > 10000:
            # Optional safety is unavailable at the work boundary.
            return True
        if isinstance(part, ast.Name):
            if isinstance(part.ctx, ast.Load) and part.id in names:
                return True
        elif not (
            isinstance(part, ast.Attribute)
            and isinstance(part.ctx, ast.Load)
            and part.attr in _VALUE_FIELDS
        ):
            pending.extend(ast.iter_child_nodes(part))
    return False


def _client_use(node, names, bindings):
    if not isinstance(node, ast.Call) or not _uses(node, names):
        return False
    name = bindings.name(node.func) or ""
    if name.startswith(("urllib.", "requests.", "httpx.", "aiohttp.")):
        return True
    if (
        isinstance(node.func, ast.Attribute)
        and node.func.attr in {"wrap_socket", "wrap_bio"}
        or name in {"ssl.SSLContext.wrap_socket", "ssl.SSLContext.wrap_bio"}
    ):
        return not any(
            kw.arg == "server_side" and _constant_bool(kw.value, True)
            for kw in node.keywords
        )
    return False


def _context_unsafe(node, bindings, filename=None, project_root=None):
    def safe_name(value):
        return _safe_native_name(value, bindings, filename, project_root)

    constructor_stable = provider_binding_is_stable(
        "ssl.SSLContext", bindings.tree, filename or "<tree-only>", project_root
    )

    def requires_certificates(value):
        literal = bindings.value(value)
        return safe_name(value) == "ssl.CERT_REQUIRED" or (
            constructor_stable
            and isinstance(literal, ast.Constant)
            and type(literal.value) is int
            and literal.value == 2
        )

    def native_context_method(call):
        if not constructor_stable:
            return None
        name = bindings.name(call.func)
        if (
            name
            and name.startswith("ssl.SSLContext.")
            and name.rsplit(".", 1)[-1] in _CONTEXT_METHODS
        ):
            return name.rsplit(".", 1)[-1]
        return None

    protocol = node.args[0] if node.args else None
    for keyword in node.keywords:
        if keyword.arg == "protocol":
            protocol = keyword.value
    protocol_name = bindings.name(protocol)
    client_default = (
        constructor_stable and safe_name(protocol) == "ssl.PROTOCOL_TLS_CLIENT"
    )
    if constructor_stable and safe_name(protocol) == "ssl.PROTOCOL_TLS_SERVER":
        return False
    # An unknown protocol may be a caller-supplied server context. Preserve
    # the existing constructor warning for native nonverifying protocols.
    if protocol is not None and protocol_name is None:
        return False
    verify, hostname = client_default, client_default
    parent = getattr(node, "parent", None)
    names = set()
    if isinstance(parent, ast.Assign) and all(
        isinstance(target, ast.Name) for target in parent.targets
    ):
        names.update(target.id for target in parent.targets)
    elif isinstance(parent, ast.AnnAssign) and isinstance(parent.target, ast.Name):
        names.add(parent.target.id)
    scope = _scope(node)
    if not names or scope is None:
        return not client_default
    for _ in range(16):
        before = set(names)
        for part in ast.walk(scope):
            if isinstance(part, ast.Assign) and _uses(part.value, names):
                names.update(t.id for t in part.targets if isinstance(t, ast.Name))
        if before == names:
            break
    if parent not in getattr(scope, "body", []):
        # Conditional construction cannot borrow unconditional setup from a
        # different branch. Native client defaults still need to retain any
        # visible disabling write in that context's scope.
        if not client_default:
            return True
        for part in ast.walk(scope):
            if isinstance(part, ast.Call) and _uses(part, names):
                if _client_use(part, names, bindings):
                    continue
                if native_context_method(part):
                    continue
                return True
            if not isinstance(part, (ast.Assign, ast.AnnAssign)):
                continue
            targets = part.targets if isinstance(part, ast.Assign) else [part.target]
            for target in targets:
                if (
                    isinstance(target, ast.Attribute)
                    and _uses(target.value, names)
                    and target.attr in _CONTEXT_METHODS | {"__class__", "__dict__"}
                ):
                    return True
                if (
                    part is not parent
                    and isinstance(target, ast.Name)
                    and target.id in names
                    and not (_uses(part.value, names))
                ):
                    return True
                if isinstance(target, (ast.Attribute, ast.Subscript)) and _uses(
                    part.value, names
                ):
                    return True
                if not (
                    isinstance(target, ast.Attribute) and _uses(target.value, names)
                ):
                    continue
                if target.attr == "verify_mode" and not requires_certificates(
                    part.value
                ):
                    return True
                if target.attr == "check_hostname" and not _constant_bool(
                    part.value, True, bindings
                ):
                    return True
        return False
    body = scope.body
    following = body[body.index(parent) + 1 :]
    client = any(
        _client_use(part, names, bindings)
        for statement in following
        for part in ast.walk(statement)
    )
    server_certificate = False
    hostname_disabled = False
    for statement in following:
        handled = set()
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
            for assigned in targets:
                if (
                    isinstance(assigned, ast.Attribute)
                    and _uses(assigned.value, names)
                    and assigned.attr in _CONTEXT_METHODS | {"__class__", "__dict__"}
                ):
                    return True
                if (
                    isinstance(assigned, ast.Name)
                    and assigned.id in names
                    and not (_uses(statement.value, names))
                ):
                    # A later object cannot lend its configuration to the
                    # original context or to a saved alias of that context.
                    return True
                if isinstance(assigned, (ast.Attribute, ast.Subscript)) and _uses(
                    statement.value, names
                ):
                    return True
                if (
                    isinstance(assigned, ast.Attribute)
                    and _uses(assigned.value, names)
                    and assigned.attr in {"verify_mode", "check_hostname"}
                ):
                    if assigned.attr == "verify_mode":
                        verify = requires_certificates(statement.value)
                    else:
                        hostname = _constant_bool(statement.value, True, bindings)
                        hostname_disabled = not hostname
                    handled.add(id(assigned))
        if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
            call = statement.value
            if native_context_method(call) == "load_cert_chain" and _uses(call, names):
                server_certificate = True
                handled.add(id(call))
        for part in ast.walk(statement):
            if (
                isinstance(part, ast.Attribute)
                and _uses(part.value, names)
                and part.attr in {"verify_mode", "check_hostname"}
                and isinstance(part.ctx, (ast.Store, ast.Del))
                and id(part) not in handled
            ):
                return True
            if isinstance(part, ast.Call) and _uses(part, names):
                if id(part) in handled:
                    continue
                if isinstance(part.func, ast.Attribute) and part.func.attr in {
                    "__setattr__",
                    "__delattr__",
                }:
                    return True
                if isinstance(part.func, ast.Name) and part.func.id in {
                    "setattr",
                    "delattr",
                }:
                    return True
                if _client_use(part, names, bindings) and not (verify and hostname):
                    return True
                if _client_use(part, names, bindings):
                    continue
                if native_context_method(part):
                    continue
                # A callback given the context can turn verification off;
                # its name is not evidence of a harmless configuration.
                return True
        if isinstance(statement, ast.Return) and _uses(statement, names):
            return not (
                verify
                and (hostname or not client and not hostname_disabled)
                or server_certificate
                and not client
            )
    return not (
        verify
        and (hostname or not client and not hostname_disabled)
        or server_certificate
        and not client
    )


def _pure_local_definition(definition):
    """A small data-only function/DTO, with no callbacks or object protocols."""
    if isinstance(definition, ast.ClassDef):
        if definition.bases or definition.keywords or definition.decorator_list:
            return False
        for statement in definition.body:
            if isinstance(statement, ast.Expr) and isinstance(
                statement.value, ast.Constant
            ):
                continue
            if isinstance(statement, ast.Pass):
                continue
            if (
                not isinstance(statement, ast.FunctionDef)
                or statement.name != "__init__"
                or statement.decorator_list
            ):
                return False
            for part in ast.walk(statement):
                if isinstance(part, ast.Attribute) and not (
                    isinstance(part.ctx, ast.Store)
                    and isinstance(part.value, ast.Name)
                    and part.value.id == "self"
                    and not part.attr.startswith("__")
                ):
                    return False
                if isinstance(
                    part,
                    (
                        ast.Call,
                        ast.Await,
                        ast.Yield,
                        ast.YieldFrom,
                        ast.Global,
                        ast.Nonlocal,
                        ast.Import,
                        ast.ImportFrom,
                        ast.For,
                        ast.AsyncFor,
                        ast.While,
                        ast.With,
                        ast.AsyncWith,
                        ast.Subscript,
                        ast.BinOp,
                        ast.Compare,
                        ast.UnaryOp,
                    ),
                ):
                    return False
        return True
    if not isinstance(definition, ast.FunctionDef) or definition.decorator_list:
        return False
    forbidden = (
        ast.Call,
        ast.Attribute,
        ast.Subscript,
        ast.Await,
        ast.Yield,
        ast.YieldFrom,
        ast.Global,
        ast.Nonlocal,
        ast.Import,
        ast.ImportFrom,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.With,
        ast.AsyncWith,
        ast.BinOp,
        ast.UnaryOp,
        ast.Compare,
        ast.BoolOp,
        ast.ListComp,
        ast.SetComp,
        ast.DictComp,
        ast.GeneratorExp,
        ast.Lambda,
        ast.ClassDef,
    )
    return not any(
        isinstance(part, forbidden)
        for statement in definition.body
        for part in ast.walk(statement)
    )


def _discarded_result(node, bindings):
    parent = getattr(node, "parent", None)
    if isinstance(parent, ast.Expr):
        return True
    if isinstance(parent, (ast.Assign, ast.AnnAssign)):
        targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
        if all(isinstance(target, ast.Name) for target in targets):
            names = {target.id for target in targets}
            scope = _scope(node)
            if scope is None:
                return False
            loaded = bindings.scope_loads.get(id(scope))
            if loaded is None:
                loaded = {
                    part.id
                    for part in ast.walk(scope)
                    if isinstance(part, ast.Name) and isinstance(part.ctx, ast.Load)
                }
                bindings.scope_loads[id(scope)] = loaded
            return not names & loaded
    return False


def _local_provider_definition(qualified, bindings, filename, project_root):
    if not filename or not import_environment_is_stable(bindings.tree):
        return None
    try:
        original_source = Path(filename)
        source = original_source.resolve()
        root = Path(project_root).resolve() if project_root else source.parent
        if (
            original_source.is_symlink()
            or not source.is_file()
            or not source.is_relative_to(root)
        ):
            return None
        module, separator, member = qualified.partition(".")
        if not separator or "." in member:
            return None
        sources, complete = project_source_snapshot(root)
        if not complete:
            return None
        # A package sibling does not satisfy an absolute provider import.
        # The explicit project root bounds this negative proof; filename-only
        # callers retain their directory as the root of their source snapshot.
        directory = root
        for _ in range(64):
            if any(
                path.suffix in {".so", ".pyd"} for path in directory.glob(module + ".*")
            ):
                return None
            candidates = [
                path
                for path in (
                    directory / (module + ".py"),
                    directory / module / "__init__.py",
                )
                if path.is_file()
            ]
            if candidates:
                if len(candidates) != 1:
                    return None
                candidate = candidates[0]
                if (
                    candidate == directory / (module + ".py")
                    and (directory / module).exists()
                ):
                    # A package may have only an opaque compiled initializer;
                    # selecting the adjacent source module is not a proof of
                    # which implementation Python will import.
                    return None
                if (
                    candidate.is_symlink()
                    or not candidate.resolve().is_relative_to(root)
                    or candidate.stat().st_size > 2_000_000
                ):
                    return None
                if any(
                    path.suffix in {".so", ".pyd"}
                    for path in candidate.parent.glob("__init__.*")
                ):
                    return None
                ancestor = candidate.parent
                while ancestor != root:
                    if ancestor.is_symlink() or not ancestor.is_relative_to(root):
                        return None
                    ancestor = ancestor.parent
                parsed = sources.get(candidate)
                if parsed is None:
                    return None
                # A self-contained no-op provider can refute a native API;
                # a wrapper/re-export/imported implementation cannot.
                for statement in parsed.body:
                    if isinstance(statement, (ast.FunctionDef, ast.ClassDef)):
                        if not _pure_local_definition(statement):
                            return None
                    elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
                        if not isinstance(statement.value, ast.Constant):
                            return None
                    elif not (
                        isinstance(statement, ast.Expr)
                        and isinstance(statement.value, ast.Constant)
                    ):
                        return None
                return next(
                    (
                        statement
                        for statement in parsed.body
                        if isinstance(statement, (ast.FunctionDef, ast.ClassDef))
                        and statement.name == member
                    ),
                    None,
                )
            if (directory / module).exists() or directory == root:
                break
            directory = directory.parent
    except (OSError, RuntimeError, ValueError, TypeError):
        return None
    return None


def _local_callable_identities(definition, filename, project_root):
    if not filename:
        return set()
    try:
        source = Path(filename).resolve()
        root = Path(project_root).resolve() if project_root else source.parent
        if not source.is_file() or not source.is_relative_to(root):
            return set()
        parts = list(source.relative_to(root).with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
        identities = {".".join([*parts, definition.name])} if parts else set()
        packages = []
        directory = source.parent
        for _ in range(32):
            if not (directory / "__init__.py").is_file():
                break
            packages.insert(0, directory.name)
            directory = directory.parent
        tail = [] if source.stem == "__init__" else [source.stem]
        for start in range(len(packages)):
            identities.add(".".join([*packages[start:], *tail, definition.name]))
        return identities
    except (OSError, RuntimeError, ValueError, TypeError):
        return set()


def _local_data_method(node, bindings):
    """A direct, non-escaping instance whose method only returns plain data."""
    if not isinstance(node.func, ast.Attribute) or not isinstance(
        node.func.value, ast.Call
    ):
        return None, None
    constructor = node.func.value
    if constructor.args or constructor.keywords:
        return None, None
    owner = bindings.value(constructor.func)
    if (
        not isinstance(owner, ast.ClassDef)
        or not isinstance(getattr(owner, "parent", None), ast.Module)
        or owner.bases
        or owner.keywords
        or owner.decorator_list
    ):
        return None, None

    def data(value, parameters):
        if isinstance(value, ast.Constant):
            return True
        if isinstance(value, ast.Name):
            return value.id in parameters
        if isinstance(value, (ast.List, ast.Tuple)):
            return all(data(item, parameters) for item in value.elts)
        if isinstance(value, ast.Dict):
            return all(
                isinstance(key, ast.Constant) and data(item, parameters)
                for key, item in zip(value.keys, value.values)
            )
        return False

    selected = []
    for method in owner.body:
        if isinstance(method, ast.Pass) or (
            isinstance(method, ast.Expr) and isinstance(method.value, ast.Constant)
        ):
            continue
        if (
            not isinstance(method, ast.FunctionDef)
            or method.name.startswith("__")
            or not _pure_local_definition(method)
        ):
            return None, None
        arguments = [*method.args.posonlyargs, *method.args.args]
        parameters = {arg.arg for arg in arguments[1:] + method.args.kwonlyargs}
        parameters.update(
            arg.arg for arg in (method.args.vararg, method.args.kwarg) if arg
        )
        for statement in method.body:
            if isinstance(statement, ast.Pass) or (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Constant)
            ):
                continue
            if not isinstance(statement, ast.Return) or not data(
                statement.value, parameters
            ):
                return None, None
        if method.name == node.func.attr:
            selected.append(method)
    return (owner, selected[0]) if len(selected) == 1 else (None, None)


def _inert_call(node, bindings, qualified=None, filename=None, project_root=None):
    if not _discarded_result(node, bindings):
        return False
    owner, method = _local_data_method(node, bindings)
    definition = method or bindings.value(node.func)
    if isinstance(definition, (ast.FunctionDef, ast.ClassDef)):
        identity_owner = owner or definition
        identities = _local_callable_identities(identity_owner, filename, project_root)
        if not identities or not all(
            project_provider_effects_are_stable(
                identity, bindings.tree, filename, project_root
            )
            for identity in identities
        ):
            return False
        # Only AST-local body/identity facts are cached. Imported source and
        # import-provider metadata can change while a caller tree is reused.
        key = id(definition)
        cached = bindings.inert_definitions.get(key)
        if cached is not None:
            return cached
        bindings.inert_definitions[key] = False
        if module_rebinding(
            bindings.tree, module_name_for(filename) or "__tls_inert__"
        )[0]:
            return False
        # A local body does not prove the callable remains that implementation
        # after code replacement or an escaped callable alias.
        for part in ast.walk(bindings.tree):
            if (
                isinstance(part, ast.Name)
                and isinstance(part.ctx, ast.Load)
                and part.id == identity_owner.name
            ):
                parent = getattr(part, "parent", None)
                if not (isinstance(parent, ast.Call) and parent.func is part):
                    return False
        result = _pure_local_definition(definition)
        bindings.inert_definitions[key] = result
        return result
    elif qualified:
        if not project_provider_effects_are_stable(
            qualified, bindings.tree, filename, project_root
        ):
            return False
        definition = _local_provider_definition(
            qualified, bindings, filename, project_root
        )
    return _pure_local_definition(definition)


def tls_verification_disabled(
    node, fallback_name=None, *, filename=None, project_root=None
):
    bindings = _bindings(node)
    name = bindings.name(node.func)
    if (
        (name is None or name.startswith("!local"))
        and fallback_name
        and fallback_name.startswith(("ssl.", "requests.", "httpx."))
    ):
        # Unknown parameters and imported objects can still be the native
        # provider. Only a visible non-native binding refutes that candidate.
        name = fallback_name
    verify_off = any(
        kw.arg == "verify"
        and isinstance(kw.value, ast.Constant)
        and kw.value.value == 0
        for kw in node.keywords
    )
    ignore = any(
        kw.arg == "ignore_https_errors" and _constant_bool(kw.value, True)
        for kw in node.keywords
    )
    native_candidate = name in {"ssl.SSLContext", "ssl._create_unverified_context"} or (
        verify_off and name and name.startswith(("requests.", "httpx."))
    )
    if not (native_candidate or ignore):
        return None
    inert = _inert_call(node, bindings, name, filename, project_root)
    if inert:
        return None
    if verify_off and name and name.startswith(("requests.", "httpx.")):
        return f"{name.split('.')[0]} call with verify=False"
    if name == "ssl._create_unverified_context":
        return "TLS context disables certificate verification"
    if name == "ssl.SSLContext" and _context_unsafe(
        node, bindings, filename, project_root
    ):
        return "TLS context does not verify certificates or host names"
    if ignore:
        # Explicit disabling is still a candidate when an async/branch/
        # container receiver is unresolved. Only positive inert-body and
        # discarded-result evidence can refute the old candidate.
        return "Browser accepts any TLS certificate (ignore_https_errors=True)"
    return None
