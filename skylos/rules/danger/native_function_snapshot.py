"""An optional native callable proof used only for new nonce findings.

The original source context remains attested. Effect-only views can spell out
a bounded passive relative star import; shared provider proofs keep their
default policy. No scanned module is imported or executed.
"""

import ast
from pathlib import Path

from .import_proof import _provider_effects, provider_is_unshadowed
from .project_imports import ProjectImports, project_import_context
from .builtin_bindings import builtin_references
from .flow_env import _scope_bindings
from .module_namespace import module_name_for, module_rebinding
from .untrusted_sources import _unsafe_import_roots


NATIVE_NONCE_FUNCTIONS = frozenset(
    {
        "hashlib.md5",
        "hashlib.sha1",
        "hashlib.sha224",
        "hashlib.sha256",
        "hashlib.sha384",
        "hashlib.sha512",
        "time.ctime",
    }
)


def _passive_exception_exports(tree):
    known = {"Exception"}
    exported = []
    if sum(1 for _ in ast.walk(tree)) > 2048:
        return None
    for statement in tree.body:
        if isinstance(statement, ast.Pass) or (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        ):
            continue
        if (
            not isinstance(statement, ast.ClassDef)
            or statement.decorator_list
            or statement.keywords
            or getattr(statement, "type_params", ())
        ):
            return None
        if not statement.bases or not all(
            isinstance(base, ast.Name) and base.id in known for base in statement.bases
        ):
            return None
        for member in statement.body:
            if isinstance(member, ast.Pass) or (
                isinstance(member, ast.Expr)
                and isinstance(member.value, ast.Constant)
                and isinstance(member.value.value, str)
            ):
                continue
            if (
                not isinstance(member, ast.FunctionDef)
                or member.name == "__init_subclass__"
                or member.decorator_list
                or member.returns
                or getattr(member, "type_params", ())
            ):
                return None
            args = member.args
            parameters = [
                *args.posonlyargs,
                *args.args,
                *args.kwonlyargs,
                args.vararg,
                args.kwarg,
            ]
            if (
                args.defaults
                or any(value is not None for value in args.kw_defaults)
                or any(
                    arg is not None and arg.annotation is not None for arg in parameters
                )
            ):
                return None
        known.add(statement.name)
        if not statement.name.startswith("_"):
            exported.append(statement.name)
    return exported


def _effect_view(tree, path, context, provider):
    body = []
    imported_bindings = {
        alias.asname or alias.name.split(".", 1)[0]
        for statement in ast.walk(tree)
        if isinstance(statement, (ast.Import, ast.ImportFrom))
        for alias in statement.names
        if alias.name != "*"
    }
    stars = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and any(alias.name == "*" for alias in node.names)
    ]
    if not stars:
        return ast.Module(body=list(tree.body), type_ignores=tree.type_ignores)
    if any(node not in tree.body for node in stars):
        return None
    for node in tree.body:
        if node not in stars:
            body.append(node)
            continue
        if (
            node.level != 1
            or not node.module
            or any(not part.isidentifier() for part in node.module.split("."))
        ):
            return None
        target = path.parent.joinpath(*node.module.split(".")).with_suffix(".py")
        try:
            resolved = target.resolve(strict=True)
            if resolved != target or not resolved.is_relative_to(context.root):
                return None
        except (OSError, RuntimeError, ValueError):
            return None
        provider_tree = context.snapshot.get(resolved)
        if provider_tree is None:
            return None
        exports = _passive_exception_exports(provider_tree)
        if not exports or set(exports) & (set(provider.split(".")) | imported_bindings):
            return None
        explicit = ast.ImportFrom(
            module=node.module,
            names=[ast.alias(name=name) for name in exports],
            level=1,
        )
        body.append(ast.copy_location(explicit, node))
    return ast.Module(body=body, type_ignores=tree.type_ignores)


def _private_context(tree, source, project_root):
    attested = project_import_context(tree, source, project_root)
    if attested is None:
        return None
    private = ProjectImports(tree, source, attested.root, attested.snapshot)
    return private if private.complete else None


def native_function_snapshot_is_stable(provider, tree, filename, project_root=None):
    """Prove selected imported native callable values can be copied passively.

    Constructors are immutable callable values under the stdlib API model;
    their module, attribute writes and reflective capabilities stay guarded.
    Python functions, modules and arbitrary classes cannot opt into this proof.
    """
    if provider not in NATIVE_NONCE_FUNCTIONS:
        return False
    return _snapshot_provider_is_stable(
        provider, tree, filename, project_root, immutable=True
    )


def nonce_imported_provider_is_stable(provider, tree, filename, project_root=None):
    """The same attested passive-star view with the ordinary mutable policy."""
    return _snapshot_provider_is_stable(
        provider, tree, filename, project_root, immutable=False
    )


def nonce_builtin_references(tree, function, filename, project_root, names):
    """Builtin references after the same source-checked passive star facts."""
    try:
        source = Path(filename).resolve()
        context = None
        if source.is_file():
            context = _private_context(tree, source, project_root)
            if context is None:
                return set()
            view = _effect_view(tree, source, context, "builtins")
        elif project_root is None:
            view = ast.Module(body=list(tree.body), type_ignores=tree.type_ignores)
        else:
            return set()
        if view is None or function not in tree.body:
            return set()
        dynamic, rebound = module_rebinding(view, module_name_for(filename))
        if dynamic:
            return set()
        module_bound, _ = _scope_bindings(view)
        unsafe, unknown_global_write = _unsafe_import_roots(view)
        if unknown_global_write:
            return set()
        references = builtin_references(
            ast.Module(body=[function], type_ignores=[]), names
        )
        stable_names = {
            name
            for name in names
            if name not in module_bound and name not in rebound and name not in unsafe
            if (
                _provider_effects({"builtins." + name}, view)
                if context is None
                else nonce_imported_provider_is_stable(
                    "builtins." + name, tree, filename, project_root
                )
            )
        }
        return {
            id(node)
            for node in ast.walk(tree)
            if isinstance(node, ast.Name)
            and id(node) in references
            and node.id in stable_names
        }
    except (OSError, RuntimeError, ValueError, RecursionError, TypeError):
        return set()


def _snapshot_provider_is_stable(provider, tree, filename, project_root, *, immutable):
    if not provider or not provider_is_unshadowed(provider, filename, project_root):
        return False
    try:
        source = Path(filename).resolve()
        if not source.is_file():
            if project_root is not None:
                return False
            view = ast.Module(body=list(tree.body), type_ignores=tree.type_ignores)
            return _provider_effects(
                {provider}, view, immutable_values={provider} if immutable else ()
            )
        context = _private_context(tree, source, project_root)
        if context is None or provider.split(".", 1)[0] in context.modules:
            return False
        names = context.qualified_names(provider)
        for path, parsed in context.entries:
            view = _effect_view(parsed, path, context, provider)
            if view is None or not _provider_effects(
                names,
                view,
                context.local_symbols(path, names),
                immutable_values=names if immutable else (),
            ):
                return False
        return True
    except (OSError, RuntimeError, ValueError, RecursionError, TypeError):
        return False
