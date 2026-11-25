"""Recognize Django field constructors when a reachable module loads plugins."""

import ast

from .builtin_bindings import builtin_references
from .import_proof import (
    _effects,
    _provider_effects,
    _ships_provider_module,
    provider_binding_is_stable,
    provider_is_unshadowed,
)
from .project_imports import project_import_context


def form_base_preserves_scalar_read(project, base_unit, base, reader_unit, read):
    """Check the form base while accounting for the proven scalar field read."""
    if provider_binding_is_stable(base, base_unit.tree, base_unit.path, project.root):
        return True
    if not provider_is_unshadowed(base, base_unit.path, project.root):
        return False
    context = project_import_context(base_unit.tree, base_unit.path, project.root)
    if not context or "django" in context.modules:
        return False
    # The generic effects check treats returning Form.base_fields[key].initial
    # as returning a capability of Form. Replace just that proven scalar in
    # the effects view. Keep the source AST, imports and every other read intact.
    node, scalar = read, ast.copy_location(ast.Constant(value=0), read)
    for parent in reader_unit.ancestors(read):
        fields = dict(ast.iter_fields(parent))
        for key, value in fields.items():
            if value is node:
                fields[key] = scalar
            elif isinstance(value, list) and node in value:
                fields[key] = [scalar if item is node else item for item in value]
        scalar = ast.copy_location(type(parent)(**fields), parent)
        node = parent
    if node is not reader_unit.tree:
        return False
    names = context.qualified_names(base)
    return all(
        _provider_effects(
            names,
            scalar if path == reader_unit.path else tree,
            context.local_symbols(path, names),
        )
        for path, tree in context.entries
    )


def _only_discarded_imports(unit):
    """Allow an ordinary plugin import for its side effects, keeping other opaque calls closed."""
    effects = _effects(unit.tree)
    if not effects or not effects.complete:
        return False
    imports = builtin_references(unit.tree, {"__import__"})
    seen = False
    for call, _ in unit.calls:
        names = effects.refs(call.func)
        if any(
            n.startswith("importlib.") or n in {"builtins.eval", "builtins.exec"}
            for n in names
        ):
            return False
        if isinstance(call.func, ast.Name) and call.func.id in {"exec", "eval"}:
            return False
        if not (
            isinstance(call.func, ast.Name)
            and call.func.id == "__import__"
            or "builtins.__import__" in names
        ):
            continue
        if (
            id(call.func) not in imports
            or not isinstance(unit.parents.get(id(call)), ast.Expr)
            or not call.args
            or not isinstance(call.args[0], ast.Name)
        ):
            return False
        seen = True
    return seen


def django_field_is_available(project, unit, qualified):
    """Positive RSA findings may model installed Django fields in plugin-based apps.

    A discarded plugin import leaves runtime extension behavior unknown. Keep
    this assumption local to warnings about the declared fallback, and verify
    that reachable source preserves the Django constructor and import state.
    """
    if provider_binding_is_stable(qualified, unit.tree, unit.path, project.root):
        return True
    if not provider_is_unshadowed(
        qualified, unit.path, project.root
    ) or _ships_provider_module(project.root, "django"):
        return False
    context = project_import_context(unit.tree, unit.path, project.root)
    if not context or "django" in context.modules:
        return False
    names = context.qualified_names(qualified)
    for path, tree in context.entries:
        local = context.local_symbols(path, names)
        if _provider_effects(names, tree, local):
            continue
        imported = project.by_path.get(path)
        if not imported or not _only_discarded_imports(imported):
            return False
        if not _provider_effects(names, tree, local, opaque_ok=True):
            return False
    # A plugin shipped alongside the app can replace the field even when its
    # module is selected at runtime. Check modules that name this constructor.
    reachable = {path for path, _ in context.entries}
    leaf = qualified.rsplit(".", 1)[-1]
    for other in project.units:
        if other.is_test or other.path in reachable:
            continue
        if any(
            isinstance(n, ast.Attribute)
            and n.attr == leaf
            or isinstance(n, ast.alias)
            and n.name.rsplit(".", 1)[-1] == leaf
            or isinstance(n, ast.Constant)
            and n.value in (leaf, qualified)
            for n in ast.walk(other.tree)
        ) and not _provider_effects(names, other.tree, opaque_ok=True):
            return False
    return True
