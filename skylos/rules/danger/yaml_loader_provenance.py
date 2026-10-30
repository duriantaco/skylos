"""Module-local yaml loader classes that keep SafeLoader construction.

A class qualifies only when it is defined once at module level, every base is
SafeLoader/CSafeLoader or an earlier qualifying class, its body never names a
constructor registry or an unsafe loader/constructor, and the module only uses
it as a base or as the loader of a yaml.load call. Registrations, rebinding,
attribute writes and any other use leave the call a review candidate.
"""

from __future__ import annotations

import ast

from .module_namespace import attribute_write_names, has_mock_api_patching

_SAFE_BASES = frozenset(
    {
        "yaml.SafeLoader",
        "yaml.CSafeLoader",
        "yaml.loader.SafeLoader",
        "yaml.cyaml.CSafeLoader",
    }
)
_LOAD_CALLS = frozenset({"yaml.load", "yaml.load_all"})
_REGISTRY_NAMES = frozenset(
    {
        "add_constructor",
        "add_multi_constructor",
        "yaml_constructors",
        "yaml_multi_constructors",
    }
)
_DEFINITIONS = (
    ast.ClassDef,
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ExceptHandler,
    ast.MatchAs,
    ast.MatchStar,
)
_UNSAFE_NAMES = frozenset(
    {
        "add_constructor",
        "add_multi_constructor",
        "yaml_constructors",
        "yaml_multi_constructors",
        "Constructor",
        "FullConstructor",
        "UnsafeConstructor",
        "Loader",
        "FullLoader",
        "UnsafeLoader",
        "load",
        "load_all",
        "full_load",
        "unsafe_load",
        "setattr",
        "__dict__",
        "__class__",
    }
)


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        if base:
            return f"{base}.{node.attr}"
    return None


def _import_aliases(statement):
    if isinstance(statement, ast.Import):
        for alias in statement.names:
            if alias.asname:
                yield alias.asname, alias.name
            else:
                local = alias.name.split(".", 1)[0]
                yield local, local
    elif (
        isinstance(statement, ast.ImportFrom)
        and statement.module
        and not statement.level
    ):
        for alias in statement.names:
            if alias.name != "*":
                yield alias.asname or alias.name, f"{statement.module}.{alias.name}"


def _module_aliases(tree):
    return dict(pair for statement in tree.body for pair in _import_aliases(statement))


def _resolved(node, aliases):
    dotted = _dotted(node)
    if not dotted:
        return None
    head, _, rest = dotted.partition(".")
    target = aliases.get(head)
    if target is None:
        return None
    if rest:
        return f"{target}.{rest}"
    return target


def _bound_names(node):
    if isinstance(node, _DEFINITIONS):
        return (node.name,)
    if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
        return (node.id,)
    if isinstance(node, ast.arg):
        return (node.arg,)
    if isinstance(node, ast.alias):
        return (node.asname or node.name.split(".", 1)[0],)
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return tuple(node.names)
    if isinstance(node, ast.MatchMapping):
        return (node.rest,)
    return ()


def _binding_counts(tree):
    counts = {}
    for node in ast.walk(tree):
        for name in _bound_names(node):
            if name:
                counts[name] = counts.get(name, 0) + 1
    return counts


def _body_names(node):
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            yield child.id
        elif isinstance(child, ast.Attribute):
            yield child.attr
        elif isinstance(child, ast.Constant) and isinstance(child.value, str):
            yield child.value


def _candidate(statement, aliases, safe):
    if statement.decorator_list or statement.keywords or not statement.bases:
        return False
    for base in statement.bases:
        if isinstance(base, ast.Name) and base.id in safe:
            continue
        if _resolved(base, aliases) not in _SAFE_BASES:
            return False
    return not any(
        name in _UNSAFE_NAMES for child in statement.body for name in _body_names(child)
    )


def _qualifying_classes(tree, aliases):
    counts = _binding_counts(tree)
    safe = set()
    bases = set()
    for statement in tree.body:
        if (
            isinstance(statement, ast.ClassDef)
            and counts.get(statement.name) == 1
            and _candidate(statement, aliases, safe)
        ):
            safe.add(statement.name)
            bases.update(id(base) for base in statement.bases)
    return safe, bases


def _writes_through(node, aliases, names):
    dotted = _dotted(node.value)
    if not dotted:
        return False
    head = dotted.split(".", 1)[0]
    return head in names or aliases.get(head, "").split(".", 1)[0] == "yaml"


def _touches_loader_state(tree, aliases, names):
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        if node.attr in _REGISTRY_NAMES:
            return True
        if not isinstance(node.ctx, ast.Load) and _writes_through(node, aliases, names):
            return True
    return False


def _loader_argument_ids(tree, aliases):
    ids = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _resolved(node.func, aliases) not in _LOAD_CALLS:
            continue
        if len(node.args) > 1:
            ids.add(id(node.args[1]))
        for keyword in node.keywords:
            if keyword.arg == "Loader":
                ids.add(id(keyword.value))
    return ids


def _only_loader_uses(tree, aliases, safe, bases):
    allowed = bases | _loader_argument_ids(tree, aliases)
    return not any(
        isinstance(node, ast.Name) and node.id in safe and id(node) not in allowed
        for node in ast.walk(tree)
    )


def safe_yaml_loader_classes(tree):
    """Names of module-level classes that load yaml as SafeLoader does."""
    if not isinstance(tree, ast.Module) or has_mock_api_patching(tree):
        return frozenset()
    if attribute_write_names(tree)[1]:
        return frozenset()
    aliases = _module_aliases(tree)
    safe, bases = _qualifying_classes(tree, aliases)
    if not safe or _touches_loader_state(tree, aliases, safe):
        return frozenset()
    if not _only_loader_uses(tree, aliases, safe, bases):
        return frozenset()
    return frozenset(safe)
