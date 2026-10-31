"""Positive proofs for local YAML loaders with data-only mapping overrides.

Inheritance alone does not prove safety: hooks can replace construction, and a
project importer can mutate a loader or its shared base. Unknown class bodies,
bindings, escapes and incomplete project snapshots retain the finding.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

from .builtin_bindings import builtin_references
from .module_namespace import (
    attribute_write_names,
    has_mock_api_patching,
    module_rebinding,
    module_name_for,
)
from .project_source import project_source_snapshot

_SAFE_BASES = frozenset(
    {
        "yaml.SafeLoader",
        "yaml.CSafeLoader",
        "yaml.loader.SafeLoader",
        "yaml.cyaml.CSafeLoader",
    }
)
_LOAD_CALLS = frozenset({"yaml.load", "yaml.load_all"})
_BASE_STATE = _SAFE_BASES | frozenset(
    {
        "yaml.constructor.SafeConstructor",
        "yaml.constructor.BaseConstructor",
        "yaml.reader.Reader",
        "yaml.scanner.Scanner",
        "yaml.parser.Parser",
        "yaml.composer.Composer",
        "yaml.resolver.Resolver",
        "yaml.constructor.ConstructorError",
        "builtins",
        "__builtins__",
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


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        if base:
            return f"{base}.{node.attr}"
    if isinstance(node, ast.Subscript):
        return _dotted(node.value)
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
    if isinstance(node, ast.Name):
        return aliases.get(node.id)
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        base = _resolved(node.value, aliases)
        if base is not None:
            if isinstance(node, ast.Attribute):
                return f"{base}.{node.attr}"
            return base
    if isinstance(node, ast.Call):
        callee = _resolved(node.func, aliases) or _dotted(node.func)
        if (
            callee in {"getattr", "builtins.getattr", "__builtins__.getattr"}
            and len(node.args) >= 2
        ):
            attribute = node.args[1]
            base = _resolved(node.args[0], aliases)
            if (
                base
                and isinstance(attribute, ast.Constant)
                and isinstance(attribute.value, str)
            ):
                return f"{base}.{attribute.value}"
    return None


def yaml_load_call_name(node, tree):
    """Resolve YAML calls using Python's unaliased dotted-import semantics."""
    if not isinstance(tree, ast.Module):
        return None
    name = _resolved(node.func, _module_aliases(tree))
    if name in _LOAD_CALLS:
        return name
    return None


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


class _MappingProof:
    def __init__(self, method, aliases, builtins):
        self.method = method
        self.aliases = aliases
        self.builtins = builtins
        self.values = {"self": "self", "node": "node", "deep": "data"}

    def kind(self, node):
        if isinstance(node, ast.Name):
            return self.values.get(node.id)
        if isinstance(node, ast.Constant):
            return "data"
        if isinstance(node, ast.Dict) and not node.keys:
            return "mapping"
        if isinstance(node, ast.Attribute) and self.kind(node.value) == "node":
            if node.attr in {"start_mark", "value"}:
                return "data"
        if not isinstance(node, ast.Call):
            return None
        if isinstance(node.func, ast.Name) and id(node.func) in self.builtins:
            if node.func.id == "set" and not node.args and not node.keywords:
                return "keys"
        if not isinstance(node.func, ast.Attribute):
            return None
        receiver = node.func.value
        if (
            node.func.attr == "construct_object"
            and isinstance(receiver, ast.Name)
            and receiver.id == "self"
        ):
            if self.arguments(node, "node"):
                return "data"
        if node.func.attr == "construct_mapping" and isinstance(receiver, ast.Call):
            if (
                isinstance(receiver.func, ast.Name)
                and receiver.func.id == "super"
                and id(receiver.func) in self.builtins
                and not receiver.args
                and not receiver.keywords
                and self.arguments(node, "node")
            ):
                return "mapping"
        return None

    def arguments(self, node, first_kind):
        if not 1 <= len(node.args) <= 2 or self.kind(node.args[0]) != first_kind:
            return False
        if len(node.args) == 2 and self.kind(node.args[1]) != "data":
            return False
        return all(
            keyword.arg == "deep" and self.kind(keyword.value) == "data"
            for keyword in node.keywords
        )

    def assign(self, target, value):
        kind = self.kind(value)
        if kind is None:
            return False
        if isinstance(target, ast.Name) and target.id not in {"self", "node", "deep"}:
            self.values[target.id] = kind
            return True
        return (
            isinstance(target, ast.Subscript)
            and self.kind(target.value) == "mapping"
            and self.kind(target.slice) == "data"
            and kind == "data"
        )

    def statements(self, statements):
        for node in statements:
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                if not self.assign(node.targets[0], node.value):
                    return False
            elif isinstance(node, ast.For):
                target = node.target
                if (
                    node.orelse
                    or not isinstance(node.iter, ast.Attribute)
                    or node.iter.attr != "value"
                    or not isinstance(node.iter.value, ast.Name)
                    or node.iter.value.id != "node"
                    or not isinstance(target, ast.Tuple)
                    or len(target.elts) != 2
                ):
                    return False
                for item in target.elts:
                    if not isinstance(item, ast.Name) or item.id in {
                        "self",
                        "node",
                        "deep",
                    }:
                        return False
                    self.values[item.id] = "node"
                if not self.statements(node.body):
                    return False
            elif isinstance(node, ast.If):
                test = node.test
                if (
                    not isinstance(test, ast.Compare)
                    or len(test.ops) != 1
                    or not isinstance(test.ops[0], (ast.In, ast.NotIn))
                    or self.kind(test.left) != "data"
                    or self.kind(test.comparators[0]) not in {"keys", "mapping"}
                    or node.orelse
                    or not all(isinstance(item, ast.Raise) for item in node.body)
                    or not self.statements(node.body)
                ):
                    return False
            elif isinstance(node, ast.Raise):
                call = node.exc
                if node.cause or not isinstance(call, ast.Call) or call.keywords:
                    return False
                error = _resolved(call.func, self.aliases)
                builtin_error = (
                    isinstance(call.func, ast.Name)
                    and call.func.id == "ValueError"
                    and id(call.func) in self.builtins
                )
                if not builtin_error and error != "yaml.constructor.ConstructorError":
                    return False
                if not all(self.kind(arg) == "data" for arg in call.args):
                    return False
            elif isinstance(node, ast.Expr):
                call = node.value
                if isinstance(call, ast.Constant) and isinstance(call.value, str):
                    continue
                if (
                    not isinstance(call, ast.Call)
                    or not isinstance(call.func, ast.Attribute)
                    or call.func.attr != "add"
                    or self.kind(call.func.value) != "keys"
                    or len(call.args) != 1
                    or self.kind(call.args[0]) != "data"
                    or call.keywords
                ):
                    return False
            elif isinstance(node, ast.Return):
                if self.kind(node.value) != "mapping":
                    return False
            else:
                return False
        return True

    def prove(self):
        method = self.method
        args = method.args
        if (
            method.name != "construct_mapping"
            or method.decorator_list
            or method.returns
            or getattr(method, "type_params", ())
            or args.posonlyargs
            or args.kwonlyargs
            or args.vararg
            or args.kwarg
            or [arg.arg for arg in args.args] != ["self", "node", "deep"]
            or any(arg.annotation for arg in args.args)
            or len(args.defaults) != 1
            or not isinstance(args.defaults[0], ast.Constant)
            or args.defaults[0].value is not False
        ):
            return False
        return self.statements(method.body)


def _candidate(statement, aliases, safe, counts, builtins):
    if (
        statement.decorator_list
        or statement.keywords
        or not statement.bases
        or getattr(statement, "type_params", ())
    ):
        return False
    for base in statement.bases:
        if isinstance(base, ast.Name) and base.id in safe:
            continue
        root = (_dotted(base) or "").split(".", 1)[0]
        if counts.get(root) != 1 or _resolved(base, aliases) not in _SAFE_BASES:
            return False
    methods = set()
    for child in statement.body:
        if (
            isinstance(child, ast.Pass)
            or isinstance(child, ast.Expr)
            and isinstance(child.value, ast.Constant)
            and isinstance(child.value.value, str)
        ):
            continue
        if (
            not isinstance(child, ast.FunctionDef)
            or child.name in methods
            or not _MappingProof(child, aliases, builtins).prove()
        ):
            return False
        methods.add(child.name)
    return True


def _loader_argument_ids(tree, aliases):
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _resolved(node.func, aliases) in _LOAD_CALLS:
            if len(node.args) > 1:
                ids.add(id(node.args[1]))
            ids.update(
                id(keyword.value)
                for keyword in node.keywords
                if keyword.arg == "Loader"
            )
    return ids


def _sensitive(name, names):
    return name is not None and any(
        name == target or name.startswith(target + ".") for target in names
    )


def _project_aliases(tree, module, names, package=False):
    aliases = dict(
        pair for statement in ast.walk(tree) for pair in _import_aliases(statement)
    )
    for statement in ast.walk(tree):
        if isinstance(statement, ast.ImportFrom) and statement.level:
            remove = statement.level
            if package:
                remove -= 1
            parent = module.split(".")
            if remove:
                parent = parent[:-remove]
            imported = ".".join(
                [*parent, *([statement.module] if statement.module else [])]
            )
            for alias in statement.names:
                aliases[alias.asname or alias.name] = ".".join(
                    filter(None, [imported, alias.name])
                )
    for statement in tree.body:
        if isinstance(statement, ast.ClassDef):
            aliases[statement.name] = ".".join(filter(None, [module, statement.name]))
    for name in ("getattr", "setattr", "delattr"):
        aliases.setdefault(name, "builtins." + name)
    aliases.update(names)
    for _iteration in range(3):
        for statement in ast.walk(tree):
            if (
                isinstance(statement, (ast.Assign, ast.AnnAssign))
                and statement.value is not None
            ):
                targets = (
                    statement.targets
                    if isinstance(statement, ast.Assign)
                    else [statement.target]
                )
                name = _resolved(statement.value, aliases)
                if name:
                    for target in targets:
                        if isinstance(target, ast.Name):
                            aliases[target.id] = name
    return aliases


def _sink_callbacks_safe(tree, aliases):
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        calls = [node for node in ast.walk(function) if isinstance(node, ast.Call)]
        if not any(_resolved(call.func, aliases) in _LOAD_CALLS for call in calls):
            continue
        parameters = {
            arg.arg
            for arg in [
                *function.args.posonlyargs,
                *function.args.args,
                *function.args.kwonlyargs,
            ]
        }
        for statement in ast.walk(function):
            if (
                isinstance(statement, ast.Assign)
                and isinstance(statement.value, ast.Name)
                and statement.value.id in parameters
            ):
                parameters.update(
                    target.id
                    for target in statement.targets
                    if isinstance(target, ast.Name)
                )
        if any(
            (_dotted(call.func) or "").split(".", 1)[0] in parameters for call in calls
        ):
            return False
    return True


def _external_uses_safe(tree, aliases, sensitive, allowed_extra=frozenset()):
    parents = {
        id(child): node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }
    external_roots = {
        target.split(".", 1)[0]
        for statement in ast.walk(tree)
        for _name, target in _import_aliases(statement)
    } - (sys.stdlib_module_names | {"yaml", "builtins", "__builtins__"})
    allowed = _loader_argument_ids(tree, aliases) | allowed_extra
    if not _sink_callbacks_safe(tree, aliases):
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            resolved_func = _resolved(node.func, aliases) or _dotted(node.func) or ""
            imported_func = _resolved(node.func, aliases)
            if imported_func and imported_func.split(".", 1)[0] in external_roots:
                return False
            if (
                resolved_func.rsplit(".", 1)[-1]
                in {"setattr", "delattr", "__setattr__", "__delattr__", "getattr"}
                and node.args
            ):
                receiver = _resolved(node.args[0], aliases)
                if receiver and (
                    receiver == "yaml"
                    or receiver.startswith("yaml.")
                    or _sensitive(receiver, sensitive)
                ):
                    return False
            terminal = (_dotted(node.func) or "").rsplit(".", 1)[-1]
            if terminal in {
                "vars",
                "globals",
                "locals",
                "exec",
                "eval",
                "__import__",
                "import_module",
                "spec_from_file_location",
                "exec_module",
                "reload",
            }:
                return False
        name = _resolved(node, aliases)
        parent = parents.get(id(node))
        if name in {"yaml", "yaml.loader", "yaml.cyaml", "yaml.constructor"}:
            if not isinstance(parent, ast.Attribute) or parent.value is not node:
                return False
        if not _sensitive(name, sensitive):
            continue
        if isinstance(parent, (ast.Attribute, ast.Subscript)) and parent.value is node:
            continue
        if (
            isinstance(parent, ast.ClassDef)
            and node in parent.bases
            and not parent.decorator_list
            and not parent.keywords
            and len(parent.bases) == 1
        ):
            continue
        if id(node) in allowed:
            continue
        return False
    return True


def _project_exports(sources, packages):
    exports = {}
    origins = {}
    for module, _source in sources:
        parts = module.split(".")
        for offset in range(len(parts)):
            origins.setdefault(".".join(parts[offset:]), set()).add(module)
    for alias, targets in origins.items():
        if len(targets) > 1:
            exports[alias] = "__ambiguous_project_module__"
        else:
            target = next(iter(targets))
            if alias != target:
                exports[alias] = target
    for module, source in sources:
        for name, target in _project_aliases(
            source, module, {}, module in packages
        ).items():
            full = ".".join(filter(None, [module, name]))
            if full != target:
                exports[full] = target
    return exports


def _canonical_aliases(aliases, exports):
    result = {}
    for local, target in aliases.items():
        seen = set()
        while target not in seen:
            seen.add(target)
            matching = [
                name
                for name in exports
                if target == name or target.startswith(name + ".")
            ]
            if not matching:
                result[local] = target
                break
            name = max(matching, key=len)
            target = exports[name] + target[len(name) :]
        else:
            result[local] = "__ambiguous_project_module__"
    return result


def _shared_registry_names(sources, packages=frozenset(), exports=None):
    if exports is None:
        exports = _project_exports(sources, packages)
    derived = set(_SAFE_BASES)
    pending = []
    for module, source in sources:
        aliases = _canonical_aliases(
            _project_aliases(source, module, {}, module in packages), exports
        )
        for statement in source.body:
            if isinstance(statement, ast.ClassDef):
                pending.append((aliases[statement.name], statement.bases, aliases))
    changed = True
    while changed:
        changed = False
        for name, bases, aliases in pending:
            if name not in derived and any(
                _resolved(base, aliases) in derived for base in bases
            ):
                derived.add(name)
                changed = True
    return frozenset(
        f"{name}.{registry}"
        for name in derived
        for registry in ("yaml_constructors", "yaml_multi_constructors")
    )


def _project_module(path, root):
    parts = list(path.relative_to(root).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    if (root / "__init__.py").is_file():
        parts.insert(0, root.name)
    return ".".join(parts)


def _project_safe(tree, filename, project_root, safe):
    if not filename:
        return project_root is None
    path = Path(filename).resolve()
    if project_root is None and not path.is_file():
        return True
    root = Path(project_root).resolve() if project_root else path.parent
    trees, complete = project_source_snapshot(root)
    if not complete or path not in trees:
        return False
    if any(
        other.name == "yaml.py"
        or other.name == "__init__.py"
        and other.parent.name == "yaml"
        for other in trees
    ):
        return False
    if ast.dump(tree) != ast.dump(trees[path]):
        return False
    module = _project_module(path, root)
    sources = [
        (_project_module(other, root), source) for other, source in trees.items()
    ]
    packages = frozenset(
        _project_module(other, root) for other in trees if other.name == "__init__.py"
    )
    exports = _project_exports(sources, packages)
    if any("__ambiguous_project_module__" in target for target in exports.values()):
        return False
    sensitive = (
        _BASE_STATE
        | frozenset(f"{module}.{name}" for name in safe)
        | _shared_registry_names(sources, packages, exports)
    )
    for other_path, other_tree in trees.items():
        if other_path == path:
            continue
        dynamic, rebound = module_rebinding(other_tree, module_name_for(other_path))
        if dynamic or rebound:
            return False
        other_module = _project_module(other_path, root)
        aliases = _canonical_aliases(
            _project_aliases(
                other_tree, other_module, {}, other_path.name == "__init__.py"
            ),
            exports,
        )
        if not _external_uses_safe(other_tree, aliases, sensitive):
            return False
    return True


def safe_yaml_loader_classes(tree, filename=None, project_root=None):
    if (
        not isinstance(tree, ast.Module)
        or has_mock_api_patching(tree)
        or module_rebinding(tree, module_name_for(filename) or "__yaml_proof__")[0]
    ):
        return frozenset()
    written, computed = attribute_write_names(tree)
    if computed:
        return frozenset()
    aliases = _module_aliases(tree)
    counts = _binding_counts(tree)
    builtins = builtin_references(tree, {"set", "super", "ValueError"})
    safe = set()
    bases = set()
    for statement in tree.body:
        if (
            isinstance(statement, ast.ClassDef)
            and counts.get(statement.name) == 1
            and _candidate(statement, aliases, safe, counts, builtins)
        ):
            safe.add(statement.name)
            bases.update(id(base) for base in statement.bases)
    if not safe:
        return frozenset()
    names = _BASE_STATE | frozenset(safe) | _shared_registry_names([("", tree)])
    local_aliases = _project_aliases(tree, "", {name: name for name in safe})
    allowed_errors = frozenset(
        id(node.exc.func)
        for statement in tree.body
        if isinstance(statement, ast.ClassDef) and statement.name in safe
        for node in ast.walk(statement)
        if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call)
    )
    if not _external_uses_safe(tree, local_aliases, names, allowed_errors):
        return frozenset()
    if written & {name.rsplit(".", 1)[-1] for name in _SAFE_BASES}:
        return frozenset()
    allowed = bases | _loader_argument_ids(tree, aliases)
    if any(
        isinstance(node, ast.Name) and node.id in safe and id(node) not in allowed
        for node in ast.walk(tree)
    ):
        return frozenset()
    if not _project_safe(tree, filename, project_root, safe):
        return frozenset()
    return frozenset(safe)


def yaml_loader_classes(tree, filename=None, project_root=None):
    """Return proven safe local classes and all local class names."""
    if not isinstance(tree, ast.Module):
        return frozenset(), frozenset()
    local = frozenset(
        node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)
    )
    return safe_yaml_loader_classes(tree, filename, project_root), local
