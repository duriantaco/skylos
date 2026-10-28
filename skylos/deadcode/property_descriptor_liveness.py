"""Classify source-proven property declarations without inventing callers.

The visitor already treats ``@property`` declarations as descriptors. This pass
recognizes the equivalent builtin construction, including a bounded source-owned
factory whose returns construct that builtin. It does not infer receiver types
from attribute spelling, nor prove that every descriptor is externally used.
"""

from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from skylos.deadcode._reachability_bindings import BoundNames, argument_nodes


@dataclass
class _Module:
    name: str
    path: Path
    tree: ast.Module
    counts: dict
    imports: dict
    functions: dict
    classes: dict
    aliases: dict


def _bindings(nodes):
    visitor = BoundNames()
    for node in nodes:
        visitor.visit(node)
    return visitor.counts


def _imports(module, path, tree):
    result = {}
    package = module if path.name == "__init__.py" else module.rpartition(".")[0]
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                result[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parts = package.split(".") if package else []
                if node.level > len(parts):
                    continue
                base = ".".join(
                    parts[: len(parts) - node.level + 1] + ([base] if base else [])
                )
            for alias in node.names:
                if alias.name != "*":
                    result[alias.asname or alias.name] = base + "." + alias.name
    return result


def _qualified(node, module, local=()):
    if module.counts.get("*"):
        return None
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name) or node.id in local:
        return None
    name = node.id
    if module.counts.get(name, 0) == 1 and name in module.aliases:
        base = module.aliases[name]
    elif module.counts.get(name, 0) == 1 and name in module.imports:
        base = module.imports[name]
    elif module.counts.get(name, 0) == 1 and (
        name in module.functions or name in module.classes
    ):
        base = module.name + "." + name
    elif name == "property" and module.counts.get(name, 0) == 0:
        base = "builtins.property"
    else:
        return None
    return ".".join([base, *reversed(parts)])


def _own_nodes(function):
    pending = list(function.body)
    while pending:
        node = pending.pop()
        yield node
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        pending.extend(ast.iter_child_nodes(node))


def _mutations(modules):
    changed = set()
    function_modules = {
        module.name + "." + name: module.name
        for module in modules
        for name in module.functions
    }

    def namespace(expression, module):
        if isinstance(expression, ast.Name) and expression.id == "__builtins__":
            return "builtins"
        if isinstance(expression, ast.Call) and isinstance(expression.func, ast.Name):
            if expression.func.id in {"globals", "locals"}:
                return module.name
            if expression.func.id == "vars" and len(expression.args) == 1:
                return _qualified(expression.args[0], module)
        if isinstance(expression, ast.Attribute) and expression.attr in {
            "__dict__",
            "__globals__",
        }:
            owner = _qualified(expression.value, module)
            if expression.attr == "__globals__":
                return function_modules.get(owner, owner)
            return owner
        return None

    for module in modules:
        builtin_aliases = {
            alias.asname or "builtins"
            for node in ast.walk(module.tree)
            if isinstance(node, ast.Import)
            for alias in node.names
            if alias.name == "builtins"
        }
        if module.counts.get("__builtins__"):
            changed.add(module.name + ".*")
        for node in ast.walk(module.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                declarations = defaultdict(int)
                for child in _own_nodes(node):
                    if isinstance(child, ast.Global):
                        for name in child.names:
                            declarations[name] += 1
                bindings = _bindings(node.body) if declarations else {}
                for name, count in declarations.items():
                    if bindings.get(name, 0) > count:
                        changed.add(module.name + "." + name)
                        if name == "__builtins__":
                            changed.add(module.name + ".*")
            if isinstance(node, ast.Attribute) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                if (
                    node.attr == "property"
                    and isinstance(node.value, ast.Name)
                    and node.value.id in builtin_aliases
                ):
                    changed.add("builtins.property")
                if isinstance(node.value, ast.Name) and node.value.id == "__builtins__":
                    changed.add("builtins." + node.attr)
                value = _qualified(node, module)
                if value:
                    changed.add(value)
            if not isinstance(node, ast.Call):
                continue
            leaf = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else node.func.attr
                if isinstance(node.func, ast.Attribute)
                else None
            )
            if leaf in {"setattr", "delattr"} and len(node.args) >= 2:
                base = _qualified(node.args[0], module)
                if base:
                    field = node.args[1]
                    changed.add(
                        base
                        + "."
                        + (
                            field.value
                            if isinstance(field, ast.Constant)
                            and isinstance(field.value, str)
                            else "*"
                        )
                    )
            if (
                leaf == "patch"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                changed.add(node.args[0].value)
            if (
                leaf == "object"
                and isinstance(node.func, ast.Attribute)
                and node.args
                and len(node.args) >= 2
            ):
                base = _qualified(node.args[0], module)
                field = node.args[1]
                if (
                    base
                    and isinstance(field, ast.Constant)
                    and isinstance(field.value, str)
                ):
                    changed.add(base + "." + field.value)
            if leaf in {"exec", "eval"}:
                changed.add(module.name + ".*")
            if isinstance(node.func, ast.Attribute) and node.func.attr in {
                "update",
                "__setitem__",
                "__delitem__",
                "setdefault",
                "pop",
                "popitem",
                "clear",
            }:
                owner = namespace(node.func.value, module)
                if owner:
                    changed.add(owner + ".*")
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "update"
                and isinstance(node.func.value, ast.Call)
                and isinstance(node.func.value.func, ast.Name)
                and node.func.value.func.id in {"globals", "locals"}
            ):
                changed.add(module.name + ".*")
        for node in ast.walk(module.tree):
            if not isinstance(node, ast.Subscript) or not isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                continue
            base = node.value
            owner = namespace(base, module)
            if owner:
                changed.add(owner + ".*")
            if (
                isinstance(base, ast.Call)
                and isinstance(base.func, ast.Name)
                and base.func.id in {"globals", "locals"}
            ):
                changed.add(module.name + ".*")
            elif isinstance(base, ast.Attribute) and base.attr == "__dict__":
                owner = _qualified(base.value, module)
                if owner:
                    changed.add(owner + ".*")
    return changed


def _blocked(name, changed):
    parts = name.split(".")
    return any(
        ".".join(parts[:index]) in changed or ".".join(parts[:index]) + ".*" in changed
        for index in range(1, len(parts) + 1)
    )


def _binding_blocked(node, module, changed):
    while isinstance(node, ast.Attribute):
        node = node.value
    return isinstance(node, ast.Name) and _blocked(module.name + "." + node.id, changed)


def classify_property_descriptors(definitions, parsed_files, module_names=None):
    """Set descriptor kind/skip reason; never add references or root evidence."""
    by_file = defaultdict(list)
    declaration_index = {}
    for definition in definitions.values():
        path = Path(definition.filename).resolve()
        by_file[path].append(definition)
        declaration_index[(path, definition.name, definition.line)] = definition
    names = {Path(path).resolve(): name for path, name in (module_names or {}).items()}
    modules = []
    for parsed in parsed_files:
        path = parsed.path.resolve()
        name = names.get(path)
        if not name:
            top = {
                (node.name, node.lineno)
                for node in parsed.tree.body
                if isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                )
            }
            candidates = {
                definition.name.rpartition(".")[0]
                for definition in by_file[path]
                if (definition.simple_name, definition.line) in top
            }
            if len(candidates) != 1:
                continue
            name = candidates.pop()
        functions = {
            node.name: node
            for node in parsed.tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        classes = {
            node.name: node
            for node in parsed.tree.body
            if isinstance(node, ast.ClassDef)
        }
        modules.append(
            _Module(
                name,
                path,
                parsed.tree,
                _bindings(parsed.tree.body),
                _imports(name, path, parsed.tree),
                functions,
                classes,
                {},
            )
        )
    for module in modules:
        assignments = [
            node for node in module.tree.body if isinstance(node, ast.Assign)
        ]
        for _ in range(min(len(assignments), 24)):
            grew = False
            for node in assignments:
                if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                    continue
                target = node.targets[0].id
                if module.counts.get(target) != 1 or target in module.aliases:
                    continue
                value = _qualified(node.value, module)
                if value:
                    module.aliases[target] = value
                    grew = True
            if not grew:
                break
    changed = _mutations(modules)
    factories = {
        module.name + "." + name: (module, node)
        for module in modules
        for name, node in module.functions.items()
        if module.counts.get(name) == 1
    }
    classes = {
        module.name + "." + name: (module, node)
        for module in modules
        for name, node in module.classes.items()
    }
    factory_cache = {}
    base_cache = {}
    changed_parents = {
        ".".join(item.split(".")[:index])
        for item in changed
        for index in range(1, len(item.split(".")))
    }

    def base_rewrites(name, seen=frozenset()):
        if name not in classes:
            return False
        if name in seen or len(seen) >= 24:
            return True
        key = (name, 24 - len(seen))
        if key in base_cache:
            return base_cache[key]
        module, node = classes[name]
        if (
            module.counts.get(node.name) != 1
            or node.keywords
            or node.decorator_list
            or any(
                isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                and child.name == "__init_subclass__"
                for child in node.body
            )
        ):
            base_cache[key] = True
            return True
        base_cache[key] = any(
            base_rewrites(
                _qualified(
                    base.value if isinstance(base, ast.Subscript) else base, module
                ),
                seen | {name},
            )
            for base in node.bases
        )
        return base_cache[key]

    def factory(name):
        if name in factory_cache:
            return factory_cache[name]
        factory_cache[name] = False
        if name not in factories or _blocked(name, changed) or name in changed_parents:
            return False
        module, node = factories[name]
        if (
            not isinstance(node, ast.FunctionDef)
            or node.decorator_list
            or not node.body
            or not isinstance(node.body[-1], ast.Return)
        ):
            return False
        local = set(_bindings(node.body)) | {
            argument.arg for argument in argument_nodes(node.args)
        }
        own = list(_own_nodes(node))
        if any(
            isinstance(
                child,
                (
                    ast.Yield,
                    ast.YieldFrom,
                    ast.Global,
                    ast.Nonlocal,
                    ast.Import,
                    ast.ImportFrom,
                ),
            )
            for child in own
        ):
            return False
        if any(
            isinstance(child, ast.Name)
            and isinstance(child.ctx, ast.Load)
            and child.id in {"globals", "locals", "vars"}
            or isinstance(child, (ast.Name, ast.Attribute))
            and _qualified(child, module, local)
            in {"builtins.globals", "builtins.locals", "builtins.vars"}
            for child in own
        ):
            return False
        if any(
            isinstance(child, ast.Call)
            and (
                (
                    isinstance(child.func, ast.Name)
                    and (
                        child.func.id in {"globals", "locals"}
                        or child.func.id == "vars"
                        and not child.args
                        and not child.keywords
                    )
                )
                or _qualified(child.func, module, local)
                in {"builtins.globals", "builtins.locals"}
                or _qualified(child.func, module, local) == "builtins.vars"
                and not child.args
                and not child.keywords
            )
            for child in own
        ):
            return False
        returns = [child for child in own if isinstance(child, ast.Return)]
        if not returns or any(
            not builtin_property(child.value, module, local) for child in returns
        ):
            return False
        factory_cache[name] = True
        return True

    def builtin_property(value, module, local):
        if not isinstance(value, ast.Call):
            return False
        name = _qualified(value.func, module, local)
        return (
            name == "builtins.property"
            and not _blocked(name, changed)
            and not _blocked(module.name + ".property", changed)
            and not _binding_blocked(value.func, module, changed)
        )

    classified = []
    for module in modules:
        for class_name, cls in module.classes.items():
            owner = module.name + "." + class_name
            if (
                cls.decorator_list
                or cls.keywords
                or module.counts.get(class_name) != 1
                or _blocked(owner, changed)
                or any(
                    base_rewrites(
                        _qualified(
                            base.value if isinstance(base, ast.Subscript) else base,
                            module,
                        )
                    )
                    for base in cls.bases
                )
            ):
                continue
            local = _bindings(cls.body)
            for statement in cls.body:
                if isinstance(statement, ast.Assign):
                    targets, value = statement.targets, statement.value
                elif isinstance(statement, ast.AnnAssign):
                    targets, value = [statement.target], statement.value
                else:
                    continue
                if not isinstance(value, ast.Call):
                    continue
                if _binding_blocked(value.func, module, changed):
                    continue
                name = _qualified(value.func, module, local)
                if not builtin_property(value, module, local) and not (
                    name and factory(name)
                ):
                    continue
                for target in targets:
                    if not isinstance(target, ast.Name) or local.get(target.id) != 1:
                        continue
                    qualified = owner + "." + target.id
                    if _blocked(qualified, changed):
                        continue
                    definition = declaration_index.get(
                        (module.path, qualified, target.lineno)
                    )
                    if definition is not None and definition.type == "variable":
                        definition.is_descriptor = True
                        definition.confidence = 0
                        definition.skip_reason = (
                            "source-proven property descriptor declaration"
                        )
                        definition.suppression_code = "property_descriptor_declaration"
                        classified.append(definition)
    return classified
