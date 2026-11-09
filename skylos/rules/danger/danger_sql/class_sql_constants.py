"""Proof that a class attribute holds fixed SQL text across a whole project.

``conn.execute(self.SQL_ALL)`` reads an attribute, and a subclass, an imported
base or any object can replace an attribute. The proof therefore needs the
complete project source: every class-body binding of the name is a literal,
nothing writes the attribute or passes it as a keyword, and every class related
to the owner is visible and unable to rewrite instances dynamically. An
incomplete snapshot proves nothing. Code outside the project (a downstream
subclass) is out of reach, the same trust level as a module-level constant.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from skylos.rules.danger.project_source import project_source_snapshot
from skylos.rules.danger.builtin_bindings import builtin_references
from skylos.rules.danger.untrusted_sources import UntrustedSourceIndex

_PLAIN_BASES = frozenset(
    {"builtins.object", "abc.ABC", "typing.Generic", "typing.Protocol"}
)
_ATTRIBUTE_WRITE_CALLS = frozenset({"setattr", "delattr"})
_DYNAMIC_ATTRIBUTES = frozenset({"__dict__", "__setattr__", "__getattribute__"})
_DYNAMIC_CALLS = frozenset({"vars", "exec", "eval", "new_class"})
_NON_DATA_CLASS_MEMBERS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_MAX_LITERAL_DEPTH = 8


def _last_segment(node: ast.AST) -> str | None:
    if isinstance(node, ast.Subscript):
        node = node.value
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


@dataclass
class _ProjectClass:
    bases: list[str | None]
    sealed: bool
    module: int
    bound_names: frozenset[str]


def _class_is_sealed(
    node: ast.ClassDef, imports: UntrustedSourceIndex, local_modules
) -> bool:
    """No metaclass or class keyword, and no decorator but ``final``."""
    if node.keywords:
        return False
    for item in node.decorator_list:
        provider = imports.resolved_import(None, ast.unparse(item))
        if provider not in {"typing.final", "typing_extensions.final"}:
            return False
        if provider.split(".", 1)[0] in local_modules:
            return False
    return True


def _is_literal_text(node: ast.AST | None, siblings: dict, depth: int = 0) -> bool:
    if node is None or depth > _MAX_LITERAL_DEPTH:
        return False
    if isinstance(node, ast.Constant):
        return isinstance(node.value, (str, int, float)) and not isinstance(
            node.value, bool
        )
    if isinstance(node, ast.JoinedStr):
        for part in node.values:
            if isinstance(part, ast.Constant):
                continue
            if not (
                isinstance(part, ast.FormattedValue)
                and part.format_spec is None
                and _is_literal_text(part.value, siblings, depth + 1)
            ):
                return False
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_literal_text(node.left, siblings, depth + 1) and _is_literal_text(
            node.right, siblings, depth + 1
        )
    if isinstance(node, ast.Name):
        return _is_literal_text(siblings.get(node.id), siblings, depth + 1)
    return False


def _is_literal_mapping(node: ast.AST | None, siblings: dict) -> bool:
    return isinstance(node, ast.Dict) and all(
        isinstance(key, ast.Constant)
        and isinstance(key.value, str)
        and _is_literal_text(value, siblings)
        for key, value in zip(node.keys, node.values)
    )


def _class_scope_nodes(statements):
    stack = list(statements)
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, _NON_DATA_CLASS_MEMBERS):
            stack.extend(ast.iter_child_nodes(node))


def _class_body_bindings(node: ast.ClassDef) -> dict[str, list[ast.AST | None]]:
    """Every name a class body binds; ``None`` stands for a value that is not
    one plain top-level ``NAME = value``."""
    simple = set()
    bindings: dict[str, list[ast.AST | None]] = {}
    for statement in node.body:
        target = None
        value = None
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
            value = statement.value
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
            target = statement.target
            value = statement.value
        if isinstance(target, ast.Name):
            simple.add(id(target))
            bindings.setdefault(target.id, []).append(value)
    for child in _class_scope_nodes(node.body):
        if isinstance(child, ast.Name) and isinstance(child.ctx, (ast.Store, ast.Del)):
            if id(child) not in simple:
                bindings.setdefault(child.id, []).append(None)
        elif isinstance(child, _NON_DATA_CLASS_MEMBERS):
            bindings.setdefault(child.name, []).append(None)
        elif isinstance(child, (ast.Import, ast.ImportFrom)):
            for alias in child.names:
                bindings.setdefault(alias.asname or alias.name, []).append(None)
    return bindings


class ProjectClassConstants:
    def __init__(self, trees, root):
        self.written: set[str] = set()
        self.classes: dict[str, list[_ProjectClass]] = {}
        self.children: dict[str, set[str]] = {}
        self.literal_names: dict[str, list[bool]] = {}
        self.literal_mappings: dict[str, list[bool]] = {}
        self.exposed_mappings: set[str] = set()
        self.dynamic_modules: set[int] = set()
        self.module_names = {}
        self.project_symbols = set()
        for path, tree in trees.items():
            parts = list(Path(path).relative_to(root).with_suffix("").parts)
            if parts and parts[0] == "src":
                parts.pop(0)
            if parts and parts[-1] == "__init__":
                parts.pop()
            module = ".".join(parts)
            self.module_names[id(tree)] = module
            self.project_symbols.update(
                f"{module}.{statement.name}"
                for statement in tree.body
                if isinstance(statement, ast.ClassDef)
            )
        for number, tree in enumerate(trees.values()):
            self._read_module(number, tree)
        for tree in trees.values():
            parents = {
                id(child): parent
                for parent in ast.walk(tree)
                for child in ast.iter_child_nodes(parent)
            }
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    self.exposed_mappings.add(node.id)
                if not isinstance(node, ast.Attribute):
                    continue
                parent = parents.get(id(node))
                call = parents.get(id(parent))
                if not (
                    isinstance(parent, ast.Attribute)
                    and parent.attr in {"items", "values", "keys"}
                    and isinstance(call, ast.Call)
                    and call.func is parent
                    and not call.args
                    and not call.keywords
                ):
                    self.exposed_mappings.add(node.attr)

    def _read_module(self, number: int, tree: ast.AST) -> None:
        imports = UntrustedSourceIndex(tree)
        builtin_objects = builtin_references(tree, {"object"})
        local_classes = {
            statement.name
            for statement in tree.body
            if isinstance(statement, ast.ClassDef)
        }
        replaced = {
            item.id
            for item in ast.walk(tree)
            if isinstance(item, ast.Name) and isinstance(item.ctx, (ast.Store, ast.Del))
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                if isinstance(node.ctx, (ast.Store, ast.Del)):
                    self.written.add(node.attr)
                if node.attr in _DYNAMIC_ATTRIBUTES:
                    self.dynamic_modules.add(number)
            elif isinstance(node, ast.keyword) and node.arg:
                self.written.add(node.arg)
            elif isinstance(node, ast.Call):
                self._read_call(number, node)
            elif isinstance(node, ast.ClassDef):
                bases = []
                for base in node.bases:
                    expression = base.value if isinstance(base, ast.Subscript) else base
                    if id(expression) in builtin_objects:
                        bases.append("builtins.object")
                        continue
                    resolved = imports.resolved_import(None, ast.unparse(expression))
                    if (
                        resolved in _PLAIN_BASES
                        and resolved.split(".", 1)[0] not in self.module_names.values()
                    ):
                        bases.append(resolved)
                    elif resolved in self.project_symbols:
                        bases.append(resolved.rsplit(".", 1)[-1])
                    elif (
                        isinstance(expression, ast.Name)
                        and expression.id in local_classes
                        and expression.id not in replaced
                    ):
                        bases.append(expression.id)
                    else:
                        bases.append(None)
                self._read_class(number, node, bases, imports)

    def _read_call(self, number: int, node: ast.Call) -> None:
        name = _last_segment(node.func)
        if name in _DYNAMIC_CALLS or (name == "type" and len(node.args) > 1):
            self.dynamic_modules.add(number)
        if name not in _ATTRIBUTE_WRITE_CALLS:
            return
        if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
            self.written.add(str(node.args[1].value))
        else:
            self.dynamic_modules.add(number)

    def _read_class(self, number: int, node: ast.ClassDef, bases, imports) -> None:
        bindings = _class_body_bindings(node)
        self.classes.setdefault(node.name, []).append(
            _ProjectClass(
                bases,
                _class_is_sealed(node, imports, self.module_names.values()),
                number,
                frozenset(bindings),
            )
        )
        for base in bases:
            if base:
                self.children.setdefault(base, set()).add(node.name)
        siblings = {
            name: values[0] for name, values in bindings.items() if len(values) == 1
        }
        for name, values in bindings.items():
            self.literal_names.setdefault(name, []).extend(
                _is_literal_text(value, siblings) for value in values
            )
            self.literal_mappings.setdefault(name, []).extend(
                _is_literal_mapping(value, siblings) for value in values
            )

    def _related_classes(self, owner: str) -> set[str]:
        """The owner, everything that inherits from it, and all their bases: a
        method on the owner can run with any of these as ``self``."""
        related: set[str] = set()
        pending = [owner]
        while pending:
            name = pending.pop()
            if name not in related:
                related.add(name)
                pending.extend(self.children.get(name, ()))
        pending = list(related)
        while pending:
            for declaration in self.classes.get(pending.pop(), ()):
                for base in declaration.bases:
                    if base and base not in related:
                        related.add(base)
                        pending.append(base)
        return related

    def _class_can_keep_constants(self, name: str) -> bool:
        declarations = self.classes.get(name)
        if not declarations:
            return name in _PLAIN_BASES
        return all(
            declaration.sealed
            and declaration.module not in self.dynamic_modules
            and all(declaration.bases)
            for declaration in declarations
        )

    def _hierarchy_binds(self, owner: str, attribute: str) -> bool:
        seen: set[str] = set()
        pending = [owner]
        while pending:
            name = pending.pop()
            if name in seen:
                continue
            seen.add(name)
            for declaration in self.classes.get(name, ()):
                if attribute in declaration.bound_names:
                    return True
                pending.extend(base for base in declaration.bases if base)
        return False

    def holds_fixed_text(self, owner: str, attribute: str) -> bool:
        if attribute in self.written:
            return False
        literal = self.literal_names.get(attribute)
        if not literal or not all(literal):
            return False
        if not self._hierarchy_binds(owner, attribute):
            return False
        return all(
            self._class_can_keep_constants(name)
            for name in self._related_classes(owner)
        )

    def holds_fixed_mapping(self, owner: str, attribute: str) -> bool:
        if attribute in self.written or attribute in self.exposed_mappings:
            return False
        literal = self.literal_mappings.get(attribute)
        if (
            not literal
            or not all(literal)
            or not self._hierarchy_binds(owner, attribute)
        ):
            return False
        return all(
            self._class_can_keep_constants(name)
            for name in self._related_classes(owner)
        )


_cache: dict[str, tuple[object, ProjectClassConstants]] = {}


def project_class_constants(
    project_root, file_path=None, tree=None
) -> ProjectClassConstants | None:
    if not project_root:
        return None
    trees, complete = project_source_snapshot(project_root)
    if not complete or not trees:
        return None
    if file_path is not None and tree is not None:
        try:
            captured = trees.get(Path(file_path).resolve())
            if captured is None or ast.dump(captured) != ast.dump(tree):
                return None
        except (OSError, RuntimeError, RecursionError):
            return None
    key = str(project_root)
    cached = _cache.get(key)
    if cached is not None and cached[0] is trees:
        return cached[1]
    index = ProjectClassConstants(trees, Path(project_root).resolve())
    if len(_cache) >= 16:
        _cache.pop(next(iter(_cache)))
    _cache[key] = (trees, index)
    return index
