"""Python lexical bindings for source-only security explanations."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
import hashlib


@dataclass
class Binding:
    kind: str
    node: ast.AST
    value: object = None
    conditional: bool = False
    owner: object = None


@dataclass(eq=False)
class Scope:
    unit: object
    node: ast.AST
    name: str
    parent: object = None
    bindings: dict = field(default_factory=dict)
    dynamic: bool = False

    def add(self, name, binding):
        binding.owner = self
        self.bindings.setdefault(name, []).append(binding)


def dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    parts.reverse()
    return ".".join(parts)


class SourceUnit:
    def __init__(self, path, text, tree, module_name):
        self.path = path
        self.tree = tree
        self.digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        self.module_name = module_name
        self.parents = {}
        self.owners = {}
        self.scopes = []
        self.functions = {}
        self.calls_by_line = {}
        self.mutated_roots = set()
        self.module = Scope(self, tree, module_name)
        self.scopes.append(self.module)
        self._index_nodes()

    def _index_nodes(self):
        stack = [(self.tree, self.module, False)]
        while stack:
            node, owner, conditional = stack.pop()
            self.owners[id(node)] = owner
            child_owner = owner
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
            ):
                name = getattr(node, "name", "<lambda>" + str(node.lineno))
                if not isinstance(node, ast.Lambda):
                    owner.add(
                        node.name, Binding("definition", node, conditional=conditional)
                    )
                if owner.name:
                    name = owner.name + "." + name
                child_owner = Scope(self, node, name, owner)
                self.scopes.append(child_owner)
                if isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
                ):
                    self.functions[id(node)] = child_owner
                    arguments = [
                        *node.args.posonlyargs,
                        *node.args.args,
                        *node.args.kwonlyargs,
                    ]
                    if node.args.vararg:
                        arguments.append(node.args.vararg)
                    if node.args.kwarg:
                        arguments.append(node.args.kwarg)
                    for argument in arguments:
                        child_owner.add(argument.arg, Binding("parameter", argument))
                conditional = False
            else:
                self._record_binding(node, owner, conditional)
            if isinstance(node, ast.Call):
                self.calls_by_line.setdefault(node.lineno, []).append(node)
            children = list(ast.iter_child_nodes(node))
            children.reverse()
            for child in children:
                self.parents[id(child)] = node
                branch = conditional or isinstance(
                    node, (ast.If, ast.Try, ast.For, ast.While, ast.Match)
                )
                if isinstance(
                    node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                ):
                    if child not in node.body:
                        stack.append((child, owner, False))
                        continue
                stack.append((child, child_owner, branch))

    def _record_binding(self, node, scope, conditional):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name.split(".")[0]
                if alias.asname:
                    value = alias.name
                else:
                    value = alias.name.split(".")[0]
                scope.add(name, Binding("import", node, value, conditional))
        elif isinstance(node, ast.ImportFrom):
            prefix = self._import_prefix(node)
            for alias in node.names:
                if alias.name == "*":
                    scope.dynamic = True
                else:
                    name = alias.asname or alias.name
                    if prefix:
                        value = prefix + "." + alias.name
                    else:
                        value = alias.name
                    scope.add(name, Binding("import", node, value, conditional))
        elif isinstance(
            node, (ast.Assign, ast.AnnAssign, ast.NamedExpr, ast.AugAssign)
        ):
            targets = getattr(node, "targets", None)
            if targets is None:
                targets = [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and not isinstance(node, ast.AugAssign):
                    scope.add(
                        target.id, Binding("assignment", node, node.value, conditional)
                    )
                    if target.id == "__builtins__":
                        self.module.dynamic = True
                else:
                    for part in ast.walk(target):
                        if isinstance(part, ast.Name):
                            scope.add(
                                part.id, Binding("unknown", node, conditional=True)
                            )
                            if isinstance(target, (ast.Attribute, ast.Subscript)):
                                self.mutated_roots.add(part.id)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            scope.dynamic = True
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in {
                "exec",
                "eval",
                "globals",
                "locals",
                "setattr",
            }:
                scope.dynamic = True
                self.module.dynamic = True
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            for part in ast.walk(node.target):
                if isinstance(part, ast.Name):
                    scope.add(part.id, Binding("unknown", node, conditional=True))
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            for part in ast.walk(node.optional_vars):
                if isinstance(part, ast.Name):
                    scope.add(part.id, Binding("unknown", node, conditional=True))
        elif isinstance(node, ast.ExceptHandler) and node.name:
            scope.add(node.name, Binding("unknown", node, conditional=True))
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                for part in ast.walk(target):
                    if isinstance(part, ast.Name):
                        scope.add(part.id, Binding("unknown", node, conditional=True))

    def _import_prefix(self, node):
        if not node.level:
            return node.module or ""
        parts = self.module_name.split(".")
        if not self.path.endswith("/__init__.py") and self.path != "__init__.py":
            parts = parts[:-1]
        remove = node.level - 1
        if remove > len(parts):
            return ""
        if remove:
            parts = parts[:-remove]
        if node.module:
            parts.extend(node.module.split("."))
        return ".".join(parts)

    def scope_for(self, node):
        return self.owners.get(id(node), self.module)

    def strict_binding(self, scope, name):
        for current in self.lexical_scopes(scope):
            if current.dynamic:
                return None
            values = current.bindings.get(name)
            if values:
                if len(values) != 1 or values[0].conditional:
                    return None
                return values[0]
        return None

    def lexical_scopes(self, scope):
        """Class namespaces are not enclosing lexical scopes of methods."""
        current = scope
        first = True
        while current is not None:
            if first or not isinstance(current.node, ast.ClassDef):
                yield current
            first = False
            current = current.parent

    def imported_name(self, scope, expression):
        name = dotted(expression)
        if not name:
            return None
        head, separator, tail = name.partition(".")
        if head in self.mutated_roots:
            return None
        binding = self.strict_binding(scope, head)
        if binding is None or binding.kind != "import":
            return None
        if separator:
            return binding.value + "." + tail
        return binding.value
