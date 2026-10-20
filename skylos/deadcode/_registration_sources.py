"""Lazy source indexes and lexical bindings used by registration receivers."""

from __future__ import annotations
import ast
from pathlib import Path
from skylos.deadcode._reachability_bindings import argument_nodes, bound_names
from skylos.deadcode._registration_common import _FUNCTION_NODES, _resolved


class _RegistrationSourceIndex:
    def __init__(self, definitions, parsed_files):
        self.files = {}
        for parsed in parsed_files:
            self.files[str(parsed.path.resolve())] = parsed
        self.parents = {}
        self.file_for_node = {}
        self.bindings = {}
        self.member_writes = {}
        self.modules = {}
        self.function_modules = {}
        self.definitions_by_location = {}
        self.module_paths = {}
        resolved_files = {}
        for definition in definitions.values():
            if getattr(definition, "type", None) in {"class", "function", "method"}:
                location = (
                    _resolved(Path(definition.filename), resolved_files),
                    definition.line,
                )
                self.definitions_by_location.setdefault(location, []).append(definition)
        for file_key, parsed in self.files.items():
            self.file_for_node[parsed.tree] = file_key
            path = parsed.path
            parts = (*path.parts[:-1], path.stem)
            if path.name == "__init__.py":
                parts = path.parts[:-1]
            for start in range(1, len(parts)):
                self.module_paths.setdefault(tuple(parts[start:]), []).append(parsed)

    def prepare(self, parsed):
        """Index a source module once, only when a candidate needs it."""
        file_key = self.file_for_node[parsed.tree]
        if file_key in self.modules:
            return
        identities = set()
        module_functions = {}
        for node in parsed.tree.body:
            if isinstance(node, _FUNCTION_NODES):
                module_functions[node.name] = node

        def index(node, prefix=""):
            for child in ast.iter_child_nodes(node):
                self.parents[child] = node
                self.file_for_node[child] = file_key
                qualified = prefix
                if isinstance(child, (*_FUNCTION_NODES, ast.ClassDef)):
                    if isinstance(child, _FUNCTION_NODES):
                        self.function_modules[child] = module_functions
                    if prefix:
                        qualified = f"{prefix}.{child.name}"
                    else:
                        qualified = child.name
                    for definition in self.definitions_by_location.get(
                        (file_key, child.lineno), ()
                    ):
                        suffix = "." + qualified
                        if definition.name.endswith(suffix):
                            identities.add(definition.name[: -len(suffix)])
                        elif definition.simple_name == child.name:
                            identities.add(definition.name.rsplit(".", 1)[0])
                index(child, qualified)

        index(parsed.tree)
        if len(identities) == 1:
            self.modules[file_key] = next(iter(identities))
        else:
            self.modules[file_key] = None

    def context(self, node):
        child = node
        current = self.parents.get(node)
        while current is not None:
            if isinstance(current, (ast.Module, ast.ClassDef, *_FUNCTION_NODES)):
                if not isinstance(current, _FUNCTION_NODES) or child in current.body:
                    return current
            child = current
            current = self.parents.get(current)
        return None

    def _scope_bindings(self, scope):
        if scope in self.bindings:
            return self.bindings[scope]
        counts = bound_names(scope.body).counts
        entries = {}
        if isinstance(scope, _FUNCTION_NODES):
            for arg in argument_nodes(scope.args):
                counts[arg.arg] += 1
                entries[arg.arg] = arg
        for statement in scope.body:
            if isinstance(statement, (ast.ClassDef, *_FUNCTION_NODES)):
                entries[statement.name] = statement
            elif isinstance(statement, ast.Assign) and len(statement.targets) == 1:
                if isinstance(statement.targets[0], ast.Name):
                    entries[statement.targets[0].id] = statement.value
            elif isinstance(statement, ast.AnnAssign) and isinstance(
                statement.target, ast.Name
            ):
                entries[statement.target.id] = statement.value
            elif isinstance(statement, (ast.Import, ast.ImportFrom)):
                for alias in statement.names:
                    entries[alias.asname or alias.name.split(".", 1)[0]] = statement
        result = {}
        for name, value in entries.items():
            if counts[name] == 1:
                result[name] = value
            else:
                result[name] = None
        writes = []
        for statement in scope.body:
            nodes = [statement]
            while nodes:
                node = nodes.pop()
                if isinstance(node, (*_FUNCTION_NODES, ast.ClassDef, ast.Lambda)):
                    continue
                if isinstance(node, ast.Attribute) and isinstance(
                    node.ctx, (ast.Store, ast.Del)
                ):
                    writes.append(node)
                nodes.extend(ast.iter_child_nodes(node))
        self.bindings[scope] = result
        self.member_writes[scope] = writes
        return result

    def _lookup(self, name, context):
        current = context
        while current is not None:
            if isinstance(current, (ast.Module, ast.ClassDef, *_FUNCTION_NODES)):
                bindings = self._scope_bindings(current)
                if name in bindings:
                    return bindings[name], current
            previous = current
            current = self.context(current)
            # A method's lexical namespace does not inherit class locals.
            if isinstance(previous, _FUNCTION_NODES) and isinstance(
                current, ast.ClassDef
            ):
                current = self.context(current)
        return None, None
