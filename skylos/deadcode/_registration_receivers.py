"""Resolve receiver classes, member replacement and reachable patch owners."""

from __future__ import annotations
import ast
from pathlib import Path
from skylos.deadcode._reachability_bindings import bound_names
from skylos.deadcode._registration_common import (
    _FUNCTION_NODES,
    _is_static,
    _is_signature_stub,
    _import_aliases,
    _decorator_reference,
    _executed_nodes,
    _attribute_root,
)
from skylos.deadcode._registration_flow import _MethodScope
from skylos.deadcode._registration_sources import _RegistrationSourceIndex


class _RegistrationReceivers(_RegistrationSourceIndex):
    def __init__(self, definitions, parsed_files):
        super().__init__(definitions, parsed_files)
        self.constructor_writes = {}
        self.scopes = {}

    def member_rebound(self, expression, owner, name, context, *, instance=False):
        if instance:
            if owner not in self.constructor_writes:
                writes = set()
                scope = self.method_scope(owner)
                for initializer in scope.class_methods.get("__init__", ()):
                    params = [*initializer.args.posonlyargs, *initializer.args.args]
                    if not params:
                        continue
                    receiver = params[0].arg
                    for node in _executed_nodes(initializer.body):
                        if (
                            isinstance(node, ast.Attribute)
                            and isinstance(node.ctx, (ast.Store, ast.Del))
                            and isinstance(node.value, ast.Name)
                            and node.value.id == receiver
                        ):
                            writes.add(node.attr)
                        elif (
                            isinstance(node, ast.Call)
                            and isinstance(node.func, ast.Name)
                            and node.func.id == "setattr"
                            and len(node.args) >= 2
                            and isinstance(node.args[0], ast.Name)
                            and node.args[0].id == receiver
                            and isinstance(node.args[1], ast.Constant)
                            and isinstance(node.args[1].value, str)
                        ):
                            writes.add(node.args[1].value)
                self.constructor_writes[owner] = writes
            if name in self.constructor_writes[owner]:
                return True
        current = context
        while current is not None:
            if isinstance(current, (ast.Module, ast.ClassDef, *_FUNCTION_NODES)):
                self._scope_bindings(current)
                for write in self.member_writes[current]:
                    if write.attr != name:
                        continue
                    if isinstance(expression, ast.Name) and isinstance(
                        write.value, ast.Name
                    ):
                        if expression.id == write.value.id:
                            return True
                    if isinstance(write.value, ast.Name):
                        target = self.resolve(write.value, current)
                        if target == (owner, "class"):
                            return True
            current = self.context(current)
        return False

    def _qualified(self, dotted, seen):
        if not dotted or dotted in seen:
            return None
        seen = seen | {dotted}
        parts = dotted.split(".")
        for end in range(len(parts) - 1, 0, -1):
            matches = self.module_paths.get(tuple(parts[:end]), ())
            if len(matches) == 1 and end == len(parts) - 1:
                self.prepare(matches[0])
                expression = ast.Name(id=parts[-1])
                return self.resolve(expression, matches[0].tree, seen)
        return None

    def resolve(self, expression, context, seen=frozenset()):
        if expression is None or context is None or expression in seen:
            return None
        seen = seen | {expression}
        if isinstance(expression, ast.Constant) and isinstance(expression.value, str):
            try:
                expression = ast.parse(expression.value, mode="eval").body
            except SyntaxError:
                return None
        if isinstance(expression, ast.Call):
            target = self.resolve(expression.func, context, seen)
            if target and target[1] == "class":
                return target[0], "instance"
            return None
        if isinstance(expression, ast.Name):
            binding, scope = self._lookup(expression.id, context)
            if isinstance(binding, ast.ClassDef):
                return binding, "class"
            if isinstance(binding, _FUNCTION_NODES):
                for decorator in binding.decorator_list:
                    if not isinstance(decorator, ast.Name):
                        return None
                    if decorator.id not in {"staticmethod", "classmethod"}:
                        return None
                return binding, "function"
            if isinstance(binding, ast.arg):
                positional = [*scope.args.posonlyargs, *scope.args.args]
                owner = self.context(scope)
                if (
                    positional
                    and binding is positional[0]
                    and isinstance(owner, ast.ClassDef)
                    and not _is_static(scope)
                ):
                    return owner, "instance"
                target = self.resolve(binding.annotation, self.context(scope), seen)
                if target and target[1] == "class":
                    return target[0], "instance"
                return None
            if isinstance(binding, (ast.Import, ast.ImportFrom)):
                parsed = self.files[self.file_for_node[scope]]
                names, modules = _import_aliases(
                    ast.Module(body=[binding], type_ignores=[]),
                    self.modules[self.file_for_node[scope]],
                    parsed.path,
                )
                return self._qualified(names.get(expression.id, ""), seen)
            if binding is not None:
                return self.resolve(binding, scope, seen)
            return None
        if isinstance(expression, ast.Attribute):
            root = _attribute_root(expression)
            if root:
                binding, scope = self._lookup(root, context)
            else:
                binding, scope = None, None
            if isinstance(binding, (ast.Import, ast.ImportFrom)):
                parsed = self.files[self.file_for_node[scope]]
                names, modules = _import_aliases(
                    ast.Module(body=[binding], type_ignores=[]),
                    self.modules[self.file_for_node[scope]],
                    parsed.path,
                )
                _, qualified = _decorator_reference(expression, names, modules, "")
                target = self._qualified(qualified or "", seen)
                if target is not None:
                    return target
            receiver = self.resolve(expression.value, context, seen)
            if receiver and receiver[1] in {"class", "instance"}:
                if self.member_rebound(
                    expression.value,
                    receiver[0],
                    expression.attr,
                    context,
                    instance=receiver[1] == "instance",
                ):
                    return None
                scope = self.method_scope(receiver[0])
                if scope:
                    methods = scope.class_methods.get(expression.attr, ())
                else:
                    methods = ()
                if len(methods) == 1:
                    return methods[0], "function"
        return None

    def reachable_functions(self, definitions):
        pending = []
        for parsed in self.files.values():
            pending.append(parsed.tree)
        by_location = {}
        for file_key, parsed in self.files.items():
            for node in ast.walk(parsed.tree):
                if isinstance(node, _FUNCTION_NODES):
                    by_location[(file_key, node.lineno)] = node
        root_markers = {
            "framework_root",
            "package_entrypoint",
            "test_entrypoint",
            "top_level_execution",
            "coverage_hit",
            "trace_hit",
        }
        for definition in definitions.values():
            evidence = getattr(definition, "heuristic_refs", {})
            if not (
                getattr(definition, "is_exported", False)
                or (isinstance(evidence, dict) and root_markers.intersection(evidence))
            ):
                continue
            file_key = str(Path(definition.filename).resolve())
            node = by_location.get((file_key, definition.line))
            if node is not None:
                self.prepare(self.files[file_key])
                pending.append(node)
        reached = set()
        while pending:
            owner = pending.pop()
            if owner in reached:
                continue
            reached.add(owner)
            if isinstance(owner, ast.Module):
                self.prepare(self.files[self.file_for_node[owner]])
            for node in _executed_nodes(owner.body):
                if not isinstance(node, ast.Call):
                    continue
                target = self.resolve(node.func, self.context(node))
                if target and target[1] == "function":
                    pending.append(target[0])
                elif target and target[1] == "class":
                    scope = self.method_scope(target[0])
                    pending.extend(scope.class_methods.get("__init__", ()))
        return reached

    def method_scope(self, owner, seen=frozenset()):
        if owner in self.scopes:
            return self.scopes[owner]
        if owner in seen:
            return None
        seen = seen | {owner}
        methods = {}
        if len(owner.bases) == 1:
            base = self.resolve(owner.bases[0], self.context(owner))
            if base and base[1] == "class":
                parent = self.method_scope(base[0], seen)
            else:
                parent = None
            if parent is not None:
                methods.update(parent.class_methods)
        counts = bound_names(owner.body).counts
        for statement in owner.body:
            if isinstance(statement, _FUNCTION_NODES) and _is_signature_stub(statement):
                counts[statement.name] -= 1
        for name in counts:
            methods.pop(name, None)
        for statement in owner.body:
            if isinstance(statement, _FUNCTION_NODES) and counts[statement.name] == 1:
                methods[statement.name] = [statement]
        parsed = self.files[self.file_for_node[owner]]
        functions = {}
        for node in parsed.tree.body:
            if isinstance(node, _FUNCTION_NODES):
                functions[node.name] = node
        scope = _MethodScope(methods, functions, self.function_modules)
        self.scopes[owner] = scope
        return scope
