"""Bounded local descriptor uses that do not read file contents."""

from __future__ import annotations

import ast

_METADATA = frozenset({"os.fstat", "os.fsync", "os.close", "fcntl.flock"})
_WRITES = frozenset({"os.write", "os.ftruncate"})


class DescriptorEffects:
    MAX_USES = 4096

    def __init__(self, modes, provider=None):
        self.modes = modes
        self.module = modes.module
        self.provider = provider

    def _owned_target(self, opened):
        binding = self.module.parents.get(opened)
        if isinstance(binding, ast.Assign) and len(binding.targets) == 1:
            target = binding.targets[0]
        elif isinstance(binding, ast.AnnAssign):
            target = binding.target
        else:
            return None
        scope = self.module.scope(opened)
        if not isinstance(target, ast.Name) or not isinstance(
            scope, (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            return None
        if (
            self.modes._namespace_changed(scope)
            or target.id in self.modes.changed_names.get(scope, ())
            or target.id in self.modes.captured_names.get(scope, ())
        ):
            return None
        nullable_stores = set()
        for definition, value, _ in self.module.bindings(scope).get(target.id, ()):
            if definition is binding:
                continue
            if not isinstance(definition, (ast.Assign, ast.AnnAssign)) or not (
                isinstance(value, ast.Constant) and value.value is None
            ):
                return None
            targets = (
                definition.targets
                if isinstance(definition, ast.Assign)
                else [definition.target]
            )
            if len(targets) != 1 or not isinstance(targets[0], ast.Name):
                return None
            nullable_stores.add(targets[0])
        return target, scope, nullable_stores

    def _null_test(self, use):
        comparison = self.module.parents.get(use)
        return (
            isinstance(comparison, ast.Compare)
            and len(comparison.ops) == 1
            and isinstance(comparison.ops[0], (ast.Is, ast.IsNot))
            and (
                comparison.left is use
                and isinstance(comparison.comparators[0], ast.Constant)
                and comparison.comparators[0].value is None
                or comparison.comparators[0] is use
                and isinstance(comparison.left, ast.Constant)
                and comparison.left.value is None
            )
        )

    def uses(self, opened):
        owned = self._owned_target(opened)
        if owned is None:
            return None
        target, scope, nullable_stores = owned
        result = []
        for count, use in enumerate(ast.walk(scope)):
            if count >= self.MAX_USES:
                return None
            if not isinstance(use, ast.Name) or use.id != target.id or use is target:
                continue
            if use in nullable_stores:
                continue
            if self.module.scope(use) is not scope:
                continue
            ancestor = self.module.parents.get(use)
            while ancestor is not None and ancestor is not scope:
                if isinstance(
                    ancestor,
                    (ast.GeneratorExp, ast.ListComp, ast.SetComp, ast.DictComp),
                ):
                    return None
                ancestor = self.module.parents.get(ancestor)
            if (
                not isinstance(use.ctx, ast.Load)
                or not nullable_stores
                and self.modes._binding(use) is not opened
            ):
                return None
            if self._null_test(use):
                continue
            operation = self.module.parents.get(use)
            if not isinstance(operation, ast.Call) or not (
                operation.args
                and operation.args[0] is use
                or any(
                    keyword.arg == "fd" and keyword.value is use
                    for keyword in operation.keywords
                )
            ):
                return None
            if any(
                isinstance(argument, ast.Starred) for argument in operation.args
            ) or any(keyword.arg is None for keyword in operation.keywords):
                return None
            result.append(operation)
        return result or None

    def metadata_only(self, opened, native):
        uses = self.uses(opened)
        return uses is not None and all(
            any(native(operation.func, provider) for provider in sorted(_METADATA))
            for operation in uses
        )

    def uncertain_read(self, opened, native, canonical, mode_values, handle_read):
        """An unresolved FD use is possible consumption, never read absence."""
        uses = self.uses(opened)
        if uses is None:
            return True
        for operation in uses:
            name = canonical(operation)
            if name in _METADATA | _WRITES and native(operation.func, name):
                continue
            if name == "os.fdopen" and native(operation.func, name):
                modes = mode_values(operation)
                if self.provider is None or not self.provider("io.open"):
                    return True
                if (
                    modes
                    and any("b" not in mode for mode in modes)
                    and not self.provider("io.text_encoding")
                ):
                    return True
                if (
                    modes
                    and all("w" in mode or "a" in mode or "x" in mode for mode in modes)
                    and not any("+" in mode for mode in modes)
                    and not handle_read(operation)
                ):
                    continue
            return True
        return False
