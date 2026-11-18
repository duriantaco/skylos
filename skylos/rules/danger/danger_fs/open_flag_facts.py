"""Native open flags: possible directions and guaranteed atomic bits differ."""

from __future__ import annotations

import ast
from dataclasses import dataclass

FLAGS = frozenset(
    {
        "O_RDONLY",
        "O_WRONLY",
        "O_RDWR",
        "O_CREAT",
        "O_TRUNC",
        "O_APPEND",
        "O_EXCL",
        "O_NOFOLLOW",
        "O_CLOEXEC",
        "O_DIRECTORY",
        "O_NONBLOCK",
    }
)
WRITE_FLAGS = frozenset({"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"})


@dataclass(frozen=True)
class OpenFlags:
    required: frozenset[str]
    possible: frozenset[str]

    def union(self, other):
        return OpenFlags(self.required | other.required, self.possible | other.possible)

    def directions(self):
        access = frozenset({"O_WRONLY", "O_RDWR"})
        uncertain_access = self.required & access != self.possible & access
        return bool(
            self.possible & WRITE_FLAGS
        ), uncertain_access or not self.possible & access


class OpenFlagFacts:
    MAX_EXPRESSIONS = 128

    def __init__(self, modes):
        self.modes = modes
        self.module = modes.module

    def _local_value(self, node, native, budget, active):
        scope = self.module.scope(node)
        if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return None
        if (
            self.modes._namespace_changed(scope)
            or node.id in self.modes.changed_names.get(scope, ())
            or node.id in self.modes.captured_names.get(scope, ())
        ):
            return None
        statements = []
        for binding, _, _ in self.module.bindings(scope).get(node.id, ()):
            if isinstance(binding, ast.Name):
                binding = self.module.parents.get(binding)
            if isinstance(binding, ast.Assign):
                if len(binding.targets) != 1 or not isinstance(
                    binding.targets[0], ast.Name
                ):
                    return None
            elif isinstance(binding, ast.AnnAssign):
                if not isinstance(binding.target, ast.Name) or binding.value is None:
                    return None
            elif not (
                isinstance(binding, ast.AugAssign)
                and isinstance(binding.op, ast.BitOr)
                and isinstance(binding.target, ast.Name)
            ):
                return None
            if not self.modes._dominates(binding, node):
                return None
            statements.append(binding)
        statements.sort(key=lambda statement: (statement.lineno, statement.col_offset))
        if not statements or not isinstance(statements[0], (ast.Assign, ast.AnnAssign)):
            return None
        if any(
            not isinstance(statement, ast.AugAssign) for statement in statements[1:]
        ):
            return None
        result = self._value(statements[0].value, native, budget, active)
        for statement in statements[1:]:
            additional = self._value(statement.value, native, budget, active)
            if result is None or additional is None:
                return None
            result = result.union(additional)
        return result

    def _value(self, node, native, budget, active=frozenset()):
        budget[0] += 1
        if node is None or node in active or budget[0] > self.MAX_EXPRESSIONS:
            return None
        active = active | {node}
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            left = self._value(node.left, native, budget, active)
            right = self._value(node.right, native, budget, active)
            return left.union(right) if left is not None and right is not None else None
        for flag in sorted(FLAGS):
            if native(node, f"os.{flag}"):
                return OpenFlags(frozenset({flag}), frozenset({flag}))
        if (
            isinstance(node, ast.Constant)
            and type(node.value) is int
            and node.value == 0
        ):
            return OpenFlags(frozenset(), frozenset())
        if (
            isinstance(node, ast.Call)
            and len(node.args) == 3
            and not node.keywords
            and native(node.func, "builtins.getattr")
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in FLAGS
            and isinstance(node.args[2], ast.Constant)
            and type(node.args[2].value) is int
            and node.args[2].value == 0
        ):
            flag = node.args[1].value
            attribute = ast.Attribute(value=node.args[0], attr=flag, ctx=ast.Load())
            if native(attribute, f"os.{flag}"):
                # The flag may be absent. In particular NOFOLLOW is not a
                # guaranteed atomic safeguard merely because getattr names it.
                return OpenFlags(frozenset(), frozenset({flag}))
        if isinstance(node, ast.Name):
            return self._local_value(node, native, budget, active)
        return None

    def facts(self, call, native):
        if (
            not native(call.func, "os.open")
            or any(isinstance(argument, ast.Starred) for argument in call.args)
            or any(keyword.arg is None for keyword in call.keywords)
        ):
            return None
        value = (
            call.args[1]
            if len(call.args) > 1
            else next(
                (keyword.value for keyword in call.keywords if keyword.arg == "flags"),
                None,
            )
        )
        return self._value(value, native, [0])
