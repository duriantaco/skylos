"""Operation-bound proofs for native final-component atomic opens.

Path prechecks can race and do not prove an eventual open safe. These proofs
apply only to the exact native call and, for reads, the descriptor it created.
They do not establish ancestor containment; traversal analysis stays separate.
"""

from __future__ import annotations

import ast

from .path_open_modes import PathOpenModes

_FLAGS = frozenset(
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
    }
)


def _argument(call, position, name):
    if len(call.args) > position:
        return call.args[position]
    return next(
        (keyword.value for keyword in call.keywords if keyword.arg == name), None
    )


def _position(node):
    return getattr(node, "lineno", 0), getattr(node, "col_offset", 0)


class AtomicOpenProofs:
    MAX_EXPRESSIONS = 128
    MAX_USES = 4096

    def __init__(self, tree, modes=None, provider=None):
        self.modes = modes or PathOpenModes(tree)
        self.module = self.modes.module
        self.provider = provider

    def _flags(self, node, native, budget, active=frozenset()):
        budget[0] += 1
        if node is None or node in active or budget[0] > self.MAX_EXPRESSIONS:
            return None
        active = active | {node}
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            left = self._flags(node.left, native, budget, active)
            right = self._flags(node.right, native, budget, active)
            return left | right if left is not None and right is not None else None
        for flag in sorted(_FLAGS):
            if native(node, f"os.{flag}"):
                return frozenset({flag})
        if (
            isinstance(node, ast.Constant)
            and type(node.value) is int
            and node.value == 0
        ):
            return frozenset()
        if isinstance(node, ast.Name):
            value = self.modes._binding(node)
            if value is not None:
                return self._flags(value, native, budget, active)
        return None

    def flags(self, call, native):
        if not native(call.func, "os.open"):
            return None
        if any(isinstance(argument, ast.Starred) for argument in call.args) or any(
            keyword.arg is None for keyword in call.keywords
        ):
            return None
        return self._flags(_argument(call, 1, "flags"), native, [0])

    def nofollow(self, call, native):
        flags = self.flags(call, native)
        return flags is not None and "O_NOFOLLOW" in flags

    def exclusive(self, call, native):
        flags = self.flags(call, native)
        return flags is not None and {"O_CREAT", "O_EXCL"} <= flags

    def descriptor_read_observed(self, call, canonical, handle_read):
        """Recognize reads of this descriptor without granting any safety.

        Import spelling alone can establish a possible read operation. The
        separate bounded proof still requires native providers and ownership.
        """
        scope = self.module.scope(call)

        def same_descriptor(node, seen=frozenset()):
            if node is call:
                return True
            if not isinstance(node, ast.Name) or node in seen or len(seen) >= 16:
                return False
            value = self.modes._binding(node)
            return value is not None and same_descriptor(value, seen | {node})

        count = 0
        for operation in ast.walk(scope):
            count += 1
            if count > self.MAX_USES:
                return True
            if not isinstance(operation, ast.Call) or not same_descriptor(
                _argument(operation, 0, "fd")
            ):
                continue
            name = canonical(operation)
            if name == "os.read" or name == "os.fdopen" and handle_read(operation):
                return True
        return False

    def _size(self, node, budget, active=frozenset()):
        budget[0] += 1
        if node is None or node in active or budget[0] > self.MAX_EXPRESSIONS:
            return None
        active = active | {node}
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value if 0 < node.value < 2**63 else None
        if isinstance(node, ast.Name):
            value = self.modes._binding(node)
            return self._size(value, budget, active) if value is not None else None
        if isinstance(node, ast.BinOp) and isinstance(
            node.op, (ast.Add, ast.Mult, ast.LShift)
        ):
            left = self._size(node.left, budget, active)
            right = self._size(node.right, budget, active)
            if (
                left is None
                or right is None
                or isinstance(node.op, ast.LShift)
                and right >= 63
            ):
                return None
            value = (
                left + right
                if isinstance(node.op, ast.Add)
                else left * right
                if isinstance(node.op, ast.Mult)
                else left << right
            )
            return value if value < 2**63 else None
        return None

    def _in_loop_or_nested(self, use, scope):
        current = self.module.parents.get(use)
        while current is not None and current is not scope:
            if isinstance(
                current,
                (
                    ast.For,
                    ast.AsyncFor,
                    ast.While,
                    ast.comprehension,
                    ast.Lambda,
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.ClassDef,
                ),
            ):
                return True
            current = self.module.parents.get(current)
        return current is not scope

    def _bounded_handle(self, item, owner, scope):
        handle = item.optional_vars
        if not isinstance(handle, ast.Name):
            return False
        bindings = self.module.bindings(scope).get(handle.id, ())
        if len(bindings) != 1 or handle.id in self.modes.captured_names.get(scope, ()):
            return False
        reads = []
        closes = []
        count = 0
        for statement in owner.body:
            for use in ast.walk(statement):
                count += 1
                if count > self.MAX_USES:
                    return False
                if not isinstance(use, ast.Name) or use.id != handle.id:
                    continue
                if not isinstance(use.ctx, ast.Load) or self._in_loop_or_nested(
                    use, scope
                ):
                    return False
                attribute = self.module.parents.get(use)
                call = self.module.parents.get(attribute)
                if (
                    not isinstance(attribute, ast.Attribute)
                    or not isinstance(call, ast.Call)
                    or call.func is not attribute
                ):
                    return False
                if (
                    attribute.attr in {"close", "tell"}
                    and not call.args
                    and not call.keywords
                ):
                    if attribute.attr == "close":
                        closes.append(call)
                    continue
                if (
                    attribute.attr not in {"read", "read1", "readline"}
                    or len(call.args) != 1
                    or call.keywords
                ):
                    return False
                if self._size(call.args[0], [0]) is None:
                    return False
                reads.append(call)
        if not reads or any(
            _position(close) < max(map(_position, reads)) for close in closes
        ):
            return None
        return reads

    def bounded_descriptor_read(self, call, native):
        """Every observed use stays with this descriptor and reads a fixed cap."""
        binding = self.module.parents.get(call)
        if isinstance(binding, ast.Assign) and len(binding.targets) == 1:
            target = binding.targets[0]
        elif isinstance(binding, ast.AnnAssign):
            target = binding.target
        else:
            return False
        scope = self.module.scope(call)
        if not isinstance(target, ast.Name) or not isinstance(
            scope, (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            return False
        bindings = self.module.bindings(scope).get(target.id, ())
        if len(bindings) != 1 or target.id in self.modes.captured_names.get(scope, ()):
            return False
        reads = []
        closes = []
        wrappers = []
        count = 0
        for use in ast.walk(scope):
            count += 1
            if count > self.MAX_USES:
                return False
            if not isinstance(use, ast.Name) or use.id != target.id or use is target:
                continue
            if self.module.scope(use) is not scope:
                continue
            if (
                not isinstance(use.ctx, ast.Load)
                or self._in_loop_or_nested(use, scope)
                or self.modes._binding(use) is not call
            ):
                return False
            operation = self.module.parents.get(use)
            if (
                not isinstance(operation, ast.Call)
                or _argument(operation, 0, "fd") is not use
            ):
                return False
            if native(operation.func, "os.close"):
                closes.append(operation)
                continue
            if native(operation.func, "os.fstat"):
                continue
            if native(operation.func, "os.read"):
                if self._size(_argument(operation, 1, "n"), [0]) is None:
                    return False
                reads.append(operation)
                continue
            if not native(operation.func, "os.fdopen"):
                return False
            modes = self.modes.modes(operation)
            if not modes or not modes <= {"r", "rb", "rt"}:
                return False
            if self.provider is None or not self.provider("io.open"):
                return False
            if any("b" not in mode for mode in modes) and not self.provider(
                "io.text_encoding"
            ):
                return False
            item = self.module.parents.get(operation)
            owner = self.module.parents.get(item)
            if not isinstance(item, ast.withitem) or not isinstance(
                owner, (ast.With, ast.AsyncWith)
            ):
                return False
            handle_reads = self._bounded_handle(item, owner, scope)
            if not handle_reads:
                return False
            reads.extend(handle_reads)
            wrappers.append(owner)
        if not reads or any(
            _position(close) < max(map(_position, reads)) for close in closes
        ):
            return False
        if len(wrappers) > 1:
            return False
        for owner in wrappers:
            closed_at = (
                getattr(owner, "end_lineno", 0),
                getattr(owner, "end_col_offset", 0),
            )
            for read in reads:
                current = read
                while current is not None and current is not owner:
                    current = self.module.parents.get(current)
                if current is None and _position(read) > closed_at:
                    return False
        return True
