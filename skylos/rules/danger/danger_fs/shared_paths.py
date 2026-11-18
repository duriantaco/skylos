"""Positive filesystem-source patterns for predictable names in shared directories."""

import ast
import posixpath

_SHARED_ROOTS = {"/tmp", "/var/tmp", "/dev/shm"}
_PATH_TYPES = {"pathlib.Path", "pathlib.PosixPath"}


def shared_file_literal(value):
    """A direct child of a conventional shared root, with an ordinary leaf."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "surrogateescape")
    if not isinstance(value, str):
        return False
    directory, leaf = posixpath.split(value)
    return directory in _SHARED_ROOTS and leaf not in {"", ".", ".."}


def fixed_shared_file(operand, native_name, binding, *, require_path=False):
    """Resolve only literal components, native path joins and fixed local aliases."""
    remaining = 64

    def path(node):
        nonlocal remaining
        remaining -= 1
        if remaining < 0:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value, False
        if isinstance(node, ast.Name):
            value = binding(node)
            return path(value) if value is not None else None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            base, child = path(node.left), path(node.right)
            if base and base[1] and child:
                return posixpath.join(base[0], child[0]), True
            return None
        if not isinstance(node, ast.Call) or node.keywords or len(node.args) > 16:
            return None
        if isinstance(node.func, ast.Attribute) and node.func.attr == "joinpath":
            base = path(node.func.value)
            if not base or not base[1]:
                return None
            parts = [base]
            is_path = True
        else:
            name = native_name(node)
            if name == "tempfile.gettempdir" and not node.args:
                # Represents the platform's shared temp root for this pattern.
                return "/tmp", False
            if name not in _PATH_TYPES and name != "os.path.join":
                return None
            parts = []
            is_path = name in _PATH_TYPES
        for argument in node.args:
            part = path(argument)
            if not part:
                return None
            parts.append(part)
        if parts:
            return posixpath.join(*(value for value, _ in parts)), is_path
        return None

    if isinstance(operand, ast.Constant):
        return not require_path and shared_file_literal(operand.value)
    resolved = path(operand)
    return bool(
        resolved
        and (resolved[1] or not require_path)
        and shared_file_literal(resolved[0])
    )
