import ast
import operator
import re
from pathlib import Path
from typing import Optional, Tuple, Any, Callable

OPS: dict[type[ast.cmpop], Callable[[Any, Any], bool]] = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.Is: operator.is_,
    ast.IsNot: operator.is_not,
    ast.In: lambda x, y: x in y,
    ast.NotIn: lambda x, y: x not in y,
}


def _is_sys_version_info_node(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute):
        if node.attr == "version_info":
            if isinstance(node.value, ast.Name) and node.value.id == "sys":
                return True
            if isinstance(node.value, ast.Attribute):
                parts = []
                current = node.value
                while isinstance(current, ast.Attribute):
                    parts.append(current.attr)
                    current = current.value
                if isinstance(current, ast.Name):
                    parts.append(current.id)
                    full_path = ".".join(reversed(parts))
                    if full_path == "sys":
                        return True
    return False


def _extract_version_tuple(node: ast.AST) -> Optional[tuple[int, ...]]:
    if isinstance(node, ast.Tuple):
        version_parts = []
        for elt in node.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, int):
                version_parts.append(elt.value)
            else:
                return None
        return tuple(version_parts)
    return None


def _find_pyproject_toml(file_path: Optional[str]) -> Optional[Path]:
    if file_path is None:
        return None

    current = Path(file_path).resolve()
    if current.is_file():
        current = current.parent

    for _ in range(10):
        pyproject = current / "pyproject.toml"
        if pyproject.exists():
            return pyproject

        parent = current.parent
        if parent == current:
            break
        current = parent

    return None


def _parse_requires_python(
    file_path: Optional[str],
) -> Tuple[Optional[Tuple[int, int]], Optional[Tuple[int, int]]]:
    pyproject_path = _find_pyproject_toml(file_path)
    if not pyproject_path:
        return (None, None)

    try:
        import tomllib
    except Exception:
        try:
            import tomli as tomllib
        except Exception:
            return (None, None)

    try:
        with open(
            pyproject_path, "rb"
        ) as f:  # skylos: ignore[SKY-D215] analyzer reads discovered pyproject files
            data = tomllib.load(f)

        requires_python = data.get("project", {}).get("requires-python", "")
        if not requires_python:
            return (None, None)

        min_version = None
        max_version = None

        match = re.search(r">=\s*(\d+)\.(\d+)", requires_python)
        if match:
            min_version = (int(match.group(1)), int(match.group(2)))

        match = re.search(r"<=?\s*(\d+)\.(\d+)", requires_python)
        if match:
            max_version = (int(match.group(1)), int(match.group(2)))

        return (min_version, max_version)
    except Exception:
        return (None, None)


def _version_check_is_within_supported_range(
    version_tuple: tuple[int, ...],
    op_type: type[ast.cmpop],
    min_version: Optional[Tuple[int, int]],
    max_version: Optional[Tuple[int, int]],
) -> bool:
    if min_version is None:
        return True

    if op_type in (ast.GtE, ast.Gt):
        if version_tuple > min_version:
            return True
        if max_version and version_tuple <= max_version:
            return True

    if op_type in (ast.Lt, ast.LtE):
        if max_version is None or version_tuple > min_version:
            return True

    if op_type == ast.Eq:
        if not max_version or (min_version <= version_tuple <= max_version):
            return True

    if op_type == ast.NotEq:
        return True

    return False


_UNKNOWN_VALUE = object()


def evaluate_static_condition(node: ast.AST, file_path: Optional[str] = None):
    """Return a known literal value, or None when it cannot be proved.

    Boolean operations return their selected operand in Python. Keep that
    value for comparisons, and distinguish literal None from an unknown name
    internally. No target calls or attribute lookups are executed.
    """
    value = _evaluate_static_value(node, file_path)
    return None if value is _UNKNOWN_VALUE else value


def evaluate_static_truth(
    node: ast.AST, file_path: Optional[str] = None
) -> Optional[bool]:
    """Evaluate an expression specifically as a branch condition."""
    if isinstance(node, ast.BoolOp):
        conjunction = isinstance(node.op, ast.And)
        unknown = False
        for operand in node.values:
            truth = evaluate_static_truth(operand, file_path)
            if truth is None:
                unknown = True
            elif truth is not conjunction:
                return truth
        return None if unknown else conjunction
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        truth = evaluate_static_truth(node.operand, file_path)
        return None if truth is None else not truth
    value = _evaluate_static_value(node, file_path)
    return None if value is _UNKNOWN_VALUE else bool(value)


def _evaluate_static_value(node: ast.AST, file_path: Optional[str] = None):
    if isinstance(node, ast.Constant):
        return node.value

    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        val = _evaluate_static_value(node.operand, file_path)
        if val is not _UNKNOWN_VALUE:
            return not val
        else:
            return _UNKNOWN_VALUE

    if isinstance(node, ast.BoolOp):
        value = _UNKNOWN_VALUE
        for operand in node.values:
            value = _evaluate_static_value(operand, file_path)
            if value is _UNKNOWN_VALUE:
                return _UNKNOWN_VALUE
            if isinstance(node.op, ast.And) and not value:
                return value
            if isinstance(node.op, ast.Or) and value:
                return value
        return value

    if isinstance(node, ast.Compare):
        if len(node.ops) == 1 and len(node.comparators) == 1:
            is_version_check = False
            version_tuple = None
            op_type = type(node.ops[0])

            if _is_sys_version_info_node(node.left):
                version_tuple = _extract_version_tuple(node.comparators[0])
                is_version_check = version_tuple is not None
            elif _is_sys_version_info_node(node.comparators[0]):
                version_tuple = _extract_version_tuple(node.left)
                is_version_check = version_tuple is not None

            if is_version_check and version_tuple:
                min_version, max_version = _parse_requires_python(file_path)
                if _version_check_is_within_supported_range(
                    version_tuple, op_type, min_version, max_version
                ):
                    return _UNKNOWN_VALUE

            left = _evaluate_static_value(node.left, file_path)
            right = _evaluate_static_value(node.comparators[0], file_path)

            if (
                left is not _UNKNOWN_VALUE
                and right is not _UNKNOWN_VALUE
                and op_type in OPS
            ):
                if op_type in (ast.Is, ast.IsNot) and not any(
                    value is None
                    or value is True
                    or value is False
                    or value is Ellipsis
                    for value in (left, right)
                ):
                    # Non-singleton literal identity depends on compilation
                    # and interning, not just its source value.
                    return _UNKNOWN_VALUE
                try:
                    return OPS[op_type](left, right)
                except Exception:
                    return _UNKNOWN_VALUE

    return _UNKNOWN_VALUE


def extract_constant_string(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None
