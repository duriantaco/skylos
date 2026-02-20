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
        with open(pyproject_path, "rb") as f:
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


def evaluate_static_condition(
    node: ast.AST, file_path: Optional[str] = None
) -> Optional[bool]:
    if isinstance(node, ast.Constant):
        return node.value

    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        val = evaluate_static_condition(node.operand, file_path)
        if val is not None:
            return not val
        else:
            return None

    if isinstance(node, ast.BoolOp):
        values = []
        for v in node.values:
            values.append(evaluate_static_condition(v, file_path))

        if isinstance(node.op, ast.And):
            for v in values:
                if v is False:
                    return False

            for v in values:
                if v is None:
                    return None

            return True

        if isinstance(node.op, ast.Or):
            for v in values:
                if v is True:
                    return True

            for v in values:
                if v is None:
                    return None

            return False

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
                    return None

            left = evaluate_static_condition(node.left, file_path)
            right = evaluate_static_condition(node.comparators[0], file_path)

            if left is not None and right is not None and op_type in OPS:
                try:
                    return OPS[op_type](left, right)
                except Exception:
                    return None

    return None


def extract_constant_string(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None
