from __future__ import annotations

import ast
import configparser

from skylos.core.safe_cache_io import read_text_no_symlink

try:
    import tomllib
except Exception:
    tomllib = None

try:
    import tomli
except Exception:
    tomli = None


MAX_ENTRYPOINT_MANIFEST_BYTES = 5_000_000
_SETUP_CALL_NAMES = {"setup", "setuptools.setup", "distutils.core.setup"}


def _object_reference(value):
    """``module:attr.attr [extras]`` -> ``(module, "attr.attr")``.

    A module-only reference (``pytest11 = "pkg.plugin"``) has an empty
    attribute. The format follows the packaging entry-point specification.
    """
    if not isinstance(value, str):
        return None
    reference = value.split("[", 1)[0].strip()
    module, _, attribute = reference.partition(":")
    module = module.strip()
    attribute = attribute.strip()
    if not module or not all(part.isidentifier() for part in module.split(".")):
        return None
    if attribute and not all(part.isidentifier() for part in attribute.split(".")):
        return None
    return module, attribute


def _to_qname(target):
    reference = _object_reference(target)
    if reference is None or not reference[1]:
        return None
    module, attribute = reference
    return f"{module}.{attribute}"


def _read(path):
    return read_text_no_symlink(
        path,
        max_bytes=MAX_ENTRYPOINT_MANIFEST_BYTES,
        encoding="utf-8",
        errors="ignore",
    )


def _load_toml(raw):
    if tomllib is not None:
        return tomllib.loads(raw)
    if tomli is not None:
        return tomli.loads(raw)
    return {}


def _table_values(table):
    if not isinstance(table, dict):
        return []
    values = []
    for value in table.values():
        if isinstance(value, dict):
            value = value.get("callable") or value.get("reference")
        if isinstance(value, str):
            values.append(value)
    return values


def _group_values(groups):
    if not isinstance(groups, dict):
        return []
    values = []
    for table in groups.values():
        values.extend(_table_values(table))
    return values


def _pyproject_values(project_root):
    raw = _read(project_root / "pyproject.toml")
    if not raw:
        return []
    try:
        data = _load_toml(raw)
    except (ValueError, RecursionError):
        return []
    if not isinstance(data, dict):
        return []
    values = []
    project = data.get("project")
    if isinstance(project, dict):
        for table_name in ("scripts", "gui-scripts"):
            values.extend(_table_values(project.get(table_name)))
        values.extend(_group_values(project.get("entry-points")))
    tool = data.get("tool")
    poetry = {}
    if isinstance(tool, dict):
        poetry = tool.get("poetry") or {}
    if isinstance(poetry, dict):
        values.extend(_table_values(poetry.get("scripts")))
        values.extend(_group_values(poetry.get("plugins")))
    return values


def _ini_lines(text):
    values = []
    for line in str(text).splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "[")):
            continue
        name, separator, value = line.partition("=")
        if separator and name.strip():
            values.append(value.strip())
    return values


def _setup_cfg_values(project_root):
    raw = _read(project_root / "setup.cfg")
    if not raw:
        return []
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(raw)
    except configparser.Error:
        return []
    if not parser.has_section("options.entry_points"):
        return []
    values = []
    for group_lines in parser["options.entry_points"].values():
        values.extend(_ini_lines(group_lines))
    return values


def _call_name(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def _module_assignments(tree):
    assignments = {}
    for stmt in tree.body:
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
        ):
            name = stmt.targets[0].id
            if name in assignments:
                assignments[name] = None
            else:
                assignments[name] = stmt.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            assignments[stmt.target.id] = stmt.value
    return assignments


def _resolve(node, assignments, depth=0):
    if isinstance(node, ast.Name) and depth < 4:
        value = assignments.get(node.id)
        if value is not None:
            return _resolve(value, assignments, depth + 1)
    return node


def _string_items(node, assignments):
    node = _resolve(node, assignments)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return _ini_lines(node.value)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values = []
        for element in node.elts:
            element = _resolve(element, assignments)
            if isinstance(element, ast.Constant) and isinstance(element.value, str):
                values.extend(_ini_lines(element.value))
        return values
    return []


def _entry_point_items(node, assignments):
    node = _resolve(node, assignments)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return _ini_lines(node.value)
    values = []
    if isinstance(node, ast.Dict):
        for value in node.values:
            values.extend(_string_items(value, assignments))
    elif isinstance(node, ast.Call) and _call_name(node.func) == "dict":
        for keyword in node.keywords:
            if keyword.arg is not None:
                values.extend(_string_items(keyword.value, assignments))
    return values


def _setup_py_values(project_root):
    raw = _read(project_root / "setup.py")
    if not raw:
        return []
    try:
        tree = ast.parse(raw)
    except (SyntaxError, ValueError, RecursionError):
        return []
    assignments = _module_assignments(tree)
    values = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _call_name(node.func) not in _SETUP_CALL_NAMES:
            continue
        for keyword in node.keywords:
            if keyword.arg == "entry_points":
                values.extend(_entry_point_items(keyword.value, assignments))
    return values


def extract_entrypoint_references(project_root):
    """Static ``(module, attribute)`` targets of every declared entry point.

    Reads ``[project.scripts]``, ``[project.gui-scripts]``,
    ``[project.entry-points.<group>]``, Poetry ``scripts`` and ``plugins``,
    ``setup.cfg`` ``[options.entry_points]`` and literal ``entry_points=``
    passed to ``setup()`` in ``setup.py``. ``setup.py`` is parsed, never run.
    """
    values = []
    values.extend(_pyproject_values(project_root))
    values.extend(_setup_cfg_values(project_root))
    values.extend(_setup_py_values(project_root))
    references = set()
    for value in values:
        reference = _object_reference(value)
        if reference is not None:
            references.add(reference)
    return references


def entrypoint_qnames(references):
    """Qualified names an entry point loads: ``mod:Cls.attr`` loads both
    ``mod.Cls`` and ``mod.Cls.attr``. Module-only references name no symbol."""
    out: set[str] = set()
    for module, attribute in references:
        if not attribute:
            continue
        parts = attribute.split(".")
        for index in range(1, len(parts) + 1):
            out.add(f"{module}.{'.'.join(parts[:index])}")
    return out


def extract_entrypoints(project_root):
    return entrypoint_qnames(extract_entrypoint_references(project_root))
