"""Static pytest collection evidence for quality advice only.

Repository configuration describes collection, not whether code is safe. Keep
this separate from the test-path helpers used by security rules.
"""

from __future__ import annotations

import ast
import configparser
import shlex
from dataclasses import dataclass
from fnmatch import fnmatchcase
from functools import lru_cache
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

from skylos.core.safe_cache_io import read_project_text_no_symlink
from skylos.rules.quality._receivers import _scope_bindings

_MAX_BYTES = 2_000_000
_CONFIGS = (
    ("pytest.toml", "native"),
    (".pytest.toml", "native"),
    ("pytest.ini", "pytest"),
    (".pytest.ini", "pytest"),
    ("pyproject.toml", "pyproject"),
    ("tox.ini", "pytest"),
    ("setup.cfg", "tool:pytest"),
)
_DEFAULT_NORECURSEDIRS = (
    "*.egg", ".*", "_darcs", "build", "CVS", "dist", "node_modules", "venv", "{arch}"
)
_DEFAULTS = {
    "python_files": ("test_*.py", "*_test.py"),
    "python_classes": ("Test",),
    "python_functions": ("test",),
    "testpaths": (),
    "norecursedirs": _DEFAULT_NORECURSEDIRS,
}
_MAX_TESTPATHS = 128
_MAX_PATH_PARTS = 64


@dataclass(frozen=True)
class PytestCollection:
    python_files: tuple[str, ...]
    python_classes: tuple[str, ...]
    python_functions: tuple[str, ...]
    testpaths: tuple[str, ...]
    norecursedirs: tuple[str, ...] = _DEFAULT_NORECURSEDIRS


def _options(source, name, mode):
    """Return (selected, native, options); never merge configuration files."""
    if mode in {"native", "pyproject"}:
        document = tomllib.loads(source)
        if mode == "native":
            options = document.get("pytest", {})
            if any(not isinstance(value, dict) for value in document.values()):
                raise ValueError("pytest TOML options must be in a table")
            return True, True, options
        table = document.get("tool", {}).get("pytest", {})
        native = {key: value for key, value in table.items() if key != "ini_options"}
        legacy = table.get("ini_options")
        if native and legacy:
            raise ValueError("mixed pytest configuration modes")
        if native:
            return True, True, native
        if legacy is not None:
            return True, False, legacy
        return False, False, {}
    # pytest's INI parser preserves case and does not inherit [DEFAULT].
    parser = configparser.ConfigParser(interpolation=None, default_section=None)
    parser.optionxform = str
    # pytest.ini is selected even when empty.
    if source.strip():
        parser.read_string(source)
    if parser.has_section(mode):
        return True, False, dict(parser.items(mode))
    if name == "setup.cfg" and parser.has_section("pytest"):
        raise ValueError("unsupported setup.cfg pytest section")
    return name in {"pytest.ini", ".pytest.ini"}, False, {}


@lru_cache(maxsize=256)
def _read_config(root, name, mode, size, mtime_ns, ctime_ns):
    source = read_project_text_no_symlink(
        root, Path(root) / name, max_bytes=_MAX_BYTES, errors="strict"
    )
    if source is None:
        raise ValueError("unreadable pytest configuration")
    selected, native, options = _options(source, name, mode)
    if not selected:
        return None
    if not isinstance(options, dict):
        raise ValueError("pytest settings must be a table")
    values = {}
    for key, default in _DEFAULTS.items():
        value = options.get(key, list(default))
        if isinstance(value, str) and not native:
            value = shlex.split(value)
        if not isinstance(value, list) or not all(
            isinstance(item, str) for item in value
        ):
            raise ValueError("pytest collection settings require string lists")
        values[key] = tuple(value)
    return PytestCollection(**values)


def pytest_collection_config(project_root=None) -> PytestCollection | None:
    """Read a single root config without imports, symlinks or parent traversal.

    Invalid higher-precedence files stop selection. A stat-keyed cache observes
    configuration rewrites within a process.
    """
    if project_root is None:
        return None
    root = str(Path(project_root).absolute())
    for name, mode in _CONFIGS:
        path = Path(root) / name
        try:
            stat = path.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return None
        try:
            if path.is_symlink() or stat.st_size > _MAX_BYTES:
                return None
            config = _read_config(
                root, name, mode, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns
            )
        except (
            OSError,
            ValueError,
            RuntimeError,
            AttributeError,
            TypeError,
            configparser.Error,
        ):
            return None
        if config is not None:
            return config
    return None


def _matches_name(name, patterns):
    return any(
        name.startswith(pattern) or fnmatchcase(name, pattern) for pattern in patterns
    )


@lru_cache(maxsize=4096)
def _testpaths_select_file(relative, root, testpaths, norecursedirs):
    """Require a local root-discovery selection, without expanding its tree.

    pytest uses recursive glob expansion for testpaths when run at the root
    without explicit arguments. Matching a directory selects descendants;
    wildcard components themselves never consume a slash. Unknown explicit
    invocation paths or imported tests cannot establish test-only evidence.
    """
    if len(testpaths) > _MAX_TESTPATHS or len(norecursedirs) > _MAX_TESTPATHS:
        return False
    if any(
        not value.strip() or len(value) > 4096 or "\\" in value or "\x00" in value
        for value in norecursedirs
    ):
        return False

    def descendants_allowed(start):
        for index in range(start, len(relative.parts) - 1):
            part = relative.parts[index]
            if part == "__pycache__":
                return False
            for pattern in norecursedirs:
                if "/" in pattern:
                    text = str(root.joinpath(*relative.parts[: index + 1]))
                    if not Path(pattern).is_absolute():
                        pattern = "*/" + pattern
                else:
                    text = part
                if fnmatchcase(text, pattern):
                    return False
        return True

    if not testpaths:
        return descendants_allowed(0)
    patterns = []
    for value in testpaths:
        if (
            not value.strip()
            or len(value) > 4096
            or "\\" in value
            or "\x00" in value
            or "::" in value
        ):
            return False
        pattern = Path(value)
        if ".." in pattern.parts:
            return False
        if pattern.is_absolute():
            try:
                pattern = pattern.relative_to(root)
            except ValueError:
                return False
        if len(pattern.parts) > _MAX_PATH_PARTS:
            return False
        patterns.append(pattern.parts)

    def selected(pattern):
        @lru_cache(maxsize=None)
        def matches(pattern_index, path_index):
            if pattern_index == len(pattern):
                # A standalone ** glob does not select the root itself.
                return (path_index > 0 or not pattern) and descendants_allowed(path_index)
            component = pattern[pattern_index]
            if component == "**":
                return matches(pattern_index + 1, path_index) or (
                    path_index < len(relative.parts)
                    and not relative.parts[path_index].startswith(".")
                    and matches(pattern_index, path_index + 1)
                )
            if path_index == len(relative.parts):
                return False
            part = relative.parts[path_index]
            if part.startswith(".") and not component.startswith("."):
                return False
            return fnmatchcase(part, component) and matches(
                pattern_index + 1, path_index + 1
            )

        return matches(0, 0)

    return any(selected(pattern) for pattern in patterns)


def _opted_out(node):
    for statement in node.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else [statement.target]
        )
        if any(
            isinstance(target, ast.Name) and target.id == "__test__"
            for target in targets
        ) and _false_literal(statement.value):
            return True
    return False


def _false_literal(value):
    try:
        return not bool(ast.literal_eval(value))
    except (ValueError, TypeError, SyntaxError, RecursionError):
        return False


def _collectable_function(node, body, config, bindings=None, pytest_aliases=None):
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    if not _matches_name(node.name, config.python_functions):
        return False
    if bindings is None:
        bindings = _scope_bindings(ast.Module(body=body, type_ignores=[]))
    if bindings.counts[node.name] != 1:
        return False
    for decorator in node.decorator_list:
        expression = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = (
            expression.id
            if isinstance(expression, ast.Name)
            else expression.attr
            if isinstance(expression, ast.Attribute)
            else None
        )
        if name in {"fixture", "yield_fixture", "property", "cached_property"}:
            return False
        # An arbitrary wrapper can replace the function with a non-callable.
        # Import-proven pytest marks preserve the collected callable; unknown
        # decorators cannot establish new configured test-only evidence.
        if not _pytest_mark_decorator(decorator, pytest_aliases or {}):
            return False
    for statement in body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else [statement.target]
        )
        if _false_literal(statement.value) and any(
            isinstance(target, ast.Attribute)
            and target.attr == "__test__"
            and isinstance(target.value, ast.Name)
            and target.value.id == node.name
            for target in targets
        ):
            return False
    return True


def _pytest_mark_decorator(node, aliases):
    expression = node.func if isinstance(node, ast.Call) else node
    if not isinstance(expression, ast.Attribute):
        return False
    root = expression.value
    if isinstance(root, ast.Name):
        binding = aliases.get(root.id)
        return bool(binding and binding[0] == "mark" and binding[1] < node.lineno)
    binding = (
        aliases.get(root.value.id)
        if isinstance(root, ast.Attribute) and isinstance(root.value, ast.Name)
        else None
    )
    return (
        isinstance(root, ast.Attribute)
        and root.attr == "mark"
        and binding is not None
        and binding[0] == "module"
        and binding[1] < node.lineno
    )


def _pytest_aliases(module, bindings):
    aliases = {}
    blocked = set()
    if "*" in bindings.names:
        return aliases
    for node in ast.walk(module):
        if isinstance(node, ast.Global):
            blocked.update(node.names)
        elif isinstance(node, ast.Attribute) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            root = node.value
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                blocked.add(root.id)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"setattr", "delattr"}
            and node.args
            and isinstance(node.args[0], ast.Name)
        ):
            blocked.add(node.args[0].id)
    for statement in module.body:
        if isinstance(statement, ast.Import):
            aliases.update(
                (alias.asname or alias.name, ("module", statement.lineno))
                for alias in statement.names
                if alias.name == "pytest"
            )
        elif (
            isinstance(statement, ast.ImportFrom)
            and statement.module == "pytest"
            and not statement.level
        ):
            aliases.update(
                (alias.asname or alias.name, ("mark", statement.lineno))
                for alias in statement.names
                if alias.name == "mark"
            )
    return {
        name: evidence
        for name, evidence in aliases.items()
        if bindings.counts[name] == 1 and name not in blocked
    }


def _class_collection_barrier(node, classes, seen=frozenset(), pytest_aliases=None):
    if node in seen or _opted_out(node) or node.keywords:
        return True
    if {"__init__", "__new__"} & _scope_bindings(node).names:
        return True
    if any(
        not _pytest_mark_decorator(decorator, pytest_aliases or {})
        for decorator in node.decorator_list
    ):
        return True
    for base in node.bases:
        if not isinstance(base, ast.Name) or base.id not in classes:
            return True
        if _class_collection_barrier(
            classes[base.id], classes, seen | {node}, pytest_aliases
        ):
            return True
    return False


def is_collected_pytest_class(
    node, config: PytestCollection, classes=None, *, pytest_aliases=None
) -> bool:
    if not isinstance(node, ast.ClassDef) or _opted_out(node):
        return False
    methods = [
        child
        for child in node.body
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    # Preserve unittest collection independently of pytest class-name settings.
    if any(
        (isinstance(base, ast.Name) and base.id.endswith("TestCase"))
        or (isinstance(base, ast.Attribute) and base.attr.endswith("TestCase"))
        for base in node.bases
    ):
        return True
    bindings = _scope_bindings(node)
    method_pytest_aliases = {
        name: evidence
        for name, evidence in (pytest_aliases or {}).items()
        if name not in bindings.names
    }
    return (
        _matches_name(node.name, config.python_classes)
        and not _class_collection_barrier(
            node, classes or {}, pytest_aliases=pytest_aliases
        )
        and any(
            _collectable_function(
                method, node.body, config, bindings, method_pytest_aliases
            )
            for method in methods
        )
    )


def collected_pytest_classes(module, config):
    """Resolve only locally declared bases; unknown inheritance retains advice."""
    bindings = _scope_bindings(module)
    mutated = set()
    for node in ast.walk(module):
        root = None
        attribute = None
        if isinstance(node, ast.Attribute) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            root = node.value
            attribute = node.attr
            while isinstance(root, ast.Attribute):
                attribute = root.attr
                root = root.value
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"setattr", "delattr"}
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
        ):
            root = node.args[0]
            attribute = node.args[1].value
        if (
            isinstance(root, ast.Name)
            and attribute is not None
            and (
                attribute in {"__init__", "__new__", "__test__"}
                or _matches_name(attribute, config.python_functions)
            )
        ):
            mutated.add(root.id)
    classes = {
        node.name: node
        for node in module.body
        if isinstance(node, ast.ClassDef)
        and bindings.counts[node.name] == 1
        and node.name not in mutated
    }
    pytest_aliases = _pytest_aliases(module, bindings)
    return {
        node
        for node in classes.values()
        if is_collected_pytest_class(
            node, config, classes, pytest_aliases=pytest_aliases
        )
    }


def _has_collected_items(source, config):
    tree = ast.parse(source)
    if _opted_out(tree):
        return False
    bindings = _scope_bindings(tree)
    pytest_aliases = _pytest_aliases(tree, bindings)
    return bool(collected_pytest_classes(tree, config)) or any(
        _collectable_function(node, tree.body, config, bindings, pytest_aliases)
        for node in tree.body
    )


@lru_cache(maxsize=4096)
def _read_collected_file(root, path, size, mtime_ns, ctime_ns, config):
    source = read_project_text_no_symlink(
        root, path, max_bytes=_MAX_BYTES, errors="replace"
    )
    return isinstance(source, str) and _has_collected_items(source, config)


def is_collected_pytest_file(filename, project_root=None, source=None) -> bool:
    config = pytest_collection_config(project_root)
    if config is None or not filename or project_root is None:
        return False
    try:
        root = Path(project_root).absolute()
        path = Path(filename)
        if not path.is_absolute():
            path = root / path
        if path.is_symlink():
            return False
        relative_path = path.relative_to(root)
        if ".." in relative_path.parts or len(relative_path.parts) > _MAX_PATH_PARTS:
            return False
        resolved_relative = path.resolve().relative_to(root.resolve())
        if relative_path != resolved_relative:
            return False
        if config.testpaths and not path.is_file():
            return False
        if not _testpaths_select_file(
            relative_path, root, config.testpaths, config.norecursedirs
        ):
            return False
        relative = relative_path.as_posix()
        if not any(
            fnmatchcase(relative if "/" in pattern else path.name, pattern)
            for pattern in config.python_files
        ):
            return False
        if source is None:
            stat = path.stat()
            if stat.st_size > _MAX_BYTES:
                return False
            return _read_collected_file(
                str(root),
                str(path),
                stat.st_size,
                stat.st_mtime_ns,
                stat.st_ctime_ns,
                config,
            )
        if not isinstance(source, str) or len(source) > _MAX_BYTES:
            return False
        return _has_collected_items(source, config)
    except (OSError, RuntimeError, SyntaxError, ValueError):
        return False
