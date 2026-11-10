"""Conservative, shared static subjects for Python test-quality advice.

This selects directly declared pytest functions/methods and import-proven
unittest methods. It does not emulate plugins, imported/inherited test bodies,
test factories, nested classes or arbitrary decorators. Existing collection
settings and Done's marker/dead-assertion semantics are reused without reparsing
source, importing the target, or constructing a hashed Done inventory.
"""

from __future__ import annotations

import ast
import configparser
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Iterator

from skylos.done.inventory import (
    _body_markers,
    _class_markers,
    _dead_nodes,
    _decorator_markers,
    _decorator_name,
    _dotted,
    _import_aliases,
    _module_markers,
)
from skylos.rules.quality._pytest_collection import (
    _CONFIGS,
    _DEFAULTS,
    _MAX_PATH_PARTS,
    _MAX_BYTES,
    PytestCollection,
    _class_collection_barrier,
    _collectable_function,
    _matches_name,
    _opted_out,
    _pytest_aliases,
    _read_config,
    _testpaths_select_file,
    pytest_collection_config,
)
from skylos.rules.quality._receivers import _parameters, _scope_bindings
from skylos.rules.quality._test_collection_state import uncertain_collection_names
from skylos.rules.quality._test_flow import unreachable_test_nodes

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_SCOPES = (*_FUNCTIONS, ast.ClassDef, ast.Lambda)
_FIXTURE_DIRS = frozenset(
    {
        "fixture",
        "fixtures",
        "data",
        "testdata",
        "golden",
        "goldens",
        "snapshot",
        "snapshots",
        "__snapshots__",
        "corpus",
    }
)
_CACHE_KEY = "_test_quality_subjects"
_CLASS_HOOKS = frozenset(
    {
        "setUp",
        "setUpClass",
        "asyncSetUp",
        "tearDown",
        "tearDownClass",
        "asyncTearDown",
        "setup_method",
        "setup_class",
        "teardown_method",
        "teardown_class",
    }
)


@dataclass(frozen=True)
class TestSubject:
    __test__ = False

    node: ast.FunctionDef | ast.AsyncFunctionDef
    name: str
    framework: str
    # Done represents unreachable/ineffective assertion descendants by AST id.
    dead_nodes: frozenset[int]
    # Proven or possible local fixture/hook checks; not a runtime assertion proof.
    fixture_backed: bool = False


def scope_nodes(function: ast.FunctionDef | ast.AsyncFunctionDef) -> Iterator[ast.AST]:
    """Yield the function and its body, excluding all nested scope subtrees.

    Defaults, decorators and annotations belong to definition time, so they are
    not test-body checks. Nested callables/classes require their own proof.
    """
    yield function
    pending = list(reversed(function.body))
    while pending:
        node = pending.pop()
        if isinstance(node, _SCOPES):
            continue
        yield node
        pending.extend(reversed(list(ast.iter_child_nodes(node))))


def _selected_file(context):
    filename, project_root = context.get("filename"), context.get("project_root")
    if not filename or project_root is None:
        return None
    try:
        root = Path(project_root).absolute()
        path = Path(filename)
        if not path.is_absolute():
            path = root / path
        relative = path.relative_to(root)
        if (
            path.suffix != ".py"
            or path.name == "conftest.py"
            or ".." in relative.parts
            or len(relative.parts) > _MAX_PATH_PARTS
            or any(part.lower() in _FIXTURE_DIRS for part in relative.parts[:-1])
            or relative != path.resolve().relative_to(root.resolve())
            or path.is_symlink()
        ):
            return None
        config = pytest_collection_config(root)
        if config is None:
            # None also means malformed/unsafe configuration; defaults are
            # justified only when there is no selected configuration to read.
            for name, mode in _CONFIGS:
                candidate = root / name
                try:
                    stat = candidate.lstat()
                except FileNotFoundError:
                    continue
                if candidate.is_symlink() or stat.st_size > _MAX_BYTES:
                    return None
                # The metadata-keyed reader is shared with the configuration
                # helper; None means valid but unrelated configuration.
                try:
                    selected = _read_config(
                        str(root),
                        name,
                        mode,
                        stat.st_size,
                        stat.st_mtime_ns,
                        stat.st_ctime_ns,
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
                if selected is not None:
                    return None
            config = PytestCollection(**_DEFAULTS)
        collected = _testpaths_select_file(
            relative, root, config.testpaths, config.norecursedirs
        ) and any(
            fnmatchcase(relative.as_posix() if "/" in pattern else path.name, pattern)
            for pattern in config.python_files
        )
        return config, collected
    except (OSError, RuntimeError, TypeError, ValueError):
        return None


def _aliases(module, bindings):
    """Done's import names, restricted to stable framework imports.

    Supplying empty entries for unproven names prevents Done's intentionally
    permissive spelling fallback from treating a local lookalike as pytest.
    """
    aliases = {node.id: () for node in ast.walk(module) if isinstance(node, ast.Name)}
    imported = _import_aliases(module.body)
    blocked = set()
    for node in ast.walk(module):
        if isinstance(node, (ast.Global, ast.Nonlocal)):
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
    if "*" not in bindings.names:
        aliases.update(
            {
                name: target
                for name, target in imported.items()
                if target
                and target[0] in {"pytest", "unittest"}
                and bindings.counts[name] == 1
                and name not in blocked
            }
        )
    return aliases, blocked


def _function_aliases(function, aliases, framework):
    aliases = dict(aliases)
    bindings = _scope_bindings(function)
    for name in bindings.names | _parameters(function):
        aliases[name] = ()
    local = _import_aliases(function.body)
    aliases.update(
        {
            name: target
            for name, target in local.items()
            if target
            and target[0] in {"pytest", "unittest"}
            and bindings.counts[name] == 1
            and name not in _parameters(function)
        }
    )
    positional = [*function.args.posonlyargs, *function.args.args]
    if (
        framework == "unittest"
        and positional
        and positional[0].arg not in bindings.names
    ):
        aliases[positional[0].arg] = ("self",)
    return aliases


def _assigned_marks(node):
    return [
        statement.value
        for statement in node.body
        if isinstance(statement, (ast.Assign, ast.AnnAssign))
        and any(
            isinstance(target, ast.Name) and target.id == "pytestmark"
            for target in (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
        )
        and statement.value is not None
    ]


def _marker_scope(node):
    # pytest also reads annotated pytestmark assignments. Adapt that one
    # statement shape to Done's marker reader without changing its contracts.
    return ast.Module(
        body=[
            ast.Assign(targets=[statement.target], value=statement.value)
            if isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.target.id == "pytestmark"
            and statement.value is not None
            else statement
            for statement in node.body
        ],
        type_ignores=[],
    )


def _unittest_skip_flag(node):
    for statement in node.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else [statement.target]
        )
        if any(
            isinstance(target, ast.Name) and target.id == "__unittest_skip__"
            for target in targets
        ):
            try:
                if bool(ast.literal_eval(statement.value)):
                    return True
            except (TypeError, ValueError, SyntaxError, RecursionError):
                return True
    return False


def _fixture_marked(expressions, aliases):
    pending = list(expressions)
    while pending:
        expression = pending.pop()
        if isinstance(expression, (ast.List, ast.Tuple)):
            pending.extend(expression.elts)
        elif _decorator_name(expression, aliases) == ("pytest", "mark", "usefixtures"):
            return True
    return False


def _class_traits(node, classes, aliases, seen=frozenset()):
    if node in seen:
        return True, False
    local_aliases = dict(aliases)
    for name in _scope_bindings(node).names:
        local_aliases[name] = ()
    skipped = bool(
        _opted_out(node)
        or _unittest_skip_flag(node)
        or _decorator_markers(node.decorator_list, aliases)
        or _class_markers(_marker_scope(node), local_aliases)
    )
    fixture = _fixture_marked(node.decorator_list, aliases) or _fixture_marked(
        _assigned_marks(node), local_aliases
    )
    # Hooks may carry assertions for a literal-placeholder test body. Opaque
    # hook behavior is not evidence that the test has no runtime checks.
    fixture |= any(
        isinstance(item, _FUNCTIONS) and item.name in _CLASS_HOOKS for item in node.body
    )
    fixture |= _module_fixtures(node, local_aliases)
    for base in node.bases:
        if isinstance(base, ast.Name) and base.id in classes:
            base_skip, base_fixture = _class_traits(
                classes[base.id], classes, aliases, seen | {node}
            )
            skipped |= base_skip
            fixture |= base_fixture
    return skipped, fixture


def _scope_body_marked(function, aliases):
    # Done's marker grammar is reused on individual calls/raises, so its walk
    # cannot descend into deferred nested scopes contained in a call argument.
    for node in scope_nodes(function):
        if isinstance(node, ast.Call):
            probe = ast.Call(func=node.func, args=[], keywords=[])
        elif isinstance(node, ast.Raise):
            exception = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
            probe = ast.Raise(exc=exception, cause=None)
        else:
            continue
        if _body_markers(probe, aliases):
            return True
    return False


def _module_fixtures(module, aliases):
    for node in module.body:
        if not isinstance(node, _FUNCTIONS):
            continue
        if node.name in {
            "setup_module",
            "teardown_module",
            "setup_function",
            "teardown_function",
        }:
            return True
        for decorator in node.decorator_list:
            if (
                isinstance(decorator, ast.Call)
                and _decorator_name(decorator, aliases)
                in {("pytest", "fixture"), ("pytest", "yield_fixture")}
                and any(
                    keyword.arg == "autouse"
                    and not (
                        isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is False
                    )
                    for keyword in decorator.keywords
                )
            ):
                return True
    return False


def _possible_conftest_fixtures(context):
    """Presence is uncertainty, not proof: do not read or run conftest code."""
    root = Path(context["project_root"]).absolute()
    path = Path(context["filename"])
    if not path.is_absolute():
        path = root / path
    directory = path.parent
    for _ in range(_MAX_PATH_PARTS):
        try:
            (directory / "conftest.py").lstat()
            return True
        except FileNotFoundError:
            pass
        except OSError:
            return True
        if directory == root:
            break
        directory = directory.parent
    return False


def _proven_testcases(module, bindings, aliases, blocked):
    proven = set()
    imports = {
        name: statement.lineno
        for statement in module.body
        if isinstance(statement, (ast.Import, ast.ImportFrom))
        for name in _import_aliases([statement])
    }
    for node in module.body:
        if not isinstance(node, ast.ClassDef) or bindings.counts[node.name] != 1:
            continue
        if node.name in blocked or node.keywords or not node.bases:
            continue
        if any(
            _decorator_name(decorator, aliases)[:2] != ("pytest", "mark")
            and not _decorator_markers([decorator], aliases)
            for decorator in node.decorator_list
        ):
            continue
        good = True
        for base in node.bases:
            target = _dotted(base, aliases)
            root = base
            while isinstance(root, ast.Attribute):
                root = root.value
            native = (
                target
                in {("unittest", "TestCase"), ("unittest", "IsolatedAsyncioTestCase")}
                and isinstance(root, ast.Name)
                and imports.get(root.id, node.lineno) < node.lineno
            )
            if not native and not (isinstance(base, ast.Name) and base.id in proven):
                good = False
                break
        if good:
            proven.add(node.name)
    return proven


def _select(module, context):
    selection = _selected_file(context)
    if selection is None or _opted_out(module):
        return ()
    config, pytest_file = selection
    bindings = _scope_bindings(module)
    aliases, blocked = _aliases(module, bindings)
    blocked |= uncertain_collection_names(module, config, bindings)
    for name in blocked:
        aliases[name] = ()
    if _module_markers(_marker_scope(module), aliases):
        return ()
    pytest_aliases = {
        name: evidence
        for name, evidence in _pytest_aliases(module, bindings).items()
        if name not in blocked
    }
    classes = {
        node.name: node
        for node in module.body
        if isinstance(node, ast.ClassDef)
        and bindings.counts[node.name] == 1
        and node.name not in blocked
    }
    testcases = _proven_testcases(module, bindings, aliases, blocked)
    fixture_backed = (
        _fixture_marked(_assigned_marks(module), aliases)
        or _module_fixtures(module, aliases)
        or _possible_conftest_fixtures(context)
    )
    subjects = []

    def add(function, name, framework, inherited_fixture=False):
        if _decorator_markers(function.decorator_list, aliases):
            return
        local_aliases = _function_aliases(function, aliases, framework)
        if _scope_body_marked(function, local_aliases):
            return
        subjects.append(
            TestSubject(
                function,
                name,
                framework,
                frozenset(_dead_nodes(function)) | unreachable_test_nodes(function),
                fixture_backed
                or inherited_fixture
                or _fixture_marked(function.decorator_list, aliases),
            )
        )

    for node in module.body:
        if isinstance(node, _FUNCTIONS):
            if (
                pytest_file
                and node.name not in blocked
                and _collectable_function(
                    node, module.body, config, bindings, pytest_aliases
                )
            ):
                add(node, node.name, "pytest")
        elif (
            isinstance(node, ast.ClassDef)
            and node.name not in blocked
            and not _opted_out(node)
        ):
            framework = "unittest" if node.name in testcases else "pytest"
            class_bindings = _scope_bindings(node)
            class_aliases = {
                name: evidence
                for name, evidence in pytest_aliases.items()
                if name not in class_bindings.names
            }
            if framework == "pytest" and (
                not pytest_file
                or bindings.counts[node.name] != 1
                or not _matches_name(node.name, config.python_classes)
                or _class_collection_barrier(
                    node, classes, pytest_aliases=pytest_aliases
                )
            ):
                continue
            skipped, inherited_fixture = _class_traits(node, classes, aliases)
            if skipped:
                continue
            if any(
                not _decorator_name(decorator, aliases)[:2] == ("pytest", "mark")
                for decorator in node.decorator_list
            ):
                continue
            method_config = (
                config
                if framework == "pytest"
                else PytestCollection(
                    config.python_files,
                    config.python_classes,
                    ("test",),
                    config.testpaths,
                    config.norecursedirs,
                )
            )
            for method in node.body:
                if (
                    isinstance(method, _FUNCTIONS)
                    and f"{node.name}.{method.name}" not in blocked
                    and _collectable_function(
                        method, node.body, method_config, class_bindings, class_aliases
                    )
                ):
                    add(
                        method,
                        f"{node.name}.{method.name}",
                        framework,
                        inherited_fixture,
                    )
    return tuple(subjects)


def test_subjects(module: ast.Module, context) -> tuple[TestSubject, ...]:
    """Share selection once per existing module and analyzer context."""
    if not isinstance(module, ast.Module):
        return ()
    cached = context.get(_CACHE_KEY)
    if cached is None or cached[0] is not module:
        cached = (module, _select(module, context))
        context[_CACHE_KEY] = cached
    return cached[1]


test_subjects.__test__ = False
