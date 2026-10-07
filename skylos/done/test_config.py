"""SKY-A112: test settings loosened by the change.

A change can make failing tests "pass" without touching a test: select fewer
tests in pytest options, ignore directories, add a conftest.py hook that
drops tests or rewrites their outcomes (JUnit XML then reports the rewritten
outcome too), lower a coverage floor, or let a CI test step fail quietly.
Each loosening the change adds is one finding. Jest and Vitest settings are
read by ``js_test_config.py``.
"""

from __future__ import annotations

import ast
import sys
import configparser
import fnmatch
import hashlib
import re
import shlex
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import PurePosixPath

import yaml

from skylos.done.base import Comparison, DoneError, _git_text
from skylos.done.inventory import (
    TestItem,
    _decorator_name,
    _dotted,
    _import_aliases,
    collect_tests,
    compare_inventories,
)

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib

RULE_ID = "SKY-A112"

LocalModule = Callable[[str], bool]

# pytest hooks that can stop tests from running or change what they report.
OUTCOME_HOOKS = frozenset(
    {
        "pytest_collection_modifyitems",
        "pytest_ignore_collect",
        "pytest_collect_file",
        "pytest_pycollect_makeitem",
        "pytest_generate_tests",
        "pytest_runtest_protocol",
        "pytest_runtest_setup",
        "pytest_runtest_call",
        "pytest_runtest_makereport",
        "pytest_runtest_logreport",
        "pytest_report_teststatus",
        "pytest_sessionfinish",
    }
)

_INI_FILES = {
    "pytest.ini": ("pytest",),
    ".pytest.ini": ("pytest",),
    "tox.ini": ("pytest",),
    "setup.cfg": ("tool:pytest",),
}
_COVERAGE_INI_SECTIONS = {
    ".coveragerc": ("run", "report"),
    "setup.cfg": ("coverage:run", "coverage:report"),
    "tox.ini": ("coverage:run", "coverage:report"),
}
_SELECTION_FLAGS = {
    "-k": "selects tests by name (-k)",
    "-m": "selects tests by marker (-m)",
    "--deselect": "deselects tests (--deselect)",
    "--ignore": "ignores test paths (--ignore)",
    "--ignore-glob": "ignores test paths (--ignore-glob)",
    "--lf": "runs only last-failed tests (--lf)",
    "--last-failed": "runs only last-failed tests (--last-failed)",
    "--sw": "stops at the first failure and resumes later (--sw)",
    "--stepwise": "stops at the first failure and resumes later (--stepwise)",
    "--co": "collects tests without running them (--co)",
    "--collect-only": "collects tests without running them (--collect-only)",
}
_FLAGS_WITH_VALUES = {"-k", "-m", "--deselect", "--ignore", "--ignore-glob", "-p"}
# Turning these plugins off changes speed or ordering, never which results count.
_HARMLESS_DISABLED_PLUGINS = frozenset(
    {
        "cacheprovider",
        "randomly",
        "random_order",
        "xdist",
        "sugar",
        "rerunfailures",
        "flaky",
    }
)
_PYTEST_DEFAULT_NORECURSE = frozenset(
    {"*.egg", ".*", "_darcs", "build", "CVS", "dist", "node_modules", "venv", "{arch}"}
)
_PYTEST_DEFAULT_COLLECTION = {
    "python_files": ["test_*.py", "*_test.py"],
    "python_classes": ["Test"],
    "python_functions": ["test"],
}
_TEST_STEP_RE = re.compile(
    r"\b(?:pytest|py\.test|tox|nox|unittest|jest|vitest|mocha|rspec|phpunit"
    r"|(?:npm|yarn|pnpm|bun)\s+(?:run\s+)?test"
    r"|go\s+test|cargo\s+test|dotnet\s+test|make\s+test"
    r"|mvn\b[^\n]*\btest|gradlew?\b[^\n]*\btest)\b"
)
_SWALLOW_RE = re.compile(
    r"\|\|\s*(?:true|:|exit\s+0)\b|;\s*exit\s+0\s*$|\bset\s+\+e\b", re.M
)


@dataclass(frozen=True)
class ConfigFinding:
    file: str
    line: int | None
    message: str


def detect_loosened_test_config(comparison: Comparison) -> list[ConfigFinding]:
    findings: list[ConfigFinding] = []

    def local(module: str) -> bool:
        # A plugin module in this repository can rewrite results; a published
        # plugin (pytest_asyncio, xdist) is a dependency choice, not a loosening.
        stem = module.replace(".", "/")
        return any(
            comparison.head_text(candidate) is not None
            for candidate in (f"{stem}.py", f"{stem}/__init__.py")
        )

    existing = _ExistingTests(comparison)
    for changed in comparison.changed:
        head_path = changed.head_path
        if head_path is None:
            continue
        name = PurePosixPath(head_path).name
        is_config = (
            name in _INI_FILES
            or name in _COVERAGE_INI_SECTIONS
            or name in {"pyproject.toml", "conftest.py"}
            or _is_workflow(head_path)
        )
        if not is_config:
            continue
        base = comparison.base_text(changed.base_path)
        head = comparison.head_text(head_path)
        if head is None:
            continue
        # A brand-new config can only drop tests that already existed: one
        # that leaves none of them out loosens nothing.
        tests = (
            existing.under(str(PurePosixPath(head_path).parent))
            if base is None
            else None
        )
        if name == "pyproject.toml":
            findings += _pyproject(head_path, base, head, local, tests)
        if name in _INI_FILES:
            base_options = (
                _base_pytest_options(comparison)
                if base is None and head_path in {"pytest.ini", ".pytest.ini"}
                else None
            )
            findings += _pytest_ini(
                head_path, base, head, _INI_FILES[name], local, base_options, tests
            )
        if name in _COVERAGE_INI_SECTIONS:
            findings += _coverage_ini(
                head_path, base, head, _COVERAGE_INI_SECTIONS[name]
            )
        if name == "conftest.py":
            findings += _conftest(head_path, base, head, local)
        if _is_workflow(head_path):
            findings += _workflow(head_path, base, head)
    findings += _hook_dependency_changes(comparison)
    from skylos.done.js_test_config import detect_loosened_js_test_config

    findings += detect_loosened_js_test_config(comparison)
    return findings


def _is_workflow(path: str) -> bool:
    return path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))


class _ExistingTests:
    """Python test files that existed at the base and still exist, relative
    to a config file's directory: what a new collection setting can drop."""

    def __init__(self, comparison: Comparison) -> None:
        self.comparison = comparison
        self._paths: list[str] | None = None

    def under(self, directory: str) -> list[str] | None:
        if self._paths is None:
            listing = _git_text(
                self.comparison._context,
                "ls-tree",
                "-r",
                "--name-only",
                "-z",
                self.comparison.base_sha,
            )
            if listing is None:
                return None
            gone = {
                c.base_path
                for c in self.comparison.changed
                if c.status == "deleted" and c.base_path
            }
            moved = {
                c.base_path: c.path
                for c in self.comparison.changed
                if c.status == "renamed" and c.base_path
            }
            self._paths = [
                moved.get(path, path)
                for path in listing.split("\0")
                if path.endswith(".py")
                and path not in gone
                and _matches_any(
                    PurePosixPath(path).name, _PYTEST_DEFAULT_COLLECTION["python_files"]
                )
            ]
        if directory in {"", "."}:
            return list(self._paths)
        prefix = directory.rstrip("/") + "/"
        return [p[len(prefix) :] for p in self._paths if p.startswith(prefix)]


def _matches_any(name: str, patterns) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def _in_directory(test: str, pattern: str) -> bool:
    """A test file under a directory ``norecursedirs`` names (a basename
    pattern, or a path pattern when it has a slash)."""
    for parent in PurePosixPath(test).parents:
        if str(parent) == ".":
            continue
        if "/" in pattern:
            if fnmatch.fnmatchcase(str(parent), pattern) or fnmatch.fnmatchcase(
                str(parent), "*/" + pattern
            ):
                return True
        elif fnmatch.fnmatchcase(parent.name, pattern):
            return True
    return False


def _dropped_by_testpaths(tests: list[str], head_paths, removed_paths) -> list[str]:
    return [
        test
        for test in tests
        if not any(_under_path(test, p) for p in head_paths)
        and (not removed_paths or any(_under_path(test, p) for p in removed_paths))
    ]


# ---------------------------------------------------------------------------
# pytest options
# ---------------------------------------------------------------------------


def _pyproject(
    path: str, base: str | None, head: str, local: LocalModule, tests=None
) -> list[ConfigFinding]:
    head_data = _toml(head)
    if head_data is None:
        return []
    base_data = _toml(base) or {}
    findings = _compare_pytest_options(
        path,
        head,
        _toml_pytest_options(base_data),
        _toml_pytest_options(head_data),
        local,
        tests,
    )
    findings += _compare_coverage(
        path,
        head,
        _toml_coverage(base_data),
        _toml_coverage(head_data),
    )
    return findings


def _pytest_ini(
    path,
    base,
    head,
    sections,
    local: LocalModule,
    base_options: dict | None = None,
    tests=None,
) -> list[ConfigFinding]:
    return _compare_pytest_options(
        path,
        head,
        _ini_options(base, sections) if base_options is None else base_options,
        _ini_options(head, sections),
        local,
        tests,
    )


def _coverage_ini(path, base, head, sections) -> list[ConfigFinding]:
    run_section, report_section = sections
    return _compare_coverage(
        path,
        head,
        _ini_coverage(base, run_section, report_section),
        _ini_coverage(head, run_section, report_section),
    )


def _toml(text: str | None) -> dict | None:
    if text is None:
        return None
    try:
        return tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return None


def _toml_pytest_options(data: dict) -> dict:
    tool = data.get("tool") if isinstance(data.get("tool"), dict) else {}
    pytest_cfg = tool.get("pytest") if isinstance(tool.get("pytest"), dict) else {}
    # pytest < 9 reads [tool.pytest.ini_options]; pytest 9 also reads typed
    # values directly from [tool.pytest]. Both count.
    merged = {k: v for k, v in pytest_cfg.items() if k != "ini_options"}
    ini = pytest_cfg.get("ini_options")
    if isinstance(ini, dict):
        merged.update(ini)
    return {
        key: _as_list(value) if key != "xfail_strict" else value
        for key, value in merged.items()
    }


def _ini_options(text: str | None, sections: tuple[str, ...]) -> dict:
    parser = _ini(text)
    if parser is None:
        return {}
    for section in sections:
        if parser.has_section(section):
            return {
                key: (value if key == "xfail_strict" else _as_list(value))
                for key, value in parser.items(section)
            }
    return {}


def _ini(text: str | None) -> configparser.RawConfigParser | None:
    if not text:
        return None
    parser = configparser.RawConfigParser(strict=False, interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error:
        return None
    return parser


def _as_list(value) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        try:
            return shlex.split(value)
        except ValueError:
            return value.split()
    return []


def _option_pairs(tokens: list[str]) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    index = 0
    while index < len(tokens):
        token = tokens[index]
        index += 1
        if token.startswith("--") and "=" in token:
            flag, value = token.split("=", 1)
            pairs.add((flag, value))
        elif token in _FLAGS_WITH_VALUES:
            value = tokens[index] if index < len(tokens) else ""
            index += 1
            pairs.add((token, value))
        elif token[:2] in {"-k", "-m", "-p"} and len(token) > 2:
            pairs.add((token[:2], token[2:]))
        else:
            pairs.add((token, ""))
    return pairs


def _compare_pytest_options(
    path, head_text, base: dict, head: dict, local: LocalModule, tests=None
) -> list[ConfigFinding]:
    """Settings that collect or run fewer tests. ``tests`` are the test files
    that existed at the base, relative to the config's directory (None when
    unknown): a path setting that leaves none of them out loosens nothing."""
    findings = []
    default_files = _PYTEST_DEFAULT_COLLECTION["python_files"]
    if set(base.get("python_files", default_files)) - set(default_files):
        tests = None  # the existing tests were found by the default names
    line = _line_of(head_text, "addopts")
    base_pairs = _option_pairs(base.get("addopts", []))
    for flag, value in sorted(_option_pairs(head.get("addopts", [])) - base_pairs):
        what = None
        if tests is not None and (
            (flag == "--ignore" and not any(_under_path(t, value) for t in tests))
            or (
                flag == "--ignore-glob"
                and not any(fnmatch.fnmatchcase(t, value) for t in tests)
            )
        ):
            continue  # ignores a path that holds no existing test
        if flag in _SELECTION_FLAGS:
            what = _SELECTION_FLAGS[flag]
        elif flag == "-p" and value.startswith("no:"):
            if value[3:] not in _HARMLESS_DISABLED_PLUGINS:
                what = f"disables pytest plugin {value[3:]!r} (-p no:)"
        elif flag == "-p" and local(value):
            what = f"loads the repository's own pytest plugin {value!r} (-p)"
        if what:
            shown = f" {value}" if value and flag != "-p" else ""
            findings.append(
                ConfigFinding(path, line, f"pytest addopts now {what}{shown}".rstrip())
            )
    findings += _cov_fail_under_flag(path, line, base, head)

    added_dirs = (
        set(head.get("norecursedirs", []))
        - set(base.get("norecursedirs", []))
        - _PYTEST_DEFAULT_NORECURSE
    )
    for directory in sorted(added_dirs):
        if tests is not None and not any(_in_directory(t, directory) for t in tests):
            continue  # names no directory that holds an existing test
        findings.append(
            ConfigFinding(
                path,
                _line_of(head_text, "norecursedirs"),
                f"pytest no longer collects tests under {directory!r} (norecursedirs)",
            )
        )
    base_paths = set(base.get("testpaths", []))
    head_paths = set(head.get("testpaths", []))
    removed_paths = base_paths - head_paths
    if (
        head_paths
        and (not base_paths or removed_paths)
        and (
            tests is None
            or _dropped_by_testpaths(
                tests, head_paths, removed_paths if base_paths else ()
            )
        )
    ):
        findings.append(
            ConfigFinding(
                path,
                _line_of(head_text, "testpaths"),
                "pytest testpaths now restrict collection to "
                + ", ".join(repr(p) for p in sorted(head_paths))
                if not base_paths
                else "pytest testpaths no longer include "
                + ", ".join(repr(p) for p in sorted(removed_paths)),
            )
        )
    for key, defaults in _PYTEST_DEFAULT_COLLECTION.items():
        before = base.get(key, defaults)
        after = head.get(key, defaults)
        if (
            key == "python_files"
            and tests is not None
            and not any(
                _matches_any(PurePosixPath(t).name, before)
                and not _matches_any(PurePosixPath(t).name, after)
                for t in tests
            )
        ):
            continue  # every existing test file still matches
        if set(before) - set(after):
            findings.append(
                ConfigFinding(
                    path,
                    _line_of(head_text, key),
                    f"pytest {key} changed, which changes which tests are collected",
                )
            )
    if _truthy(base.get("xfail_strict")) and not _truthy(head.get("xfail_strict")):
        findings.append(
            ConfigFinding(
                path,
                _line_of(head_text, "xfail_strict"),
                "xfail_strict turned off: unexpected passes no longer fail",
            )
        )
    return findings


def base_excluded_tests(
    comparison: Comparison,
    tests,
    argv: tuple[str, ...],
    *,
    base_tests=None,
    file_only=False,
) -> set[str]:
    """Static, trusted-base reasons that a changed test need not report a result.

    Missing results are otherwise unfinished. Head-controlled collection
    settings and newly introduced ``__test__ = False`` never excuse them.
    """
    options = _base_pytest_options(comparison)
    args = list(
        argv[3:] if len(argv) >= 3 and argv[1:3] == ("-m", "pytest") else argv[1:]
    )
    for index, token in enumerate(args[:-1]):
        if token in {"-o", "--override-ini"} and "=" in args[index + 1]:
            key, value = args[index + 1].split("=", 1)
            options[key] = _as_list(value)
    selection = _option_pairs(options.get("addopts", []) + args)
    selectors = _effective_selectors(options.get("addopts", []) + args)
    ignored = [value for flag, value in selection if flag == "--ignore"]
    ignored_globs = [value for flag, value in selection if flag == "--ignore-glob"]
    selected_paths = _command_paths(comparison, args)
    changed_paths = {item.path: item.base_path for item in comparison.changed}
    if base_tests is None:
        base_tests = [
            test
            for path in {changed_paths.get(test.path) or test.path for test in tests}
            for test in collect_tests(path, comparison.base_text(path))
        ]
    renamed_paths = {
        item.base_path: item.path
        for item in comparison.changed
        if item.status == "renamed" and item.base_path
    }
    matched = compare_inventories(base_tests, tests, renamed_paths).matched
    excluded = set()
    source_trees: dict[str, ast.Module | None] = {}
    head_trees: dict[str, ast.Module | None] = {}
    hook_cache: dict[str, bool] = {}
    for test in tests:
        before = matched.get(test.id)
        selector_test = before or test
        path = before.path if before else changed_paths.get(test.path) or test.path
        parts = PurePosixPath(path).parts
        explicit_file = path in selected_paths
        collection_dirs = parts[:-1]
        for selected in selected_paths:
            if _under_path(path, selected):
                collection_dirs = PurePosixPath(path).relative_to(selected).parts[:-1]
                break
        filenames = options.get(
            "python_files", _PYTEST_DEFAULT_COLLECTION["python_files"]
        )
        directories = options.get("norecursedirs", _PYTEST_DEFAULT_NORECURSE)
        testpaths = options.get("testpaths", [])
        outside = (
            (
                not explicit_file
                and not any(
                    fnmatch.fnmatchcase(parts[-1], pattern) for pattern in filenames
                )
            )
            or any(
                fnmatch.fnmatchcase(part, pattern)
                for part in collection_dirs
                for pattern in directories
            )
            or (
                testpaths
                and not selected_paths
                and not any(_under_path(path, selected) for selected in testpaths)
            )
            or (
                selected_paths
                and not any(_under_path(path, selected) for selected in selected_paths)
            )
            or any(_under_path(path, ignored_path) for ignored_path in ignored)
            or any(fnmatch.fnmatchcase(path, pattern) for pattern in ignored_globs)
        )
        # unittest methods do not use pytest's python_classes/functions rules.
        if (
            not file_only
            and not selector_test.unittest_style
            and not selector_test.classes
        ):
            outside = outside or not _matches_prefix(
                selector_test.name, options.get("python_functions", ["test"])
            )
        elif not file_only and not selector_test.unittest_style:
            outside = outside or any(
                not _matches_prefix(name, options.get("python_classes", ["Test"]))
                for name in selector_test.classes
            )
        if path not in source_trees:
            source_trees[path] = _parse(comparison.base_text(path))
        tree = source_trees[path]
        if file_only:
            if outside:
                excluded.add(test.id)
            continue
        if before is None and test.path not in head_trees:
            head_trees[test.path] = _parse(comparison.head_text(test.path))
        selector_tree = tree if before else head_trees[test.path]
        if _selector_excludes(
            comparison, path, selector_tree, selector_test, selectors, hook_cache
        ):
            outside = True
        if (
            outside
            or _base_test_disabled(tree, selector_test.classes, selector_test.name)
            or _unconditional_module_skip(tree)
        ):
            excluded.add(test.id)
    return excluded


def _selector_excludes(comparison, path, tree, test, selection, hook_cache) -> bool:
    selectors = [
        (flag, value) for flag, value in selection if flag in {"-m", "-k", "--deselect"}
    ]
    if not selectors:
        return False
    # Dynamic base hooks are not an independently verified selection policy.
    # In particular, their unchanged body may read PR-modified globals/helpers.
    parents = [PurePosixPath("."), *PurePosixPath(path).parents]
    for parent in parents:
        conftest = (parent / "conftest.py").as_posix()
        if conftest not in hook_cache:
            parsed = _parse(comparison.base_text(conftest))
            hook_cache[conftest] = bool(parsed is not None and _hooks(parsed))
        if hook_cache[conftest]:
            return False
    marker_names = _static_marker_names(tree, test.classes, test.name)
    for flag, value in selectors:
        if flag == "--deselect":
            if "[" in value:
                continue  # One deselected parameter case does not exclude its test.
            target = value
            if test.id == target or test.id.startswith(target + "::"):
                return True
            continue
        if marker_names is None:
            continue
        if flag == "-m":
            selected = _selection_expression(
                value,
                lambda name: (
                    True
                    if name in marker_names
                    else None
                    if test.parametrized
                    else False
                ),
            )
        else:
            keywords = (
                *PurePosixPath(path).parts,
                *test.classes,
                test.name,
                *marker_names,
                comparison.root.name,
            )
            selected = _selection_expression(
                value,
                lambda name: (
                    True
                    if any(name.lower() in keyword.lower() for keyword in keywords)
                    else None
                    if test.parametrized
                    else False
                ),
            )
        if selected is False:
            return True
    return False


def _effective_selectors(tokens: list[str]) -> list[tuple[str, str]]:
    """pytest's last -m/-k wins; --deselect may be repeated."""
    named = {}
    deselected = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        index += 1
        flag = token
        value = None
        if token.startswith("--deselect="):
            flag, value = token.split("=", 1)
        elif token in {"-m", "-k", "--deselect"}:
            value = tokens[index] if index < len(tokens) else ""
            index += 1
        elif token[:2] in {"-m", "-k"} and len(token) > 2:
            flag, value = token[:2], token[2:].removeprefix("=")
        if value is not None:
            if flag == "--deselect":
                deselected.append((flag, value))
            else:
                named[flag] = value
        elif token in _FLAGS_WITH_VALUES | {"-o", "--override-ini", "-c"}:
            index += 1
    return [*named.items(), *deselected]


def _selection_expression(
    text: str, matches: Callable[[str], bool | None]
) -> bool | None:
    try:
        expression = ast.parse(text, mode="eval")
    except (SyntaxError, ValueError):
        return None

    def evaluate(node):
        if isinstance(node, ast.Name):
            return matches(node.id)
        if isinstance(node, ast.Constant) and isinstance(node.value, bool):
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            value = evaluate(node.operand)
            return None if value is None else not value
        if isinstance(node, ast.BoolOp):
            values = [evaluate(value) for value in node.values]
            if isinstance(node.op, ast.And):
                if False in values:
                    return False
                if None in values:
                    return None
                return all(values)
            if isinstance(node.op, ast.Or):
                if True in values:
                    return True
                if None in values:
                    return None
                return any(values)
        return None

    return evaluate(expression.body)


def _unconditional_module_skip(tree: ast.Module | None) -> bool:
    if tree is None:
        return False
    aliases = _import_aliases(tree.body)
    for statement in tree.body:
        value = (
            statement.value if isinstance(statement, (ast.Expr, ast.Assign)) else None
        )
        if not isinstance(value, ast.Call):
            continue
        raw = _dotted(value.func)
        if not raw or aliases.get(raw[0], ())[:1] != ("pytest",):
            continue
        if _dotted(value.func, aliases) == ("pytest", "skip") and any(
            keyword.arg == "allow_module_level"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in value.keywords
        ):
            return True
    return False


def _static_marker_names(
    tree: ast.Module | None, classes: tuple[str, ...], name: str
) -> set[str] | None:
    if tree is None:
        return None
    aliases = _import_aliases(tree.body)
    markers = set()
    body = tree.body
    for scope in (*classes, name):
        expressions = []
        for node in body:
            if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "pytestmark"
                for target in node.targets
            ):
                expressions.extend(
                    node.value.elts
                    if isinstance(node.value, (ast.List, ast.Tuple))
                    else [node.value]
                )
        definition = next(
            (
                node
                for node in body
                if isinstance(
                    node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
                )
                and node.name == scope
            ),
            None,
        )
        if definition is None:
            return None
        expressions.extend(definition.decorator_list)
        for expression in expressions:
            parts = list(_decorator_name(expression, aliases))
            if "mark" in parts and len(parts) >= 2:
                markers.add(parts[-1])
            elif parts not in (["staticmethod"], ["classmethod"]):
                return None
        body = definition.body
    return markers


def _base_pytest_options(comparison: Comparison) -> dict:
    for name in ("pytest.ini", ".pytest.ini"):
        text = comparison.base_text(name)
        if text is not None:
            return _ini_options(text, ("pytest",))
    data = _toml(comparison.base_text("pyproject.toml")) or {}
    tool = data.get("tool")
    if isinstance(tool, dict) and isinstance(tool.get("pytest"), dict):
        return _toml_pytest_options(data)
    for name, sections in (("tox.ini", ("pytest",)), ("setup.cfg", ("tool:pytest",))):
        options = _ini_options(comparison.base_text(name), sections)
        if options:
            return options
    return {}


def _under_path(path: str, selected: str) -> bool:
    selected = selected.replace("\\", "/").split("::", 1)[0].rstrip("/")
    while selected.startswith("./"):
        selected = selected[2:]
    return selected in {"", "."} or path == selected or path.startswith(selected + "/")


def _matches_prefix(name: str, patterns) -> bool:
    return any(
        fnmatch.fnmatchcase(name, pattern)
        if any(char in pattern for char in "*?[")
        else name.startswith(pattern)
        for pattern in patterns
    )


def _command_paths(comparison: Comparison, args: list[str]) -> list[str]:
    values = _FLAGS_WITH_VALUES | {
        "-o",
        "--override-ini",
        "-c",
        "--rootdir",
        "--confcutdir",
        "--basetemp",
        "--junitxml",
        "--junit-xml",
        "--maxfail",
        "--tb",
        "--capture",
        "--color",
        "--durations",
        "--durations-min",
        "-n",
        "--numprocesses",
        "--dist",
        "--cov",
        "--cov-report",
        "--cov-config",
        "--cov-fail-under",
    }
    paths = []
    index = 0
    while index < len(args):
        token = args[index]
        index += 1
        if token in values:
            index += 1
        elif not token.startswith("-"):
            path = token.split("::", 1)[0]
            if (
                not PurePosixPath(path).is_absolute()
                and (comparison.root / path).exists()
            ):
                paths.append(PurePosixPath(path).as_posix())
    return paths


def _base_test_disabled(
    tree: ast.Module | None, classes: tuple[str, ...], name: str
) -> bool:
    if tree is None:
        return False
    body = tree.body
    for class_name in (*classes, None):
        if _scope_test_false(body, ("__test__",)):
            return True
        if class_name is None:
            return _scope_test_false(body, (name, "__test__"))
        if _scope_test_false(body, (class_name, "__test__")):
            return True
        klass = next(
            (
                node
                for node in body
                if isinstance(node, ast.ClassDef) and node.name == class_name
            ),
            None,
        )
        if klass is None:
            return False
        body = klass.body
    return False


def _scope_test_false(body, parts: tuple[str, ...]) -> bool:
    """A final unconditional False assignment, without a later ambiguous write."""
    disabled = False
    for node in body:
        writes = [
            child
            for child in ast.walk(node)
            if isinstance(child, (ast.Assign, ast.AnnAssign, ast.AugAssign))
        ]
        for assignment in writes:
            targets = (
                assignment.targets
                if isinstance(assignment, ast.Assign)
                else [assignment.target]
            )
            if any(_dotted(target) == parts for target in targets):
                disabled = (
                    assignment is node
                    and isinstance(assignment, (ast.Assign, ast.AnnAssign))
                    and isinstance(assignment.value, ast.Constant)
                    and assignment.value.value is False
                )
    return disabled


def _cov_fail_under_flag(path, line, base: dict, head: dict) -> list[ConfigFinding]:
    before = _flag_number(base.get("addopts", []), "--cov-fail-under")
    after = _flag_number(head.get("addopts", []), "--cov-fail-under")
    if before is not None and (after is None or after < before):
        shown = "removed" if after is None else f"lowered to {after:g}"
        return [ConfigFinding(path, line, f"--cov-fail-under {before:g} {shown}")]
    return []


def _flag_number(tokens: list[str], flag: str) -> float | None:
    for index, token in enumerate(tokens):
        raw = None
        if token.startswith(flag + "="):
            raw = token.split("=", 1)[1]
        elif token == flag and index + 1 < len(tokens):
            raw = tokens[index + 1]
        if raw is not None:
            try:
                return float(raw)
            except ValueError:
                return None
    return None


def _truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, list):
        value = " ".join(value)
    return str(value).strip().lower() in {"true", "1", "yes", "on"}


# ---------------------------------------------------------------------------
# coverage
# ---------------------------------------------------------------------------


def _toml_coverage(data: dict) -> dict:
    tool = data.get("tool") if isinstance(data.get("tool"), dict) else {}
    coverage = tool.get("coverage") if isinstance(tool.get("coverage"), dict) else {}
    run = coverage.get("run") if isinstance(coverage.get("run"), dict) else {}
    report = coverage.get("report") if isinstance(coverage.get("report"), dict) else {}
    return {
        "fail_under": report.get("fail_under"),
        "omit": _as_list(run.get("omit")) + _as_list(report.get("omit")),
    }


def _ini_coverage(text, run_section, report_section) -> dict:
    parser = _ini(text)
    if parser is None:
        return {"fail_under": None, "omit": []}

    def get(section, key):
        if parser.has_section(section) and parser.has_option(section, key):
            return parser.get(section, key)
        return None

    def split_lines(value):
        return [v.strip() for v in re.split(r"[\n,]", value or "") if v.strip()]

    return {
        "fail_under": get(report_section, "fail_under"),
        "omit": split_lines(get(run_section, "omit"))
        + split_lines(get(report_section, "omit")),
    }


def _compare_coverage(path, head_text, base: dict, head: dict) -> list[ConfigFinding]:
    findings = []
    before = _number(base.get("fail_under"))
    after = _number(head.get("fail_under"))
    if before is not None and (after is None or after < before):
        shown = "removed" if after is None else f"lowered to {after:g}"
        findings.append(
            ConfigFinding(
                path,
                _line_of(head_text, "fail_under"),
                f"coverage fail_under {before:g} {shown}",
            )
        )
    for pattern in sorted(set(head.get("omit", [])) - set(base.get("omit", []))):
        findings.append(
            ConfigFinding(
                path,
                _line_of(head_text, pattern) or _line_of(head_text, "omit"),
                f"coverage now omits {pattern!r}",
            )
        )
    return findings


def _number(value) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# conftest.py
# ---------------------------------------------------------------------------


def _conftest(
    path: str, base: str | None, head: str, local: LocalModule
) -> list[ConfigFinding]:
    head_tree = _parse(head)
    if head_tree is None:
        return []
    base_tree = _parse(base)
    base_hooks = _hooks(base_tree) if base_tree else {}
    findings = []
    for name, (line, digest) in sorted(_hooks(head_tree).items()):
        if name not in base_hooks:
            findings.append(
                ConfigFinding(
                    path,
                    line,
                    f"adds the pytest hook {name}, which can drop tests or change their results",
                )
            )
        elif base_hooks[name][1] != digest:
            findings.append(
                ConfigFinding(
                    path,
                    line,
                    f"changes the pytest hook {name}, which can drop tests or change their results",
                )
            )
    for key in ("collect_ignore", "collect_ignore_glob", "pytest_plugins"):
        before = _assigned_strings(base_tree, key) if base_tree else set()
        for value in sorted(_assigned_strings(head_tree, key) - before):
            if key == "pytest_plugins" and not local(value):
                continue
            message = (
                f"loads pytest plugin {value!r} (pytest_plugins)"
                if key == "pytest_plugins"
                else f"pytest no longer collects {value!r} ({key})"
            )
            findings.append(ConfigFinding(path, _line_of(head, key), message))
    return findings


def _parse(text: str | None) -> ast.Module | None:
    if not text:
        return None
    try:
        return ast.parse(text)
    except (SyntaxError, ValueError):
        return None


def _hooks(tree: ast.Module) -> dict[str, tuple[int, str]]:
    hooks = {}
    for node in tree.body:
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name in OUTCOME_HOOKS
        ):
            digest = hashlib.sha256(ast.dump(node).encode()).hexdigest()
            hooks[node.name] = (node.lineno, digest)
    return hooks


def _hook_dependency_changes(comparison: Comparison) -> list[ConfigFinding]:
    """Compare local declarations reachable from existing result hooks.

    JUnit receives pytest's final reports, including reports rewritten by hooks.
    An unchanged hook can therefore forge success through a changed global or
    imported helper. Only reachable declarations are compared: an unrelated
    fixture edit does not change the hook's trusted baseline.
    """
    if not any(item.path.endswith(".py") for item in comparison.changed):
        return []
    declarations = _Declarations(comparison, "Pytest hook")
    roots = {
        path for path in declarations.paths if PurePosixPath(path).name == "conftest.py"
    }

    # Existing local pytest plugins are registered hook containers too.
    pending_roots = list(roots)
    options = _base_pytest_options(comparison)
    for flag, value in _option_pairs(options.get("addopts", [])):
        if flag == "-p" and not value.startswith("no:"):
            plugin = declarations.local_path("conftest.py", value)
            if plugin:
                pending_roots.append(plugin)
    inspected = set()
    while pending_roots:
        path = pending_roots.pop()
        if path in inspected:
            continue
        inspected.add(path)
        tree, _ = declarations.module(path, True)
        for plugin_name in _assigned_strings(tree, "pytest_plugins"):
            plugin = declarations.local_path(path, plugin_name)
            if plugin:
                roots.add(plugin)
                pending_roots.append(plugin)
        roots.add(path)

    findings = []
    for root in sorted(roots):
        _, bindings = declarations.module(root, True)
        for hook in sorted(OUTCOME_HOOKS & bindings.keys()):
            change = declarations.first_change([(root, hook, ())])
            if change:
                path, line, symbol = change
                findings.append(
                    ConfigFinding(
                        path,
                        line,
                        f"changes {symbol}, a dependency of the pytest hook {hook}; its test selection or reported outcomes are no longer verified against the base",
                    )
                )
    return findings


class _Declarations:
    """Top-level declarations of repository modules at the base and head.

    ``first_change`` follows what a declaration references, through imports
    of other repository modules, and reports the first reachable declaration
    that differs. Unreachable edits in the same module do not count.
    """

    def __init__(self, comparison: Comparison, subject: str) -> None:
        paths_text = _git_text(
            comparison._context,
            "ls-tree",
            "-r",
            "--name-only",
            "-z",
            comparison.base_sha,
        )
        if paths_text is None:
            raise DoneError(f"Cannot read the baseline {subject.lower()} inventory")
        self.comparison = comparison
        self.subject = subject
        self.paths = set(paths_text.split("\0"))
        self.head_paths = set(self.paths)
        for changed in comparison.changed:
            if changed.status in {"deleted", "renamed"}:
                self.head_paths.discard(changed.base_path or changed.path)
            if changed.status != "deleted":
                self.head_paths.add(changed.path)
        self._cache = {}

    def module(self, path, base):
        key = (path, base)
        if key not in self._cache:
            if len(self._cache) >= 256:
                raise DoneError(
                    f"{self.subject} dependencies exceed the static proof limit"
                )
            text = (
                self.comparison.base_text(path)
                if base
                else self.comparison.head_text(path)
            )
            try:
                tree = ast.parse(text) if text is not None else None
            except (SyntaxError, ValueError):
                tree = None
            if tree is None:
                raise DoneError(
                    f"Cannot inspect {self.subject.lower()} dependency {path}"
                )
            self._cache[key] = (tree, _module_bindings(tree))
        return self._cache[key]

    def local_path(self, source, module_name, level=0, *, base=True):
        if level:
            prefix = PurePosixPath(source).parent.parts
            prefix = prefix[: len(prefix) - level + 1]
            parts = (*prefix, *module_name.split(".")) if module_name else prefix
        else:
            parts = tuple(module_name.split("."))
        stem = "/".join(parts)
        paths = self.paths if base else self.head_paths
        # FileFinder tries a regular package before a same-named module.
        for candidate in (
            f"{stem}/__init__.py",
            f"{stem}.py",
            f"src/{stem}/__init__.py",
            f"src/{stem}.py",
        ):
            if candidate in paths:
                return candidate
        return None

    def first_change(self, pending, visited=None):
        """``(path, line, symbol)`` of the first changed reachable declaration.

        ``pending`` holds ``(path, symbol, attributes)`` starting points. Base
        declarations compared along the way are appended to ``visited``.
        """
        seen = set()
        while pending:
            path, symbol, attributes = pending.pop()
            if (path, symbol, attributes) in seen:
                continue
            seen.add((path, symbol, attributes))
            if len(seen) > 512:
                raise DoneError(
                    f"{self.subject} dependencies exceed the static proof limit"
                )
            _, before = self.module(path, True)
            _, after = self.module(path, False)
            base_nodes = before.get(symbol, [])
            head_nodes = after.get(symbol, [])
            if [ast.dump(n) for n in base_nodes] != [ast.dump(n) for n in head_nodes]:
                return path, (head_nodes[0].lineno if head_nodes else None), symbol
            if visited is not None:
                visited.extend(base_nodes)
            for node in base_nodes:
                imported = _import_binding(node, symbol)
                if imported:
                    module_name, imported_symbol, level = imported
                    target = self.local_path(path, module_name, level)
                    if target != self.local_path(path, module_name, level, base=False):
                        return path, node.lineno, f"import target for {symbol}"
                    if target is None:
                        # Namespace packages have no __init__.py, yet an
                        # explicitly referenced child can be a repository module.
                        child_parts = (
                            (module_name, imported_symbol)
                            if imported_symbol
                            else (module_name, *attributes[:-1])
                        )
                        child_name = ".".join(part for part in child_parts if part)
                        child = self.local_path(path, child_name, level)
                        head_child = self.local_path(
                            path, child_name, level, base=False
                        )
                        if child != head_child:
                            return path, node.lineno, f"import target for {symbol}"
                        if child:
                            child_attributes = (
                                attributes if imported_symbol else attributes[-1:]
                            )
                            if child_attributes:
                                pending.append(
                                    (child, child_attributes[0], child_attributes[1:])
                                )
                            else:
                                _, child_bindings = self.module(child, True)
                                pending.extend(
                                    (child, name, ()) for name in child_bindings
                                )
                        continue
                    if target:
                        if imported_symbol:
                            _, target_bindings = self.module(target, True)
                            submodule = self.local_path(
                                path,
                                ".".join(
                                    part
                                    for part in (module_name, imported_symbol)
                                    if part
                                ),
                                level,
                            )
                            head_submodule = self.local_path(
                                path,
                                ".".join(
                                    part
                                    for part in (module_name, imported_symbol)
                                    if part
                                ),
                                level,
                                base=False,
                            )
                            if (
                                imported_symbol not in target_bindings
                                and submodule != head_submodule
                            ):
                                return path, node.lineno, f"import target for {symbol}"
                            if imported_symbol not in target_bindings and submodule:
                                if attributes:
                                    pending.append(
                                        (submodule, attributes[0], attributes[1:])
                                    )
                                else:
                                    _, submodule_bindings = self.module(submodule, True)
                                    pending.extend(
                                        (submodule, name, ())
                                        for name in submodule_bindings
                                    )
                            else:
                                pending.append((target, imported_symbol, attributes))
                        elif attributes:
                            # ``import package.helper`` binds ``package``;
                            # resolve a referenced submodule before its symbol.
                            target_module = self.local_path(
                                path,
                                ".".join((module_name, *attributes[:-1])),
                                level,
                            )
                            head_target_module = self.local_path(
                                path,
                                ".".join((module_name, *attributes[:-1])),
                                level,
                                base=False,
                            )
                            if target_module != head_target_module:
                                return path, node.lineno, f"import target for {symbol}"
                            pending.append(
                                (
                                    target_module or target,
                                    attributes[-1] if target_module else attributes[0],
                                    (),
                                )
                            )
                        else:
                            _, target_bindings = self.module(target, True)
                            pending.extend(
                                (target, name, ()) for name in target_bindings
                            )
                else:
                    self.add_references(
                        path, _global_references(node), pending, exclude=symbol
                    )
        return None

    def add_references(self, path, references, pending, exclude=None):
        """Queue referenced module names, including ones only the head binds."""
        _, before = self.module(path, True)
        _, after = self.module(path, False)
        for name, attributes in references:
            if name == exclude:
                continue
            if name in before or name in after:
                # A head-only binding can shadow a builtin or imported name.
                pending.append((path, name, attributes))
            elif "*" in before or "*" in after:
                # A star import may supply the name: compare the star imports,
                # then look for the name in each imported repository module.
                pending.append((path, "*", ()))
                for node in before.get("*", []):
                    target = self.local_path(path, node.module or "", node.level)
                    if target:
                        pending.append((target, name, attributes))


def computed_case_changes(
    comparison: Comparison,
    head_tests: list[TestItem],
    base_tests: list[TestItem] | None,
    *,
    skip: set[str] = frozenset(),
) -> dict[str, str]:
    """Computed parametrized tests whose case total this change may reduce.

    Skylos cannot count a computed case list without running the base. It
    trusts the head's cases when the change leaves alone everything that
    builds them: the test's parametrize decorators, its classes' attributes,
    every repository declaration those reach and, for lists read from files,
    all tracked inputs when their paths cannot be proven. A test new in this
    change, or one that was not
    parametrized at the base, has no base total to fall short of.

    Maps head test ids to why their total cannot be checked.
    """
    if base_tests is None:
        return {
            test.id: "its base inventory is unavailable"
            for test in head_tests
            if test.parametrized and test.param_cases is None and test.id not in skip
        }
    renamed = {
        c.base_path: c.path
        for c in comparison.changed
        if c.status == "renamed" and c.base_path
    }
    matched = compare_inventories(base_tests, head_tests, renamed).matched
    computed = [
        test
        for test in head_tests
        if test.id not in skip
        and (
            (test.parametrized and test.param_cases is None)
            or (
                test.id in matched
                and matched[test.id].parametrized
                and matched[test.id].param_cases is None
            )
        )
    ]
    if not computed:
        return {}
    declarations = None
    changes = {}
    for test in computed:
        base = matched.get(test.id)
        if base is None or not base.parametrized:
            continue
        try:
            if declarations is None:
                declarations = _Declarations(comparison, "Parametrize")
            reason = _computed_case_change(comparison, declarations, base, test)
        except DoneError as exc:
            reason = f"its case sources could not be inspected ({exc})"
        if reason:
            changes[test.id] = reason
    return changes


def _computed_case_change(
    comparison: Comparison,
    declarations: _Declarations,
    base: TestItem,
    test: TestItem,
) -> str | None:
    base_tree, _ = declarations.module(base.path, True)
    head_tree, _ = declarations.module(test.path, False)
    before = _parametrize_context(base_tree, base.classes, base.name)
    after = _parametrize_context(head_tree, test.classes, test.name)
    if before is None or after is None:
        return "its parametrize setup could not be located"
    if [ast.dump(n) for n in before] != [ast.dump(n) for n in after]:
        return "this change edits its parametrize decorators or class attributes"
    pending = []
    declarations.add_references(
        base.path,
        {reference for node in before for reference in _global_references(node)},
        pending,
    )
    visited = list(before)
    change = declarations.first_change(pending, visited)
    if change:
        path, line, symbol = change
        where = f"{path}:{line}" if line else path
        return f"this change edits {symbol} ({where}), which builds them"
    if not _case_sources_closed(before, visited, declarations):
        changed = _changed_case_file(comparison, include_python=True)
        if changed:
            return (
                f"this change edits a tracked input ({changed}), whose use by "
                "the opaque case source cannot be ruled out"
            )
    return None


def _parametrize_context(tree, classes, name) -> list[ast.AST] | None:
    """What decides a test's parametrize cases outside its own body."""
    nodes: list[ast.AST] = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "pytestmark"
            for target in node.targets
        )
    ]
    body = tree.body
    for class_name in classes:
        found = [
            n for n in body if isinstance(n, ast.ClassDef) and n.name == class_name
        ]
        if not found:
            return None
        cls = found[-1]
        nodes += cls.decorator_list
        nodes += [
            child
            for child in cls.body
            if not isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            )
            and not (
                isinstance(child, ast.Expr) and isinstance(child.value, ast.Constant)
            )
        ]
        body = cls.body
    functions = [
        n
        for n in body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name
    ]
    if not functions:
        return None
    return nodes + functions[-1].decorator_list


def _case_sources_closed(context, visited, declarations) -> bool:
    """Positive, deliberately small proof that case construction performs no I/O.

    Arbitrary calls, attributes, local imports, classes, reflection and complex
    control flow are opaque. A negative result never excludes any file type.
    This proves input independence only; declaration/mutation comparisons still
    decide whether the construction itself changed.
    """
    nodes = [*context, *visited]
    functions = {
        node.name: node
        for node in nodes
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    variables = {
        target.id
        for node in nodes
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
        if isinstance(target, ast.Name)
    }
    calls = {"list", "tuple", "range", *functions}
    imported_names = set()
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "pytest":
                    continue
                if declarations.local_path("", alias.name) is None:
                    return False
                imported_names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module == "pytest":
                continue
            target = declarations.local_path("", node.module or "", node.level)
            for alias in node.names:
                child = declarations.local_path(
                    "",
                    ".".join(part for part in (node.module, alias.name) if part),
                    node.level,
                )
                if target is None and child is None:
                    return False
                if alias.name in functions:
                    calls.add(alias.asname or alias.name)
                imported_names.add(alias.asname or alias.name)
    names = variables | calls | imported_names

    def expression(node, locals=frozenset(), depth=0):
        if node is None or depth > 24:
            return False
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.Name):
            return isinstance(node.ctx, ast.Load) and node.id in names | locals
        if isinstance(node, (ast.List, ast.Tuple)):
            return all(expression(item, locals, depth + 1) for item in node.elts)
        if isinstance(node, ast.UnaryOp):
            return expression(node.operand, locals, depth + 1)
        if isinstance(node, ast.BinOp):
            return expression(node.left, locals, depth + 1) and expression(
                node.right, locals, depth + 1
            )
        if isinstance(node, ast.Call):
            if (
                not isinstance(node.func, ast.Name)
                or node.func.id not in calls
                or node.func.id in locals
            ):
                return False
            return all(expression(arg, locals, depth + 1) for arg in node.args) and all(
                keyword.arg is not None and expression(keyword.value, locals, depth + 1)
                for keyword in node.keywords
            )
        return False

    def marker_expression(node):
        parts = _dotted(node.func) if isinstance(node, ast.Call) else ()
        if parts[-1:] == ("parametrize",) and "mark" in parts:
            values = (
                node.args[1]
                if len(node.args) >= 2
                else next(
                    (k.value for k in node.keywords if k.arg == "argvalues"), None
                )
            )
            return expression(values)
        return False

    initializing = set()

    def initialization_closed(path, base):
        if (path, base) in initializing:
            return True
        initializing.add((path, base))
        tree, _ = declarations.module(path, base)

        def statements_closed(body):
            for statement in body:
                if isinstance(statement, (ast.Import, ast.ImportFrom)):
                    imports = (
                        [(alias.name, 0) for alias in statement.names]
                        if isinstance(statement, ast.Import)
                        else [(statement.module or "", statement.level)]
                    )
                    for module_name, level in imports:
                        target = declarations.local_path(
                            path, module_name, level, base=base
                        )
                        if target:
                            # The same repository module must have a closed
                            # initializer in both snapshots, including siblings.
                            if (
                                target not in declarations.paths
                                or target not in declarations.head_paths
                            ):
                                return False
                            if not initialization_closed(
                                target, True
                            ) or not initialization_closed(target, False):
                                return False
                        elif module_name.split(".")[0] not in {
                            "pytest",
                            *sys.stdlib_module_names,
                        }:
                            return False
                elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    effects = list(_definition_time_nodes(statement))
                    if any(
                        not marker_expression(effect) and not expression(effect)
                        for effect in effects
                    ):
                        return False
                elif isinstance(statement, ast.ClassDef):
                    if (
                        statement.bases
                        or statement.keywords
                        or statement.decorator_list
                    ):
                        return False
                    if not statements_closed(statement.body):
                        return False
                elif isinstance(statement, (ast.Assign, ast.AnnAssign)):
                    targets = (
                        statement.targets
                        if isinstance(statement, ast.Assign)
                        else [statement.target]
                    )
                    if not all(isinstance(target, ast.Name) for target in targets):
                        return False
                    if not expression(statement.value):
                        return False
                elif isinstance(statement, ast.Expr) and isinstance(
                    statement.value, ast.Constant
                ):
                    continue
                else:
                    return False
            return True

        return statements_closed(tree.body)

    # Cached modules are those reached by the declaration proof. Parent package
    # initializers execute too, even when they do not define the referenced name.
    reached = {path for path, _ in declarations._cache}
    for path in list(reached):
        parts = PurePosixPath(path).parts
        for size in range(1, len(parts)):
            parent = str(PurePosixPath(*parts[:size], "__init__.py"))
            if parent in declarations.paths or parent in declarations.head_paths:
                reached.add(parent)
    for path in reached:
        if path not in declarations.paths or path not in declarations.head_paths:
            return False
        if not initialization_closed(path, True) or not initialization_closed(
            path, False
        ):
            return False

    for node in nodes:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.decorator_list or isinstance(node, ast.AsyncFunctionDef):
                return False
            local_names = {
                arg.arg
                for arg in (
                    *node.args.posonlyargs,
                    *node.args.args,
                    *node.args.kwonlyargs,
                )
            }
            if node.args.vararg or node.args.kwarg:
                return False
            for statement in node.body:
                if isinstance(statement, ast.Expr) and isinstance(
                    statement.value, ast.Constant
                ):
                    continue
                if isinstance(statement, ast.Return):
                    if not expression(statement.value, frozenset(local_names)):
                        return False
                elif isinstance(statement, ast.Assign) and all(
                    isinstance(t, ast.Name) for t in statement.targets
                ):
                    if not expression(statement.value, frozenset(local_names)):
                        return False
                    local_names.update(t.id for t in statement.targets)
                else:
                    return False
            if not all(
                expression(value)
                for value in [
                    *node.args.defaults,
                    *(v for v in node.args.kw_defaults if v is not None),
                ]
            ):
                return False
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets
            ):
                marks = (
                    node.value.elts
                    if isinstance(node.value, (ast.List, ast.Tuple))
                    else [node.value]
                )
                for mark in marks:
                    if not isinstance(mark, ast.Call) or _dotted(mark.func)[-1:] != (
                        "parametrize",
                    ):
                        return False
                    values = (
                        mark.args[1]
                        if len(mark.args) >= 2
                        else next(
                            (k.value for k in mark.keywords if k.arg == "argvalues"),
                            None,
                        )
                    )
                    if not expression(values):
                        return False
            elif not expression(node.value):
                return False
        elif isinstance(node, ast.Call) and _dotted(node.func)[-1:] == ("parametrize",):
            values = (
                node.args[1]
                if len(node.args) >= 2
                else next(
                    (k.value for k in node.keywords if k.arg == "argvalues"), None
                )
            )
            if not expression(values):
                return False
        else:
            return False
    return True


def _changed_case_file(comparison: Comparison, *, include_python: bool) -> str | None:
    """Tracked-input fallback when case-reader paths or behavior are opaque."""
    for item in comparison.changed:
        paths = (item.path, item.base_path or item.path)
        if include_python or any(not path.endswith(".py") for path in paths):
            return item.base_path or item.path
    return None


def _captured_names(node) -> set[str]:
    names = set()
    for child in ast.walk(node):
        if isinstance(child, (ast.MatchAs, ast.MatchStar)) and child.name:
            names.add(child.name)
        elif isinstance(child, ast.MatchMapping) and child.rest:
            names.add(child.rest)
    return names


def _alias_groups(body):
    """Conservative shared-object provenance for executed module bindings."""
    groups = []
    for statement in body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for node in ast.walk(statement):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                targets = (
                    node.targets if isinstance(node, ast.Assign) else [node.target]
                )
                source = node.value
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                targets, source = [node.target], node.iter
            elif isinstance(node, ast.Match):
                targets, source = [case.pattern for case in node.cases], node.subject
            else:
                continue
            expressions = [*targets, source]
            called_names = {
                id(child.func)
                for expression in expressions
                if expression is not None
                for child in ast.walk(expression)
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Name)
            }
            names = {
                child.id
                for expression in expressions
                if expression is not None
                for child in ast.walk(expression)
                if isinstance(child, ast.Name) and id(child) not in called_names
            }
            for target in targets:
                if target is not None:
                    names |= _captured_names(target)
            if len(names) > 1:
                groups.append(names)
    return groups


def _mutation_sources(names, groups):
    """Propagate mutation through aliases without quadratic fixed-point scans."""
    by_name = {}
    for index, group in enumerate(groups):
        for name in group:
            by_name.setdefault(name, []).append(index)
    pending = list(names)
    visited = set()
    while pending:
        name = pending.pop()
        for index in by_name.get(name, ()):
            if index in visited:
                continue
            visited.add(index)
            additions = groups[index] - names
            names.update(additions)
            pending.extend(additions)
    return names


def _definition_time_nodes(node):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        yield from node.decorator_list
        yield from node.args.defaults
        yield from (value for value in node.args.kw_defaults if value is not None)
        yield from (
            arg.annotation
            for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
            if arg.annotation is not None
        )
        if node.returns is not None:
            yield node.returns
    elif isinstance(node, ast.ClassDef):
        yield from node.decorator_list
        yield from node.bases
        yield from (keyword.value for keyword in node.keywords)
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                yield from _definition_time_nodes(child)
            else:
                yield child
    else:
        yield node


def _module_bindings(tree):
    bindings = {}
    for node in tree.body:
        names = set()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Import):
            names.update(
                alias.asname or alias.name.split(".")[0] for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom):
            names.update(alias.asname or alias.name for alias in node.names)
        else:
            names.update(
                child.id
                for child in ast.walk(node)
                if isinstance(child, ast.Name)
                and isinstance(child.ctx, (ast.Store, ast.Del))
            )
            names.update(_captured_names(node))
            if isinstance(node, ast.Expr):
                names.update(name for name, _ in _global_references(node))
        for name in names:
            bindings.setdefault(name, []).append(node)
    # A statement can also change a module value it never assigns: mutate it
    # (``if CI: VALUES.remove(2)``, ``VALUES[2:] = []``) or pass it to a call,
    # including a local function that runs while the module loads.
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    execution = [
        effect for node in tree.body for effect in _definition_time_nodes(node)
    ]
    groups = _alias_groups(execution)
    builtin_aliases = {"builtins", "__builtins__"}
    for imported in ast.walk(tree):
        if isinstance(imported, ast.Import):
            builtin_aliases.update(
                alias.asname or alias.name
                for alias in imported.names
                if alias.name == "builtins"
            )
    call_aliases = {
        name
        for name, nodes in bindings.items()
        if any(isinstance(node, (ast.Assign, ast.AnnAssign)) for node in nodes)
    }
    for node in execution:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        # Registering the expected pytest marker is not a mutation of argvalues.
        if (
            isinstance(node, ast.Call)
            and _dotted(node.func)[-1:] == ("parametrize",)
            and "mark" in _dotted(node.func)
        ):
            continue
        mutated = _mutation_sources(
            _mutated_names(node, functions, call_aliases), groups
        )
        reflective = any(
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Name)
            and child.func.id
            in {
                "globals",
                "locals",
                "vars",
                "eval",
                "exec",
                "__import__",
                "setattr",
                "delattr",
            }
            for child in ast.walk(node)
        )
        if reflective:
            mutated.update(bindings)
        if reflective or mutated & builtin_aliases:
            for builtin in {"range", "list", "tuple"}:
                bindings.setdefault(builtin, []).append(node)
        for name in sorted(mutated & bindings.keys()):
            if not any(existing is node for existing in bindings[name]):
                bindings[name].append(node)
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            globals_in_class = {
                name
                for child in node.body
                if isinstance(child, ast.Global)
                for name in child.names
            }
            for child in _definition_time_nodes(node):
                written = {
                    descendant.id
                    for descendant in ast.walk(child)
                    if isinstance(descendant, ast.Name)
                    and isinstance(descendant.ctx, (ast.Store, ast.Del))
                }
                for name in written & globals_in_class & bindings.keys():
                    if not any(existing is child for existing in bindings[name]):
                        bindings[name].append(child)
    return bindings


def _mutated_names(node, functions, call_aliases=()) -> set[str]:
    names = set()
    for child in ast.walk(node):
        if isinstance(child, ast.NamedExpr) and isinstance(child.target, ast.Name):
            names.add(child.target.id)
        if isinstance(child, (ast.Attribute, ast.Subscript)) and isinstance(
            child.ctx, (ast.Store, ast.Del)
        ):
            names.add(_root_name(child))
        elif isinstance(child, ast.Call):
            if isinstance(child.func, (ast.Attribute, ast.Subscript)):
                names.update(
                    n.id for n in ast.walk(child.func) if isinstance(n, ast.Name)
                )
            elif isinstance(child.func, ast.Name) and child.func.id in call_aliases:
                names.add(child.func.id)
            if isinstance(child.func, ast.Name) and child.func.id in functions:
                names.update(
                    name for name, _ in _global_references(functions[child.func.id])
                )
            for argument in [*child.args, *(k.value for k in child.keywords)]:
                names.update(
                    n.id for n in ast.walk(argument) if isinstance(n, ast.Name)
                )
    names.discard(None)
    return names


def _root_name(node) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _import_binding(node, name):
    if isinstance(node, ast.Import):
        for alias in node.names:
            if (alias.asname or alias.name.split(".")[0]) == name:
                return (
                    alias.name if alias.asname else alias.name.split(".")[0],
                    None,
                    0,
                )
    elif isinstance(node, ast.ImportFrom):
        for alias in node.names:
            if (alias.asname or alias.name) == name:
                return (node.module or "", alias.name, node.level)
    return None


def _global_references(node):
    local = set()
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        local.update(
            arg.arg
            for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
        )
        local.update(arg.arg for arg in (node.args.vararg, node.args.kwarg) if arg)
        local.update(
            child.id
            for child in ast.walk(node)
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)
        )
        for child in ast.walk(node):
            if isinstance(child, ast.Global):
                local.difference_update(child.names)
    references = set()
    attributes = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Attribute) and isinstance(child.ctx, ast.Load):
            parts = _dotted(child)
            if parts and parts[0] not in local:
                references.add((parts[0], parts[1:]))
                attributes.update(
                    id(descendant)
                    for descendant in ast.walk(child)
                    if isinstance(descendant, ast.Name)
                )
    for child in ast.walk(node):
        if (
            isinstance(child, ast.Name)
            and isinstance(child.ctx, ast.Load)
            and child.id not in local
            and id(child) not in attributes
        ):
            references.add((child.id, ()))
    return references


def _assigned_strings(tree: ast.Module, name: str) -> set[str]:
    """String literals assigned, appended or added to a module-level name."""
    values: set[str] = set()
    for node in ast.walk(tree):
        target_value = None
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ):
            target_value = node.value
        elif (
            isinstance(node, (ast.AugAssign, ast.AnnAssign))
            and isinstance(node.target, ast.Name)
            and node.target.id == name
        ):
            target_value = node.value
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == name
            and node.func.attr in {"append", "extend", "insert", "add"}
        ):
            target_value = ast.Tuple(elts=list(node.args), ctx=ast.Load())
        if target_value is not None:
            for child in ast.walk(target_value):
                if isinstance(child, ast.Constant) and isinstance(child.value, str):
                    values.add(child.value)
    return values


# ---------------------------------------------------------------------------
# CI workflows
# ---------------------------------------------------------------------------


def _workflow(path: str, base: str | None, head: str) -> list[ConfigFinding]:
    head_steps = _quiet_test_steps(head)
    if not head_steps:
        return []
    base_steps = _quiet_test_steps(base) if base else {}
    base_runs = _test_step_runs(base) if base else {}
    base_named = set(_test_step_runs(base, tests_only=False)) if base else set()
    head_runs = _test_step_runs(head)
    findings = []
    for key, how in sorted(head_steps.items()):
        new = how - base_steps.get(key, set())
        if not new:
            continue
        if key not in base_named and _added_step(key, base_runs, head_runs):
            continue  # a new advisory step, not an existing check loosened
        job, step = key
        needle = "continue-on-error" if "continue-on-error" in new else None
        line = _line_of(head, needle) if needle else _first_swallow_line(head)
        label = f"step {step!r} in job {job!r}" if step else f"job {job!r}"
        findings.append(
            ConfigFinding(
                path,
                line,
                f"CI test {label} can now fail without failing the build ({', '.join(sorted(new))})",
            )
        )
    return findings


def _added_step(key, base_runs: dict, head_runs: dict) -> bool:
    """A test step (or job) the base did not have: its commands are new, and
    every test step the base job ran still runs. (The caller has checked
    that no step or job of that name existed at the base.)"""
    if key in base_runs:
        return False
    commands = head_runs.get(key, set())
    if not commands or any(commands & runs for runs in base_runs.values()):
        return False
    job = key[0]
    still_there = set().union(*head_runs.values()) if head_runs else set()
    return all(
        other in head_runs or runs <= still_there
        for other, runs in base_runs.items()
        if other[0] == job
    )


def _test_step_runs(
    text: str | None, *, tests_only: bool = True
) -> dict[tuple[str, str], set[str]]:
    """Each test step (and each job with test steps, under step "") to the
    commands it runs, whitespace collapsed; every step that runs a command
    when ``tests_only`` is False."""
    try:
        data = yaml.safe_load(text or "")
    except yaml.YAMLError:
        return {}
    if not isinstance(data, dict) or not isinstance(data.get("jobs"), dict):
        return {}
    runs: dict[tuple[str, str], set[str]] = {}
    for job_id, job in data["jobs"].items():
        steps = job.get("steps") if isinstance(job, dict) else None
        for step in steps if isinstance(steps, list) else ():
            if not (
                isinstance(step, dict)
                and isinstance(step.get("run"), str)
                and (not tests_only or _TEST_STEP_RE.search(step["run"]))
            ):
                continue
            command = " ".join(step["run"].split())
            name = str(step.get("name") or step["run"].strip().splitlines()[0])[:80]
            runs.setdefault((str(job_id), name), set()).add(command)
            runs.setdefault((str(job_id), ""), set()).add(command)
    return runs


def _quiet_test_steps(text: str | None) -> dict[tuple[str, str], set[str]]:
    from skylos.done.ci_checks import test_failure_swallowed

    try:
        data = yaml.safe_load(text or "")
    except yaml.YAMLError:
        return {}
    if not isinstance(data, dict) or not isinstance(data.get("jobs"), dict):
        return {}
    quiet: dict[tuple[str, str], set[str]] = {}
    for job_id, job in data["jobs"].items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps") if isinstance(job.get("steps"), list) else []
        test_steps = [
            step
            for step in steps
            if isinstance(step, dict)
            and isinstance(step.get("run"), str)
            and _TEST_STEP_RE.search(step["run"])
        ]
        if not test_steps:
            continue
        if _literal_true(job.get("continue-on-error")):
            quiet.setdefault((str(job_id), ""), set()).add("continue-on-error")
        for step in test_steps:
            key = (
                str(job_id),
                str(step.get("name") or step["run"].strip().splitlines()[0])[:80],
            )
            reasons = set()
            if _literal_true(step.get("continue-on-error")):
                reasons.add("continue-on-error")
            if test_failure_swallowed(step["run"]):
                reasons.add("failure swallowed in the script")
            if reasons:
                quiet.setdefault(key, set()).update(reasons)
    return quiet


def _literal_true(value) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def _first_swallow_line(text: str) -> int | None:
    for index, line in enumerate(text.splitlines(), 1):
        if _SWALLOW_RE.search(line):
            return index
    return None


def _line_of(text: str | None, needle: str | None) -> int | None:
    if not text or not needle:
        return None
    for index, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return index
    return None
