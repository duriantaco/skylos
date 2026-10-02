"""SKY-A112: test settings loosened by the change.

A change can make failing tests "pass" without touching a test: select fewer
tests in pytest options, ignore directories, add a conftest.py hook that
drops tests or rewrites their outcomes (JUnit XML then reports the rewritten
outcome too), lower a coverage floor, or let a CI test step fail quietly.
Each loosening the change adds is one finding.
"""

from __future__ import annotations

import ast
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
        if name == "pyproject.toml":
            findings += _pyproject(head_path, base, head, local)
        if name in _INI_FILES:
            base_options = (
                _base_pytest_options(comparison)
                if base is None and head_path in {"pytest.ini", ".pytest.ini"}
                else None
            )
            findings += _pytest_ini(
                head_path, base, head, _INI_FILES[name], local, base_options
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
    return findings


def _is_workflow(path: str) -> bool:
    return path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))


# ---------------------------------------------------------------------------
# pytest options
# ---------------------------------------------------------------------------


def _pyproject(
    path: str, base: str | None, head: str, local: LocalModule
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
    )
    findings += _compare_coverage(
        path,
        head,
        _toml_coverage(base_data),
        _toml_coverage(head_data),
    )
    return findings


def _pytest_ini(
    path, base, head, sections, local: LocalModule, base_options: dict | None = None
) -> list[ConfigFinding]:
    return _compare_pytest_options(
        path,
        head,
        _ini_options(base, sections) if base_options is None else base_options,
        _ini_options(head, sections),
        local,
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
    path, head_text, base: dict, head: dict, local: LocalModule
) -> list[ConfigFinding]:
    findings = []
    line = _line_of(head_text, "addopts")
    base_pairs = _option_pairs(base.get("addopts", []))
    for flag, value in sorted(_option_pairs(head.get("addopts", [])) - base_pairs):
        what = None
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
    if head_paths and (not base_paths or removed_paths):
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
    paths_text = _git_text(
        comparison._context, "ls-tree", "-r", "--name-only", "-z", comparison.base_sha
    )
    if paths_text is None:
        raise DoneError("Cannot read the baseline pytest hook inventory")
    paths = set(paths_text.split("\0"))
    roots = {path for path in paths if PurePosixPath(path).name == "conftest.py"}
    cache = {}

    def module(path, base):
        key = (path, base)
        if key not in cache:
            if len(cache) >= 256:
                raise DoneError(
                    "Pytest hook dependencies exceed the static proof limit"
                )
            text = comparison.base_text(path) if base else comparison.head_text(path)
            try:
                tree = ast.parse(text) if text is not None else None
            except (SyntaxError, ValueError):
                tree = None
            if tree is None:
                raise DoneError(f"Cannot inspect pytest hook dependency {path}")
            cache[key] = (tree, _module_bindings(tree))
        return cache[key]

    def local_path(source, module_name, level=0):
        if level:
            prefix = PurePosixPath(source).parent.parts
            prefix = prefix[: len(prefix) - level + 1]
            parts = (*prefix, *module_name.split(".")) if module_name else prefix
        else:
            parts = tuple(module_name.split("."))
        stem = "/".join(parts)
        for candidate in (
            f"{stem}.py",
            f"{stem}/__init__.py",
            f"src/{stem}.py",
            f"src/{stem}/__init__.py",
        ):
            if candidate in paths:
                return candidate
        return None

    # Existing local pytest plugins are registered hook containers too.
    pending_roots = list(roots)
    options = _base_pytest_options(comparison)
    for flag, value in _option_pairs(options.get("addopts", [])):
        if flag == "-p" and not value.startswith("no:"):
            plugin = local_path("conftest.py", value)
            if plugin:
                pending_roots.append(plugin)
    inspected = set()
    while pending_roots:
        path = pending_roots.pop()
        if path in inspected:
            continue
        inspected.add(path)
        tree, _ = module(path, True)
        for plugin_name in _assigned_strings(tree, "pytest_plugins"):
            plugin = local_path(path, plugin_name)
            if plugin:
                roots.add(plugin)
                pending_roots.append(plugin)
        roots.add(path)

    findings = []
    for root in sorted(roots):
        _, bindings = module(root, True)
        for hook in sorted(OUTCOME_HOOKS & bindings.keys()):
            seen = set()
            pending = [(root, hook, ())]
            while pending:
                path, symbol, attributes = pending.pop()
                if (path, symbol, attributes) in seen:
                    continue
                seen.add((path, symbol, attributes))
                if len(seen) > 512:
                    raise DoneError(
                        "Pytest hook dependencies exceed the static proof limit"
                    )
                _, before = module(path, True)
                _, after = module(path, False)
                base_nodes = before.get(symbol, [])
                head_nodes = after.get(symbol, [])
                if [ast.dump(n) for n in base_nodes] != [
                    ast.dump(n) for n in head_nodes
                ]:
                    line = head_nodes[0].lineno if head_nodes else None
                    findings.append(
                        ConfigFinding(
                            path,
                            line,
                            f"changes {symbol}, a dependency of the pytest hook {hook}; its test selection or reported outcomes are no longer verified against the base",
                        )
                    )
                    break
                for node in base_nodes:
                    imported = _import_binding(node, symbol)
                    if imported:
                        module_name, imported_symbol, level = imported
                        target = local_path(path, module_name, level)
                        if target:
                            if imported_symbol:
                                _, target_bindings = module(target, True)
                                submodule = local_path(
                                    path,
                                    ".".join(
                                        part
                                        for part in (module_name, imported_symbol)
                                        if part
                                    ),
                                    level,
                                )
                                if imported_symbol not in target_bindings and submodule:
                                    if attributes:
                                        pending.append(
                                            (submodule, attributes[0], attributes[1:])
                                        )
                                    else:
                                        _, submodule_bindings = module(submodule, True)
                                        pending.extend(
                                            (submodule, name, ())
                                            for name in submodule_bindings
                                        )
                                else:
                                    pending.append(
                                        (target, imported_symbol, attributes)
                                    )
                            elif attributes:
                                # ``import package.helper`` binds ``package``;
                                # resolve a referenced submodule before its symbol.
                                target_module = local_path(
                                    path,
                                    ".".join((module_name, *attributes[:-1])),
                                    level,
                                )
                                pending.append(
                                    (
                                        target_module or target,
                                        attributes[-1]
                                        if target_module
                                        else attributes[0],
                                        (),
                                    )
                                )
                            else:
                                _, target_bindings = module(target, True)
                                pending.extend(
                                    (target, name, ()) for name in target_bindings
                                )
                    else:
                        for name, attrs in _global_references(node):
                            if name in before and name != symbol:
                                pending.append((path, name, attrs))
    return findings


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
            if isinstance(node, ast.Expr):
                names.update(name for name, _ in _global_references(node))
        for name in names:
            bindings.setdefault(name, []).append(node)
    return bindings


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
    findings = []
    for key, how in sorted(head_steps.items()):
        new = how - base_steps.get(key, set())
        if not new:
            continue
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


def _quiet_test_steps(text: str | None) -> dict[tuple[str, str], set[str]]:
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
            if _SWALLOW_RE.search(step["run"]):
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
