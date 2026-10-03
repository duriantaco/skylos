"""Static inventory of Python tests, and what changed between two of them.

Collected without importing anything: pytest functions and ``Test*`` class
methods in pytest-style test files, and ``test*`` methods of
``unittest.TestCase`` subclasses in any file. Each test records a hash of its
body (so a moved or renamed test is not a deletion), the skip and xfail
markers that apply to it, and how many literal parametrize cases it has.
"""

from __future__ import annotations

import ast
import difflib
import hashlib
from dataclasses import dataclass, field
from pathlib import PurePosixPath

# Two tests are the same test, renamed and edited, above this similarity.
RENAME_SIMILARITY = 0.6

_SKIP_DECORATORS = {
    "skip": "skip",
    "skipif": "skipif",
    "xfail": "xfail",
    "skipIf": "skipif",
    "skipUnless": "skipif",
    "expectedFailure": "xfail",
}
_SKIP_CALLS = {
    ("pytest", "skip"): "pytest.skip()",
    ("pytest", "xfail"): "pytest.xfail()",
    ("pytest", "importorskip"): "pytest.importorskip()",
    ("self", "skipTest"): "self.skipTest()",
    ("cls", "skipTest"): "self.skipTest()",
}
_SKIP_EXCEPTIONS = {"SkipTest", "Skipped"}


@dataclass(frozen=True)
class TestItem:
    path: str
    classes: tuple[str, ...]
    name: str
    line: int
    body_hash: str
    body_dump: str = field(repr=False, compare=False)
    markers: frozenset[str] = frozenset()
    param_cases: int | None = None  # None unless every case list is literal
    end_line: int = 0
    unittest_style: bool = False
    parametrized: bool = False

    @property
    def id(self) -> str:
        return "::".join((self.path, *self.classes, self.name))

    @property
    def local_id(self) -> str:
        return "::".join((*self.classes, self.name))

    @property
    def skipped(self) -> bool:
        return bool(self.markers)


def is_pytest_file(path: str) -> bool:
    name = PurePosixPath(path).name
    return name.endswith(".py") and (
        name.startswith("test_") or name.endswith("_test.py")
    )


def collect_tests(
    path: str, source: str | None, *, strict: bool = False
) -> list[TestItem]:
    """Tests defined in one Python file (empty when it is not one)."""
    if source is None or not path.endswith(".py"):
        if strict and source is None:
            raise ValueError("test source is unreadable or over the source-size limit")
        return []
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError):
        if strict:
            raise ValueError("test source is not valid Python") from None
        return []
    collector = _Collector(path, pytest_style=is_pytest_file(path))
    collector.collect_module(tree)
    return collector.items


def imported_modules(source: str | None) -> set[str]:
    """Dotted names a file imports (absolute imports only)."""
    if not source:
        return set()
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names.add(node.module)
    return names


# ---------------------------------------------------------------------------
# Comparing two inventories
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeletedTest:
    test: TestItem


@dataclass(frozen=True)
class NewlySkipped:
    test: TestItem
    added: frozenset[str]


@dataclass(frozen=True)
class DroppedCases:
    test: TestItem
    before: int
    after: int


@dataclass
class InventoryDiff:
    deleted: list[DeletedTest] = field(default_factory=list)
    newly_skipped: list[NewlySkipped] = field(default_factory=list)
    dropped_cases: list[DroppedCases] = field(default_factory=list)
    matched: dict[str, TestItem] = field(default_factory=dict)


def compare_inventories(
    base: list[TestItem],
    head: list[TestItem],
    renamed_paths: dict[str, str] | None = None,
) -> InventoryDiff:
    """Tests that existed at the base and are gone, skipped or thinned at head.

    ``renamed_paths`` maps base paths to head paths for renamed files. Tests
    written after the base are not considered: they can change freely.
    """
    renamed_paths = renamed_paths or {}
    head_by_id = {item.id: item for item in head}
    mapped_base_ids = {_moved_id(item, renamed_paths) for item in base}
    # Head tests that are new in this change: candidates for "renamed and edited".
    unmatched_new = {item.id: item for item in head if item.id not in mapped_base_ids}

    result = InventoryDiff()
    for test in base:
        current = head_by_id.get(_moved_id(test, renamed_paths))
        if current is None:
            # Match a particular survivor, once: body identity does not prove
            # its decorators or parameter cases were preserved.
            match = next(
                (
                    item
                    for item in unmatched_new.values()
                    if item.body_hash == test.body_hash
                ),
                None,
            )
            if match is None:
                match = _renamed_and_edited(test, unmatched_new, renamed_paths)
            if match is not None:
                unmatched_new.pop(match.id, None)
                current = match
            else:
                result.deleted.append(DeletedTest(test))
                continue
        result.matched[current.id] = test
        added = current.markers - test.markers
        if added:
            result.newly_skipped.append(NewlySkipped(current, frozenset(added)))
        current_cases = current.param_cases if current.parametrized else 1
        if (
            test.param_cases is not None
            and current_cases is not None
            and current_cases < test.param_cases
        ):
            result.dropped_cases.append(
                DroppedCases(current, test.param_cases, current_cases)
            )
    return result


def _moved_id(item: TestItem, renamed: dict[str, str], *, reverse: bool = False) -> str:
    mapping = {v: k for k, v in renamed.items()} if reverse else renamed
    return "::".join((mapping.get(item.path, item.path), *item.classes, item.name))


def _renamed_and_edited(
    test: TestItem, candidates: dict[str, TestItem], renamed: dict[str, str]
) -> TestItem | None:
    target_path = renamed.get(test.path, test.path)
    best: tuple[float, TestItem] | None = None
    for item in candidates.values():
        if item.path != target_path or item.classes != test.classes:
            continue
        ratio = difflib.SequenceMatcher(
            None, test.body_dump, item.body_dump, autojunk=False
        ).ratio()
        if ratio >= RENAME_SIMILARITY and (best is None or ratio > best[0]):
            best = (ratio, item)
    return best[1] if best else None


# ---------------------------------------------------------------------------
# AST collection
# ---------------------------------------------------------------------------


class _Collector:
    def __init__(self, path: str, *, pytest_style: bool) -> None:
        self.path = path
        self.pytest_style = pytest_style
        self.items: list[TestItem] = []
        self.testcase_classes: set[str] = set()

    def collect_module(self, tree: ast.Module) -> None:
        self.aliases = _import_aliases(tree.body)
        self.literal_cases = _literal_case_values(tree, self.aliases)
        module_markers = _module_markers(tree, self.aliases)
        module_params = _param_settings(
            _assigned_pytest_marks(tree.body), self.aliases, self.literal_cases
        )
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if self.pytest_style and node.name.startswith("test"):
                    self._add(node, (), module_markers, inherited_params=module_params)
            elif isinstance(node, ast.ClassDef):
                self._collect_class(node, (), module_markers, module_params)

    def _collect_class(
        self,
        node: ast.ClassDef,
        outer: tuple[str, ...],
        inherited: frozenset[str],
        inherited_params=(False, None),
    ) -> None:
        is_testcase = _is_testcase_class(node, self.testcase_classes, self.aliases)
        if is_testcase:
            self.testcase_classes.add(node.name)
        is_pytest_class = (
            self.pytest_style
            and node.name.startswith("Test")
            and not _defines_init(node)
        )
        if not (is_testcase or is_pytest_class):
            return
        markers = (
            inherited
            | _decorator_markers(node.decorator_list, self.aliases)
            | _class_markers(node, self.aliases)
        )
        classes = (*outer, node.name)
        params = _combine_params(
            inherited_params,
            _param_settings(
                [*node.decorator_list, *_assigned_pytest_marks(node.body)],
                self.aliases,
                self.literal_cases,
            ),
        )
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if child.name.startswith("test"):
                    self._add(
                        child,
                        classes,
                        markers,
                        unittest_style=is_testcase,
                        inherited_params=params,
                    )
            elif isinstance(child, ast.ClassDef) and self.pytest_style:
                self._collect_class(child, classes, markers, params)

    def _add(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        classes: tuple[str, ...],
        inherited: frozenset[str],
        *,
        unittest_style: bool = False,
        inherited_params=(False, None),
    ) -> None:
        dump = "\n".join(ast.dump(stmt) for stmt in node.body)
        aliases = dict(self.aliases)
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Name)
                and isinstance(child.ctx, ast.Store)
                and child.id in aliases
            ):
                aliases[child.id] = ()
            elif isinstance(child, ast.arg) and child.arg in aliases:
                aliases[child.arg] = ()
        aliases.update(_import_aliases(ast.walk(node)))
        parametrized, param_cases = _combine_params(
            inherited_params,
            _param_settings(node.decorator_list, self.aliases, self.literal_cases),
        )
        if unittest_style:
            # pytest parametrization does not expand unittest.TestCase methods.
            parametrized, param_cases = False, None
        markers = (
            inherited
            | _decorator_markers(node.decorator_list, self.aliases)
            | _body_markers(node, aliases)
        )
        self.items.append(
            TestItem(
                path=self.path,
                classes=classes,
                name=node.name,
                line=node.lineno,
                body_hash=hashlib.sha256(dump.encode("utf-8")).hexdigest(),
                body_dump=dump,
                markers=frozenset(markers),
                param_cases=param_cases,
                end_line=node.end_lineno or node.lineno,
                unittest_style=unittest_style,
                parametrized=parametrized,
            )
        )


def _import_aliases(nodes) -> dict[str, tuple[str, ...]]:
    aliases = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = tuple(
                    alias.name.split(".") if alias.asname else alias.name.split(".")[:1]
                )
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = (
                        *node.module.split("."),
                        alias.name,
                    )
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    aliases[target.id] = ()
    return aliases


def _dotted(node: ast.AST, aliases=None) -> tuple[str, ...]:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        parts.reverse()
        if aliases is not None and parts[0] in aliases:
            root = aliases[parts[0]]
            return (*root, *parts[1:]) if root else ()
        return tuple(parts)
    return ()


def _decorator_name(node: ast.expr, aliases=None) -> tuple[str, ...]:
    return _dotted(node.func if isinstance(node, ast.Call) else node, aliases)


def _marker_from_expr(node: ast.expr, aliases=None) -> str | None:
    """``pytest.mark.skip``/``unittest.skip``-style expression to a marker."""
    name = _decorator_name(node, aliases)
    if not name:
        return None
    last = name[-1]
    if last not in _SKIP_DECORATORS:
        return None
    # skip/skipif/xfail must come from pytest.mark (or a bare ``mark``);
    # skipIf/skipUnless/expectedFailure/skip from unittest.
    if last in {"skipif", "xfail"} and "mark" not in name:
        return None
    if last == "skip" and not ("mark" in name or name[0] in {"unittest", "skip"}):
        return None
    return _SKIP_DECORATORS[last]


def _decorator_markers(decorators: list[ast.expr], aliases=None) -> set[str]:
    markers = set()
    for decorator in decorators:
        marker = _marker_from_expr(decorator, aliases)
        if marker:
            markers.add(marker)
    return markers


def _pytestmark_markers(value: ast.expr, aliases=None) -> set[str]:
    items = value.elts if isinstance(value, (ast.List, ast.Tuple)) else [value]
    return {m for m in (_marker_from_expr(item, aliases) for item in items) if m}


def _module_markers(tree: ast.Module, aliases=None) -> frozenset[str]:
    markers: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets
        ):
            markers |= {f"module {m}" for m in _pytestmark_markers(node.value, aliases)}
        call = _top_level_call(node)
        if call is not None:
            name = _dotted(call.func, aliases)
            if name[-2:] == ("pytest", "skip") or name[-2:] == (
                "pytest",
                "importorskip",
            ):
                markers.add(f"module {_SKIP_CALLS[name[-2:]]}")
    return frozenset(markers)


def _top_level_call(node: ast.stmt) -> ast.Call | None:
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
        return node.value
    if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
        return node.value
    return None


def _class_markers(node: ast.ClassDef, aliases=None) -> set[str]:
    markers = set()
    for child in node.body:
        if isinstance(child, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "pytestmark" for t in child.targets
        ):
            markers |= _pytestmark_markers(child.value, aliases)
    return markers


def _body_markers(
    node: ast.FunctionDef | ast.AsyncFunctionDef, aliases=None
) -> set[str]:
    markers = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name = _dotted(child.func, aliases)
            if len(name) >= 2 and name[-2:] in _SKIP_CALLS:
                markers.add(_SKIP_CALLS[name[-2:]])
        elif isinstance(child, ast.Raise) and child.exc is not None:
            exc = child.exc.func if isinstance(child.exc, ast.Call) else child.exc
            name = _dotted(exc, aliases)
            if name and name[-1] in _SKIP_EXCEPTIONS:
                markers.add("raise SkipTest")
    return markers


def _is_testcase_class(node: ast.ClassDef, known: set[str], aliases=None) -> bool:
    for base in node.bases:
        name = _dotted(base, aliases)
        if name and (name[-1].endswith("TestCase") or name[-1] in known):
            return True
    return False


def _defines_init(node: ast.ClassDef) -> bool:
    return any(
        isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
        and child.name == "__init__"
        for child in node.body
    )


def _assigned_pytest_marks(body) -> list[ast.expr]:
    return [
        expression
        for node in body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "pytestmark"
            for target in node.targets
        )
        for expression in (
            node.value.elts
            if isinstance(node.value, (ast.List, ast.Tuple))
            else [node.value]
        )
    ]


def _combine_params(first, second) -> tuple[bool, int | None]:
    if not first[0]:
        return second
    if not second[0]:
        return first
    return True, None if first[1] is None or second[1] is None else first[1] * second[1]


def _param_settings(
    decorators: list[ast.expr], aliases=None, literal_cases=None
) -> tuple[bool, int | None]:
    """Product of literal parametrize case counts; None if any is computed."""
    total = 1
    found = False
    for decorator in decorators:
        if not isinstance(decorator, ast.Call):
            continue
        name = _decorator_name(decorator, aliases)
        if not name or name[-1] != "parametrize" or "mark" not in name:
            continue
        found = True
        values = None
        if len(decorator.args) >= 2:
            values = decorator.args[1]
        else:
            for keyword in decorator.keywords:
                if keyword.arg == "argvalues":
                    values = keyword.value
        if isinstance(values, ast.Name):
            values = (literal_cases or {}).get(values.id)
        if not isinstance(values, (ast.List, ast.Tuple)):
            return True, None
        if any(isinstance(item, ast.Starred) for item in values.elts):
            return True, None
        total *= len(values.elts)
    return found, total if found else None


def _literal_case_values(tree, aliases):
    """Simple module constants and aliases, without computed or mutated values."""
    values = {}
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = (
                values.get(node.value.id)
                if isinstance(node.value, ast.Name)
                else node.value
            )
            for target in targets:
                if isinstance(target, ast.Name):
                    values[target.id] = (
                        value if isinstance(value, (ast.List, ast.Tuple)) else None
                    )
    unsafe = set()
    writes = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    writes[target.id] = writes.get(target.id, 0) + 1
        if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            value = node.value
            if isinstance(value, ast.Name):
                unsafe.add(value.id)
        elif isinstance(node, ast.Call):
            name = _dotted(node.func, aliases)
            if name and name[-1] == "parametrize" and "mark" in name:
                continue
            # Values supplied to arbitrary calls may be modified by that call.
            unsafe.update(
                child.id
                for arg in [*node.args, *(keyword.value for keyword in node.keywords)]
                for child in ast.walk(arg)
                if isinstance(child, ast.Name) and child.id in values
            )
            raw = _dotted(node.func)
            if len(raw) > 1:
                unsafe.add(raw[0])
    unsafe.update(name for name, count in writes.items() if count > 1)
    unsafe_values = {
        id(values[name])
        for name in unsafe
        if name in values and values[name] is not None
    }
    return {
        name: value
        for name, value in values.items()
        if value is not None and id(value) not in unsafe_values
    }
