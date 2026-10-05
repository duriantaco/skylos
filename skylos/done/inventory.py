"""Static inventory of Python tests, and what changed between two of them.

Collected without importing anything: pytest functions and ``Test*`` class
methods in pytest-style test files, and ``test*`` methods of
``unittest.TestCase`` subclasses in any file. Each test records a hash of its
body (so a moved or renamed test is not a deletion), the skip and xfail
markers that apply to it, how many literal parametrize cases it has, how
many assertions it makes and the ``return`` statements that can skip them.
"""

from __future__ import annotations

import ast
import difflib
import functools
import hashlib
import operator
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

# Two tests are the same test, renamed and edited, above this similarity
# (and with similar titles).
RENAME_SIMILARITY = 0.6
# A new test standing where a deleted test stood (same file, between the same
# surviving neighbours) is that test rewritten in place when its title or
# body is at least this similar. Tests in one file share setup, so position,
# not this floor, is what pairs them; the floor rules out unrelated tests.
REWRITE_SIMILARITY = 0.35
# A new test at least this close to a test that is still there is a copy of
# that test, never the replacement of a deleted one.
COPY_SIMILARITY = 0.9
# Titles are similar when this share of their words, or of their characters,
# match.
TITLE_WORD_SIMILARITY = 0.5
TITLE_CHAR_SIMILARITY = 0.6
# Above this many candidate pairs in one place, compare titles only.
_REWRITE_BODY_PAIRS = 400
# Calls that are assertions by name: assert_frame_equal(), check_response(),
# self.assertEqual() (and the JavaScript expectValid(), verifyRow()). A
# function of that name defined in the test file itself counts only when it
# asserts.
ASSERTION_HELPER_RE = re.compile(
    r"^_*(?i:assert|check|verify|expect|validate|ensure|should)(?:[A-Z0-9_]|$)"
)
_PY_ASSERTION_CALLS = {"raises", "warns", "deprecated_call", "fail"}
# Assertion calls that check their first argument is true.
_PY_TRUTH_ASSERTIONS = {"assertTrue", "assert_", "failUnless"}
# Exceptions that a failed assertion raises, and that swallow it when caught.
_PY_ASSERTION_ERRORS = {"AssertionError", "Exception", "BaseException"}
_TOKEN_RE = re.compile(r"\w+|[^\w\s]")
_DUMP_TOKEN_RE = re.compile(
    r"(?:\b(?:id|attr|arg|name|module)=(?P<name>'[^']*'))"
    r"|(?:\bvalue=(?P<value>b?'(?:[^'\\]|\\.)*'|b?\"(?:[^\"\\]|\\.)*\""
    r"|-?\d[\w.+-]*|True|False|None|Ellipsis))"
    r"|(?:\b(?P<node>[A-Z]\w*)\()"
)
_DUMP_SCAFFOLDING = frozenset(
    {"Name", "Constant", "Load", "Store", "Del", "Expr", "Attribute"}
)
_COMPARE = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
}
# x == x, x is x, x >= x: true whatever x is.
_REFLEXIVE = (ast.Eq, ast.Is, ast.GtE, ast.LtE)

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
    # Assertions in the body that can run; None when they cannot be counted.
    assertions: int | None = field(default=None, compare=False)
    # Lines of ``return`` statements with assertions after them.
    early_returns: tuple[int, ...] = field(default=(), compare=False)

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


@dataclass(frozen=True)
class GuttedTest:
    test: TestItem  # at head
    before: int  # assertions at the base


@dataclass(frozen=True)
class FewerAssertions:
    test: TestItem  # at head
    before: int
    after: int


@dataclass(frozen=True)
class EarlyReturn:
    test: TestItem  # at head
    line: int  # a return statement the base test did not have


@dataclass(frozen=True)
class RewrittenTest:
    before: TestItem
    after: TestItem
    # "renamed": a new title and an edited body, in the same class or
    # describe; "moved": the same title under a renamed class or describe,
    # edited; "in place": written where the deleted test stood.
    how: str = "in place"


@dataclass
class InventoryDiff:
    deleted: list[DeletedTest] = field(default_factory=list)
    newly_skipped: list[NewlySkipped] = field(default_factory=list)
    dropped_cases: list[DroppedCases] = field(default_factory=list)
    # Existing tests left with no countable assertion.
    gutted: list[GuttedTest] = field(default_factory=list)
    # Existing tests with fewer countable assertions (but some).
    fewer_assertions: list[FewerAssertions] = field(default_factory=list)
    # Existing tests with a new return that can skip their assertions.
    early_returns: list[EarlyReturn] = field(default_factory=list)
    # Deleted tests paired with a new test whose body differs: renamed and
    # edited, or written in their place. Only an identical body (a move or a
    # rename) pairs without being reported.
    rewritten: list[RewrittenTest] = field(default_factory=list)
    matched: dict[str, TestItem] = field(default_factory=dict)


def compare_inventories(
    base: list[TestItem],
    head: list[TestItem],
    renamed_paths: dict[str, str] | None = None,
) -> InventoryDiff:
    """Tests that existed at the base and are gone, skipped or thinned at head.

    ``renamed_paths`` maps base paths to head paths for renamed files. Tests
    written after the base are not considered: they can change freely.

    A base test without a test of the same id at head is matched, in order,
    to a new test with the same body (a move or rename, not reported); to a
    new test in the same class or describe block with a similar title and a
    similar body (renamed and edited); to a new test with the same name under
    a class or describe block that was renamed; and to a new test written in
    its place: in the same file, between the same surviving neighbours, with
    a similar title or body. Every pairing but the first is reported as a
    rewrite. A new test that copies a test still there is never paired, and
    the last two passes never pair a test with one that has no countable
    assertion, so a gutted replacement stays a deletion.
    """
    renamed_paths = renamed_paths or {}
    head_by_id = {item.id: item for item in head}
    mapped_base_ids = {_moved_id(item, renamed_paths) for item in base}
    # Head tests that are new in this change: candidates for a pairing.
    unmatched_new = {item.id: item for item in head if item.id not in mapped_base_ids}

    pairs: dict[int, TestItem] = {}
    leftover: list[int] = []
    for index, test in enumerate(base):
        current = head_by_id.get(_moved_id(test, renamed_paths))
        if current is None:
            leftover.append(index)
        else:
            pairs[index] = current
    leftover = _same_body(base, leftover, pairs, unmatched_new, renamed_paths)
    guard = _CopyGuard(list(pairs.values()))

    how: dict[int, str] = {}
    remaining = []
    for index in leftover:
        match = _renamed_and_edited(base[index], unmatched_new, renamed_paths, guard)
        if match is None:
            remaining.append(index)
            continue
        unmatched_new.pop(match.id, None)
        pairs[index] = match
        how[index] = "renamed"
    leftover = remaining

    if leftover and unmatched_new:
        base_scopes = {(renamed_paths.get(t.path, t.path), t.classes) for t in base}
        head_scopes = {(t.path, t.classes) for t in head}
        remaining = _under_renamed_scope(
            base, leftover, pairs, unmatched_new, renamed_paths, head_scopes, guard
        )
        how.update(dict.fromkeys(set(leftover) - set(remaining), "moved"))
        for index, item in _rewritten_in_place(
            base,
            remaining,
            pairs,
            head,
            unmatched_new,
            renamed_paths,
            base_scopes,
            guard,
        ):
            pairs[index] = item
            how[index] = "in place"

    result = InventoryDiff()
    for index, test in enumerate(base):
        current = pairs.get(index)
        if current is None:
            result.deleted.append(DeletedTest(test))
            continue
        if index in how:
            result.rewritten.append(RewrittenTest(test, current, how[index]))
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
        if test.assertions and current.assertions == 0:
            result.gutted.append(GuttedTest(current, test.assertions))
        elif (
            test.assertions
            and current.assertions is not None
            and current.assertions < test.assertions
        ):
            result.fewer_assertions.append(
                FewerAssertions(current, test.assertions, current.assertions)
            )
        if len(current.early_returns) > len(test.early_returns):
            result.early_returns.append(EarlyReturn(current, current.early_returns[0]))
    return result


def _moved_id(item: TestItem, renamed: dict[str, str], *, reverse: bool = False) -> str:
    mapping = {v: k for k, v in renamed.items()} if reverse else renamed
    return "::".join((mapping.get(item.path, item.path), *item.classes, item.name))


def _same_body(
    base: list[TestItem],
    leftover: list[int],
    pairs: dict[int, TestItem],
    candidates: dict[str, TestItem],
    renamed: dict[str, str],
) -> list[int]:
    """Pair tests moved or renamed with the same body, each new test once
    (body identity does not prove decorators or cases were kept). A new
    test in the same place is preferred: same file and block, then same
    file. Returns the tests still unpaired."""
    by_hash: dict[str, list[TestItem]] = {}
    for item in candidates.values():
        by_hash.setdefault(item.body_hash, []).append(item)
    remaining = []
    for index in leftover:
        test = base[index]
        target = renamed.get(test.path, test.path)
        options = [
            item for item in by_hash.get(test.body_hash, ()) if item.id in candidates
        ]
        if not options:
            remaining.append(index)
            continue
        match = min(
            options,
            key=lambda item: (item.path != target, item.classes != test.classes),
        )
        candidates.pop(match.id)
        pairs[index] = match
    return remaining


class _CopyGuard:
    """Whether a new test copies a test that is still there.

    Deleting a failing test and pasting a passing sibling under a new name
    must not read as the deleted test renamed and edited: a new test whose
    body is identical to a surviving test anywhere, or at least
    ``COPY_SIMILARITY`` like one in the same file and closer to it than to
    the deleted test, is never the deleted test's replacement.
    """

    def __init__(self, survivors: list[TestItem]) -> None:
        self.hashes = {item.body_hash for item in survivors}
        self.by_path: dict[str, list[TestItem]] = {}
        for item in survivors:
            self.by_path.setdefault(item.path, []).append(item)
        self._closest: dict[str, float] = {}

    def closest(self, item: TestItem) -> float:
        if item.id not in self._closest:
            if item.body_hash in self.hashes:
                ratio = 1.0
            else:
                ratio = max(
                    (
                        _body_ratio(item, other, COPY_SIMILARITY)
                        for other in self.by_path.get(item.path, ())
                    ),
                    default=0.0,
                )
            self._closest[item.id] = ratio
        return self._closest[item.id]

    def is_copy(self, item: TestItem, deleted: TestItem) -> bool:
        closest = self.closest(item)
        return closest >= COPY_SIMILARITY and closest >= _body_ratio(item, deleted)


def _renamed_and_edited(
    test: TestItem,
    candidates: dict[str, TestItem],
    renamed: dict[str, str],
    guard: _CopyGuard,
) -> TestItem | None:
    target_path = renamed.get(test.path, test.path)
    best: tuple[float, TestItem] | None = None
    for item in candidates.values():
        if item.path != target_path or item.classes != test.classes:
            continue
        if not _titles_similar(test.name, item.name):
            continue
        ratio = difflib.SequenceMatcher(
            None, test.body_dump, item.body_dump, autojunk=False
        ).ratio()
        if (
            ratio >= RENAME_SIMILARITY
            and (best is None or ratio > best[0])
            and not guard.is_copy(item, test)
        ):
            best = (ratio, item)
    return best[1] if best else None


def _keeps_assertions(test: TestItem, item: TestItem) -> bool:
    return not (test.assertions and item.assertions == 0)


def _under_renamed_scope(
    base: list[TestItem],
    leftover: list[int],
    pairs: dict[int, TestItem],
    candidates: dict[str, TestItem],
    renamed: dict[str, str],
    head_scopes: set[tuple[str, tuple[str, ...]]],
    guard: _CopyGuard,
) -> list[int]:
    """Pair tests whose class or describe block was renamed and whose body
    changed (often the same rename): same file, same test name, the old
    class or describe block is gone, and the block name or the body is
    similar. Returns the tests still unpaired."""
    remaining = []
    for index in leftover:
        test = base[index]
        target_path = renamed.get(test.path, test.path)
        best: tuple[float, TestItem] | None = None
        if test.classes and (target_path, test.classes) not in head_scopes:
            for item in candidates.values():
                if (
                    item.path != target_path
                    or item.name != test.name
                    or item.classes == test.classes
                    or not _keeps_assertions(test, item)
                ):
                    continue
                ratio = max(
                    _title_ratio(" ".join(test.classes), " ".join(item.classes)),
                    _token_ratio(test.body_dump, item.body_dump),
                )
                if (
                    ratio >= REWRITE_SIMILARITY
                    and (best is None or ratio > best[0])
                    and not guard.is_copy(item, test)
                ):
                    best = (ratio, item)
        if best is None:
            remaining.append(index)
            continue
        candidates.pop(best[1].id, None)
        pairs[index] = best[1]
    return remaining


def _rewritten_in_place(
    base: list[TestItem],
    leftover: list[int],
    pairs: dict[int, TestItem],
    head: list[TestItem],
    candidates: dict[str, TestItem],
    renamed: dict[str, str],
    base_scopes: set[tuple[str, tuple[str, ...]]],
    guard: _CopyGuard,
) -> list[tuple[int, TestItem]]:
    """Deleted tests paired with the new test written in their place.

    Per file, base and head tests are aligned by the tests matched so far;
    a deleted test may pair with a new test in the same gap between
    surviving neighbours, in the same class or describe block (or across a
    block that was renamed or newly written), with a similar title or body.
    """
    target = {
        index: renamed.get(base[index].path, base[index].path) for index in leftover
    }
    head_scopes = {(t.path, t.classes) for t in head}
    result: list[tuple[int, TestItem]] = []
    for path in sorted(set(target.values())):
        base_order = sorted(
            (
                index
                for index, test in enumerate(base)
                if renamed.get(test.path, test.path) == path
            ),
            key=lambda index: base[index].line,
        )
        head_order = sorted(
            (item for item in head if item.path == path), key=lambda item: item.line
        )
        base_keys = [
            pairs[index].id
            if index in pairs and pairs[index].path == path
            else f"\0base{index}"
            for index in base_order
        ]
        head_keys = [
            item.id if item.id not in candidates else f"\0head{item.id}"
            for item in head_order
        ]
        matcher = difflib.SequenceMatcher(None, base_keys, head_keys, autojunk=False)
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag != "replace":
                continue
            gone = [
                index
                for index in base_order[i1:i2]
                if index not in pairs and index in target
            ]
            new = [item for item in head_order[j1:j2] if item.id in candidates]
            for index, item in _pair_gap(
                base, gone, new, base_scopes, head_scopes, guard
            ):
                candidates.pop(item.id, None)
                result.append((index, item))
    return result


def _pair_gap(
    base: list[TestItem],
    gone: list[int],
    new: list[TestItem],
    base_scopes: set[tuple[str, tuple[str, ...]]],
    head_scopes: set[tuple[str, tuple[str, ...]]],
    guard: _CopyGuard,
) -> list[tuple[int, TestItem]]:
    if not gone or not new:
        return []
    compare_bodies = len(gone) * len(new) <= _REWRITE_BODY_PAIRS
    scored = []
    for index in gone:
        test = base[index]
        for position, item in enumerate(new):
            if not _keeps_assertions(test, item):
                continue
            if item.classes != test.classes and (
                (item.path, test.classes) in head_scopes
                and (item.path, item.classes) in base_scopes
            ):
                continue  # both blocks still exist: a test moved between them
            score = _title_ratio(test.name, item.name)
            if compare_bodies and score < 1.0:
                score = max(score, _token_ratio(test.body_dump, item.body_dump))
            if score >= REWRITE_SIMILARITY:
                scored.append((-score, index, position))
    scored.sort()
    paired: list[tuple[int, TestItem]] = []
    used_base: set[int] = set()
    used_new: set[int] = set()
    for _, index, position in scored:
        if index in used_base or position in used_new:
            continue
        if guard.is_copy(new[position], base[index]):
            continue
        used_base.add(index)
        used_new.add(position)
        paired.append((index, new[position]))
    return paired


def _titles_similar(first: str, second: str) -> bool:
    """Most of the words, or of the characters, of two titles match."""
    a, b = _title_words(first), _title_words(second)
    if not a or not b:
        return False
    words = difflib.SequenceMatcher(None, a.split(), b.split(), autojunk=False)
    return (
        words.ratio() >= TITLE_WORD_SIMILARITY
        or _title_ratio(first, second) >= TITLE_CHAR_SIMILARITY
    )


def _title_ratio(first: str, second: str) -> float:
    a, b = _title_words(first), _title_words(second)
    if not a or not b:
        return 0.0
    ratio = difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()
    shorter, longer = sorted((a, b), key=len)
    if len(shorter) >= 12 and shorter in longer:
        ratio = max(ratio, 0.8)  # a prefix dropped or a qualifier added
    return ratio


def _title_words(name: str) -> str:
    """``test_rejects_bad_token`` and "rejects bad token" read the same."""
    text = re.sub(r"^test_?", "", name.lower()) if "_" in name else name.lower()
    return " ".join(re.sub(r"[_\W]+", " ", text).split())


def _token_ratio(first: str, second: str) -> float:
    return _ratio(_tokens(first), _tokens(second), REWRITE_SIMILARITY)


def _body_ratio(first: TestItem, second: TestItem, floor: float = 0.0) -> float:
    """Similarity of two bodies as the names, values and operations they
    contain (0.0 below ``floor``)."""
    return _ratio(_body_tokens(first), _body_tokens(second), floor)


def _body_tokens(item: TestItem) -> tuple[str, ...]:
    if item.path.endswith(".py"):
        return _dump_tokens(item.body_dump)
    return _tokens(item.body_dump)  # JS/TS bodies are stored as tokens


@functools.lru_cache(maxsize=4096)
def _tokens(text: str) -> tuple[str, ...]:
    return tuple(_TOKEN_RE.findall(text))


@functools.lru_cache(maxsize=4096)
def _dump_tokens(dump: str) -> tuple[str, ...]:
    """An ``ast.dump`` without its scaffolding: ``assert run(1) == 2`` reads
    as Assert Compare Call run 1 Eq 2, so two different one-line tests are
    not near-identical just because their dumps share the field names."""
    tokens = []
    for match in _DUMP_TOKEN_RE.finditer(dump):
        node = match.group("node")
        if node is None:
            tokens.append(match.group("name") or match.group("value"))
        elif node not in _DUMP_SCAFFOLDING:
            tokens.append(node)
    return tuple(tokens)


def _ratio(a: tuple[str, ...], b: tuple[str, ...], floor: float) -> float:
    if not a or not b:
        return 0.0
    matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
    if matcher.real_quick_ratio() < floor or matcher.quick_ratio() < floor:
        return 0.0
    ratio = matcher.ratio()
    return ratio if ratio >= floor else 0.0


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
        self.assertion_helpers, self.defined_functions = _assertion_helpers(tree)
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
                assertions=_assertion_count(
                    node, self.assertion_helpers, self.defined_functions
                ),
                early_returns=_early_returns(
                    node, self.assertion_helpers, self.defined_functions
                ),
            )
        )


# ---------------------------------------------------------------------------
# Counting assertions
# ---------------------------------------------------------------------------


def _assertion_helpers(tree: ast.Module) -> tuple[set[str], set[str]]:
    """Names of functions in the file that assert (or raise), directly or
    through each other: a test that calls one still checks something. Also
    returns every function name the file defines: a helper named like an
    assertion (``check_result``) that is defined here and asserts nothing
    checks nothing."""
    functions: dict[str, list[ast.AST]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.setdefault(node.name, []).append(node)
    defined = set(functions)
    helpers: set[str] = set()
    for _ in range(5):
        found = {
            name
            for name, nodes in functions.items()
            if name not in helpers
            and any(
                _assertion_count(node, helpers, defined, helper=True) for node in nodes
            )
        }
        if not found:
            break
        helpers |= found
    return helpers, defined


def _assertion_count(
    function: ast.AST,
    helpers: set[str],
    defined: set[str] | frozenset[str] = frozenset(),
    *,
    helper: bool = False,
) -> int:
    """``assert`` statements, ``self.assert*``/``assert_*()``-style calls,
    ``pytest.raises``/``warns``/``fail``, ``raise AssertionError`` (any
    ``raise`` in a ``helper``) and calls to asserting helpers, outside code
    that cannot run: after ``return`` or ``raise`` (also under ``if True:``),
    under ``if False:``, in a ``try`` whose ``except`` swallows the failure,
    in a nested function that is never used. Tautologies check nothing:
    ``assert True``, ``assert 1 == 1``, ``assert x == x``, ``assert (x,
    "message")``, ``self.assertEqual(x, x)``, ``self.assertTrue(True)``."""
    dead = _dead_nodes(function)
    count = 0
    for node in ast.walk(function):
        if id(node) in dead:
            continue
        if isinstance(node, ast.Assert):
            if _constant_truth(node.test) is not True and not _tautology(node.test):
                count += 1
        elif isinstance(node, ast.Raise):
            if helper or _raises_assertion_error(node):
                count += 1
        elif isinstance(node, ast.Call) and _is_assertion_call(node, helpers, defined):
            count += 1
    return count


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _is_assertion_call(node: ast.Call, helpers, defined) -> bool:
    name = _call_name(node)
    if not name:
        return False
    if name in _PY_ASSERTION_CALLS or name in helpers:
        return True
    if name in defined or not ASSERTION_HELPER_RE.match(name):
        return False
    args = node.args
    if args and all(
        _is_constant(value)
        for value in [*args, *(keyword.value for keyword in node.keywords)]
    ):
        return False  # self.assertEqual(1, 1), assert_true(True)
    if len(args) >= 2 and _same_value(args[0], args[1]):
        return False  # self.assertEqual(x, x)
    if name in _PY_TRUTH_ASSERTIONS and args and _tautology(args[0]):
        return False  # self.assertTrue(x == x)
    return True


def _raises_assertion_error(node: ast.Raise) -> bool:
    exc = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
    name = _dotted(exc) if exc is not None else ()
    return bool(name) and name[-1] in {"AssertionError", "failureException"}


def _early_returns(
    function: ast.FunctionDef | ast.AsyncFunctionDef, helpers, defined
) -> tuple[int, ...]:
    """Lines of ``return`` statements in the test itself (not in a nested
    function) with an assertion after them: ``if not data: return``."""
    last = max(
        (
            (node.lineno, node.col_offset)
            for node in ast.walk(function)
            if isinstance(node, ast.Assert)
            or (
                isinstance(node, ast.Call)
                and _is_assertion_call(node, helpers, defined)
            )
        ),
        default=None,
    )
    if last is None:
        return ()
    lines = []
    stack: list[ast.AST] = list(function.body)
    while stack:
        node = stack.pop()
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
        ):
            continue
        if (
            isinstance(node, ast.Return)
            and (
                node.end_lineno or node.lineno,
                node.end_col_offset or 0,
            )
            <= last
        ):
            lines.append(node.lineno)
        stack.extend(ast.iter_child_nodes(node))
    return tuple(sorted(lines))


_TRY_NODES = tuple(
    getattr(ast, name) for name in ("Try", "TryStar") if hasattr(ast, name)
)
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef)


def _dead_nodes(function: ast.AST) -> set[int]:
    dead: set[int] = set()

    def bury(statements) -> None:
        dead.update(id(node) for stmt in statements for node in ast.walk(stmt))

    used = {
        node.id
        for node in ast.walk(function)
        if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Store)
    }
    for node in ast.walk(function):
        for name in node._fields:
            value = getattr(node, name, None)
            if isinstance(value, list) and value and isinstance(value[0], ast.stmt):
                for position, stmt in enumerate(value):
                    if _terminates(stmt):
                        bury(value[position + 1 :])
                        break
        if isinstance(node, (ast.If, ast.While)):
            truth = _constant_truth(node.test)
            if truth is False:
                bury(node.body)
            elif truth is True and isinstance(node, ast.If):
                bury(node.orelse)
        elif isinstance(node, _TRY_NODES):
            if any(_swallows(handler) for handler in node.handlers):
                bury(node.body)  # a failed assertion is caught and dropped
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            if any(_suppresses(item.context_expr) for item in node.items):
                bury(node.body)  # contextlib.suppress(AssertionError)
        elif (
            isinstance(node, _SCOPES)
            and node is not function
            and not node.decorator_list
            and node.name not in used
        ):
            bury([node])  # a nested function nothing calls
    return dead


def _terminates(stmt: ast.stmt) -> bool:
    """``return`` and ``raise``, also under ``if True:`` or in both branches
    of an ``if``: what follows never runs."""
    if isinstance(stmt, (ast.Return, ast.Raise)):
        return True
    if isinstance(stmt, ast.If):
        truth = _constant_truth(stmt.test)
        if truth is True:
            return _block_terminates(stmt.body)
        if truth is False:
            return _block_terminates(stmt.orelse)
        return _block_terminates(stmt.body) and _block_terminates(stmt.orelse)
    return False


def _block_terminates(statements: list[ast.stmt]) -> bool:
    return any(_terminates(stmt) for stmt in statements)


def _catches_assertions(node: ast.AST | None) -> bool:
    """``except:``, ``except AssertionError``, ``except Exception`` (or a
    tuple with one of them)."""
    if node is None:
        return True
    names = node.elts if isinstance(node, ast.Tuple) else [node]
    return any((_dotted(name) or ("",))[-1] in _PY_ASSERTION_ERRORS for name in names)


def _swallows(handler: ast.ExceptHandler) -> bool:
    """A handler that catches a failed assertion and neither re-raises nor
    fails the test."""
    if not _catches_assertions(handler.type):
        return False
    for node in ast.walk(handler):
        if isinstance(node, (ast.Raise, ast.Assert)):
            return False
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name and (
                name in _PY_ASSERTION_CALLS or ASSERTION_HELPER_RE.match(name)
            ):
                return False
    return True


def _suppresses(expr: ast.expr) -> bool:
    if not isinstance(expr, ast.Call):
        return False
    name = _dotted(expr.func)
    return (
        bool(name)
        and name[-1] == "suppress"
        and any(_catches_assertions(arg) for arg in expr.args)
    )


_UNKNOWN = object()


def _constant_truth(node: ast.AST) -> bool | None:
    """The truth of an expression fixed in the source, else None."""
    value = _constant_value(node)
    if value is _UNKNOWN:
        return None
    try:
        return bool(value)
    except Exception:
        return None


def _constant_value(node: ast.AST):
    """The value of a small constant expression (``1 > 2``, ``not 0``,
    ``"a" in "abc"``), else ``_UNKNOWN``. Never evaluates anything costly."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, (ast.Tuple, ast.List)):
        values = [_constant_value(item) for item in node.elts]
        return _UNKNOWN if _UNKNOWN in values else tuple(values)
    if isinstance(node, ast.UnaryOp):
        inner = _constant_value(node.operand)
        if inner is _UNKNOWN:
            return _UNKNOWN
        if isinstance(node.op, ast.Not):
            return not inner
        if isinstance(node.op, (ast.USub, ast.UAdd)) and isinstance(
            inner, (int, float)
        ):
            return -inner if isinstance(node.op, ast.USub) else inner
        return _UNKNOWN
    if isinstance(node, ast.BoolOp):
        values = [_constant_value(item) for item in node.values]
        if _UNKNOWN in values:
            return _UNKNOWN
        result = values[0]
        for value in values[1:]:
            if isinstance(node.op, ast.And):
                result = result and value
            else:
                result = result or value
        return result
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub)):
        left, right = _constant_value(node.left), _constant_value(node.right)
        if (
            isinstance(left, (int, float))
            and isinstance(right, (int, float))
            and max(abs(left), abs(right)) < 1e12
        ):
            return left + right if isinstance(node.op, ast.Add) else left - right
        return _UNKNOWN
    if isinstance(node, ast.Compare):
        values = [_constant_value(node.left)] + [
            _constant_value(item) for item in node.comparators
        ]
        if _UNKNOWN in values or not all(
            isinstance(value, (int, float, str, bool, type(None))) for value in values
        ):
            return _UNKNOWN
        for op, left, right in zip(node.ops, values, values[1:]):
            compare = _COMPARE.get(type(op))
            try:
                if compare is not None:
                    holds = compare(left, right)
                elif isinstance(op, (ast.Is, ast.IsNot)) and None in (left, right):
                    holds = (left is right) == isinstance(op, ast.Is)
                elif isinstance(op, (ast.In, ast.NotIn)) and isinstance(right, str):
                    holds = (left in right) == isinstance(op, ast.In)
                else:
                    return _UNKNOWN
            except TypeError:
                return _UNKNOWN
            if not holds:
                return False
        return True
    return _UNKNOWN


def _is_constant(node: ast.AST) -> bool:
    if isinstance(node, ast.Dict):
        return all(key is not None and _is_constant(key) for key in node.keys) and all(
            _is_constant(value) for value in node.values
        )
    if isinstance(node, (ast.Set, ast.Tuple, ast.List)):
        return all(_is_constant(item) for item in node.elts)
    return _constant_value(node) is not _UNKNOWN


def _tautology(node: ast.AST) -> bool:
    """True whatever it is about: ``x == x``, ``x is x``, a non-empty tuple
    (``assert (x, "message")``)."""
    if isinstance(node, ast.Tuple) and node.elts:
        return True
    if (
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and isinstance(node.ops[0], _REFLEXIVE)
    ):
        return _same_value(node.left, node.comparators[0])
    if isinstance(node, ast.BoolOp):
        parts = [
            _tautology(value) or _constant_truth(value) is True for value in node.values
        ]
        return any(parts) if isinstance(node.op, ast.Or) else all(parts)
    return False


def _same_value(first: ast.AST, second: ast.AST) -> bool:
    """The same expression, with no call in it (a call may differ twice)."""
    return ast.dump(first) == ast.dump(second) and not any(
        isinstance(node, (ast.Call, ast.Await, ast.Yield, ast.YieldFrom, ast.NamedExpr))
        for node in ast.walk(first)
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
