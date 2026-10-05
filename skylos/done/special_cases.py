"""Code changed to pass particular tests instead of being right.

Agents that cannot make a test pass sometimes change the code under test so
that it recognises the test rather than computes the answer. Only lines this
change added to non-test files are read, and code that was already there at
the base never counts:

* SKY-A115, hard-coded test answers. A branch, ``match``/``switch`` case,
  conditional expression or lookup table that compares an input with a
  literal and answers with a literal, where one test assertion passes that
  input and expects that answer (``if n == 3: return 6`` for
  ``assert factorial(3) == 6``; ``{3: 6}[n]``). It blocks only when the
  function also computes its result some other way, the test calls it by
  name, the assertion existed at the base, and no input is a trivial value
  (0, 1, -1, empty, None, booleans) or a word the code or docs already use.
  Other matches are advice.
* SKY-A116, test detection. Production code that asks whether a test runner
  is running it (``PYTEST_CURRENT_TEST``, ``"pytest" in sys.modules``,
  ``process.env.JEST_WORKER_ID``, ``typeof jest``) or reads the tests' own
  files. ``NODE_ENV === "test"`` and similar environment switches are advice.
  Test helpers, setup and config files are left out.
* SKY-A117, rigged comparisons. ``__eq__`` that always holds or ignores the
  value it is compared with, ``__ne__`` that is always false,
  ``__contains__`` that is always true, and JS ``equals()``/``compareTo()``/
  ``valueOf()``/``[Symbol.toPrimitive]`` returning constants. Constant
  ordering methods, hashes and string forms the tests expect are advice.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field, replace
from pathlib import PurePosixPath

from skylos.done.answer_sites import (
    ANONYMOUS,
    RULE_HARDCODED,
    RULE_RIGGED,
    RULE_TEST_DETECTION,
    Cond,
    Marker,
    Scan,
    Site,
    _code_kind,
    _is_generated,
    _is_test_code,
    scan_source,
)
from skylos.done.base import _GIT_TIMEOUT_SECONDS, DoneError, _command
from skylos.done.expected_answers import (
    _IDENTIFIER_RE,
    _clip,
    Call,
    Case,
    _convert,
    _lit,
    _show,
    _trivial,
    _unusual,
    data_file_cases,
    is_test_data_file,
    is_test_fixture_file,
    js_cases,
    python_cases,
)
from skylos.done.inventory import is_pytest_file
from skylos.done.js_inventory import is_js_test_file

__all__ = ["RULE_HARDCODED", "RULE_RIGGED", "RULE_TEST_DETECTION", "find_special_cases"]

# Bounds: a check that reads every test file must stay cheap on big repos.
_MAX_TEST_FILES = 3000
_MAX_DATA_FILES = 200

_STDIN_RE = re.compile(
    r"sys\.stdin|\binput\(|process\.stdin|readFileSync\(\s*(?:0|['\"]/dev/stdin)"
)


# ---------------------------------------------------------------------------
# Matching code against tests
# ---------------------------------------------------------------------------


def _bound(call: Call, cond: Cond):
    """The value a call passes for the compared parameter, None if unknown."""
    if cond.param is None:
        return None
    for name, value in call.kwargs:
        if name == cond.param:
            return value
    if call.star or cond.index is None or cond.index >= len(call.args):
        return None
    return call.args[cond.index]


def _matches(cond: Cond, value) -> bool:
    if not _lit(value):
        return False
    converted = _convert(value, cond.convert)
    return _lit(converted) and converted in cond.values


def _linked_calls(site: Site, case: Case) -> list[Call]:
    names = {site.function} if site.function else set()
    if site.function in {"__init__", "__new__", "constructor"} and site.owner:
        names.add(site.owner)
    return [c for c in case.calls if c.name in names]


def _inputs_match(site: Site, case: Case, linked: list[Call]) -> bool:
    for call in linked or [None]:
        ok = True
        for cond in site.conds:
            value = _bound(call, cond) if call is not None else None
            if value is not None:
                if not _matches(cond, value):
                    ok = False
                    break
            elif not any(_matches(cond, v) for v in case.inputs):
                ok = False
                break
        if ok:
            return True
    return False


@dataclass
class _Match:
    case: Case
    linked: bool  # the test calls the function (or runs the program)
    imported: bool  # the test file imports the function's module
    answer: bool
    at_base: bool


def _best_match(site: Site, found: _Cases, stdin_files: set[str]):
    """The assertion that fits the special case best: one expecting its answer
    first, else one that calls the function with its input."""
    names = {site.function} if site.function else set()
    if site.function in {"__init__", "__new__", "constructor"} and site.owner:
        names.add(site.owner)
    forms = _answer_forms(site.result)
    candidates = []
    for form in forms:
        candidates += found.by_answer.get(form, ())
    candidates = list({id(c): c for c in candidates}.values())
    seen = {id(c) for c in candidates}
    for name in sorted(names):
        candidates += [c for c in found.by_name.get(name, ()) if id(c) not in seen]
    best: _Match | None = None
    best_rank = -1
    for case in candidates:
        linked_calls = _linked_calls(site, case)
        linked = bool(linked_calls) or (
            case.stdin
            and (site.path in stdin_files or found.runs(case.path, site.function))
        )
        if not _inputs_match(site, case, linked_calls):
            continue
        answer = bool(forms & case.expected)
        imported = site.path in found.imports.get(case.path, ())
        match = _Match(case, linked, imported, answer, case.key in found.base_keys)
        rank = (answer << 3) | (linked << 2) | (imported << 1) | match.at_base
        if rank > best_rank:
            best, best_rank = match, rank
            if rank == 15:
                break
    return best


class _Vocabulary:
    """Whether a string is already part of the code's vocabulary: quoted in a
    non-test file at the base. Text the change itself adds (to docs, a
    constant) does not count: the change cannot vouch for itself."""

    def __init__(self, comparison, python_tests: set[str]) -> None:
        self.comparison = comparison
        self.python_tests = python_tests
        self.cache: dict[str, str | None] = {}

    def where(self, text: str) -> str | None:
        if text not in self.cache:
            self.cache[text] = self._where(text)
        return self.cache[text]

    def _where(self, text: str) -> str | None:
        if not text.strip() or "\n" in text or len(text) > 200:
            return None
        patterns = [f'"{text}"', f"'{text}'", f"`{text}`"]
        holding = _grep(self.comparison, patterns, None)
        if holding is None:
            return "the base"  # Git could not say: assume the code knows it
        for path in sorted(holding):
            if not _is_test_code(path, self.python_tests) and not is_test_fixture_file(
                path
            ):
                return path
        return None


# ---------------------------------------------------------------------------
# The check
# ---------------------------------------------------------------------------


@dataclass
class Outcome:
    findings: list  # (rule, file, line, message, blocking)
    files: int
    unparsed: list[str]


def find_special_cases(ctx) -> Outcome:
    comparison = ctx.comparison
    test_names = _test_file_names(ctx)
    findings: list[tuple[str, str, int, str, bool]] = []
    scans: dict[str, Scan] = {}
    generated: set[str] = set()
    unparsed: list[str] = []
    stdin_files: set[str] = set()
    for changed in comparison.changed:
        path = changed.head_path
        if not path or _code_kind(path) is None or _is_test_code(path, set()):
            continue
        added = comparison.added_lines(changed)
        if not added:
            continue
        source = comparison.head_text(path)
        scan = scan_source(path, source, added, test_names)
        if not scan.clean:
            unparsed.append(path)
        if scan.sites or scan.markers:
            scans[path] = scan
            if _is_generated(path, source):
                generated.add(path)
            if _STDIN_RE.search(source or ""):
                stdin_files.add(path)
    # The full Python test inventory also knows unittest files kept next to
    # the code; it is only worth building when there is something to judge.
    python_tests = _python_test_paths(ctx) if scans else set()
    scans = {p: s for p, s in scans.items() if p not in python_tests}
    if not scans:
        return Outcome([], _count_files(comparison, python_tests), unparsed)

    new_sites = [s for scan in scans.values() for s in scan.sites if _worth_judging(s)]
    new_markers = [(path, m) for path, scan in scans.items() for m in scan.markers]
    if not new_sites and not new_markers:
        return Outcome([], _count_files(comparison, python_tests), unparsed)

    # Tests first: most special cases (labels, keyword dispatch) match no
    # assertion and need no further work.
    wanted = {s.function for s in new_sites if s.function not in {"", ANONYMOUS}} | {
        s.owner for s in new_sites if s.owner
    }
    # A constant string form (__repr__, toString) matters to tests of its class.
    wanted |= {m.key[1] for _, m in new_markers if m.expects and m.key[1]}
    need_cases = bool(new_sites) or any(m.expects for _, m in new_markers)
    found = (
        _collect_cases(
            ctx,
            python_tests,
            wanted,
            {s.path for s in new_sites},
            bool(stdin_files) or any(not s.function for s in new_sites),
        )
        if need_cases
        else _Cases()
    )
    matches = {id(s): _best_match(s, found, stdin_files) for s in new_sites}
    new_sites = [
        s
        for s in new_sites
        if any(c.counter for c in s.conds) or matches[id(s)] is not None
    ]
    expected_strings = {
        e[1] for case in found.cases for e in case.expected if e[0] == "s"
    }
    new_markers = [
        (p, m)
        for p, m in new_markers
        if m.expects is None or m.expects in expected_strings
    ]
    if not new_sites and not new_markers:
        return Outcome([], _count_files(comparison, python_tests), unparsed)

    # Code that was already there (moved, reformatted) is not new.
    base_keys = _base_signatures(
        comparison,
        python_tests,
        test_names,
        _needles(new_sites, [m for _, m in new_markers]),
        {s.function for s in new_sites},
        bool(new_markers),
    )
    sites = [s for s in new_sites if s.key not in base_keys["sites"]]
    markers = [(p, m) for p, m in new_markers if m.key not in base_keys["markers"]]
    # A new script nothing imports or runs (verify.py, a scratch copy of the
    # solution) is the agent's own tooling, not code the tests exercise.
    loose = _loose_scripts(
        comparison, {p for p, _ in markers} | {s.path for s in sites}
    )
    for path, marker in markers:
        blocking = marker.blocking and path not in generated and path not in loose
        message = marker.message
        if marker.blocking and not blocking:
            message = f"(advice) {message} {_why_not(path, generated)}"
        findings.append((marker.rule, path, marker.line, message, blocking))

    vocabulary = _Vocabulary(comparison, python_tests)
    seen: set[tuple[str, int]] = set()
    for site in sorted(sites, key=lambda s: (s.path, s.line)):
        if (site.path, site.line) in seen:
            continue
        verdict = _judge(site, matches[id(site)], vocabulary)
        if verdict is None:
            continue
        message, blocking = verdict
        if blocking and (site.path in generated or site.path in loose):
            blocking = False
            message = f"(advice) {message} {_why_not(site.path, generated)}"
        seen.add((site.path, site.line))
        findings.append((RULE_HARDCODED, site.path, site.line, message, blocking))
    findings.sort(key=lambda f: (not f[4], f[1], f[2]))
    return Outcome(findings, _count_files(comparison, python_tests), unparsed)


def _why_not(path: str, generated: set[str]) -> str:
    if path in generated:
        return "(in generated code)"
    return (
        "(in a new file nothing imports or runs: fine for a local check, not "
        "for code the tests exercise)"
    )


def _loose_scripts(comparison, paths: set[str]) -> set[str]:
    """New files among ``paths`` that nothing imports or names: no file at the
    base, no file the change edits and no test."""
    added = {
        c.path for c in comparison.changed if c.status == "added" and c.path in paths
    }
    if not added:
        return set()
    loose = set()
    for path in sorted(added):
        stem = PurePosixPath(path).name.split(".")[0]
        if stem in {"index", "__init__", "__main__"}:
            continue
        reference = _reference_pattern(path)
        holders = _grep(comparison, [stem], None)
        if holders is None:
            continue  # Git could not say: keep the finding
        texts = [comparison.base_text(p) for p in sorted(holders)[:50]]
        # Edited files and tests count; another new script does not (scratch
        # scripts call each other).
        texts += [
            comparison.head_text(c.head_path)
            for c in comparison.changed
            if c.head_path
            and c.head_path != path
            and (c.status != "added" or _is_test_code(c.head_path, set()))
        ]
        if not any(text and reference.search(text) for text in texts):
            loose.add(path)
    return loose


def _reference_pattern(path: str) -> re.Pattern:
    """An import of, or a path naming, the module at ``path``."""
    pure = PurePosixPath(path)
    stem = re.escape(pure.name.split(".")[0])
    name = re.escape(pure.name)
    return re.compile(
        rf"\bimport\s+(?:[\w.]+\.)?{stem}\b"
        rf"|\bfrom\s+(?:[\w.]*\.)?{stem}\s+import\b"
        rf"|\bfrom\s+[\w.]+\s+import\s+[^\n]*\b{stem}\b"
        rf"|\b{name}\b"
        rf"""|["'][^"'\n]*\b{stem}(?:\.[cm]?[jt]sx?)?["']"""
    )


def _judge(site: Site, match: _Match | None, vocabulary: _Vocabulary):
    """(message, blocking) for one special case and the assertion that fits
    it best, or None."""
    inputs = [v for cond in site.conds for v in cond.values]
    counter = any(cond.counter for cond in site.conds)
    result = _clip(site.result_text, 50) or _show(site.result, site.js)
    head = f"{site.where} {site.verb} {result} when {site.condition}"
    if site.verb.startswith("answers"):
        head = f"{site.where} {site.verb} when {site.condition}"
    if counter:
        if _trivial(site.result) or not any(v[0] == "n" for v in inputs):
            return None
        return (
            f"(advice) {head}: it keeps state between calls ("
            f"{', '.join(c.subject for c in site.conds if c.counter)}), so repeated "
            "calls with the same input can get different answers; check that "
            "this is not there to tell test calls apart",
            False,
        )
    if not _worth_judging(site):
        return None  # base cases (if n == 0: return 1), singular wording
    nontrivial = [v for v in inputs if not _trivial(v)]
    if match is None:
        return None
    test = match.case.test
    # A number, a collection or a string that is not a single word: test
    # data. A single word is usually a keyword or an enum value.
    data_like = any(_data_like(v) for v in nontrivial)
    if not match.answer:
        if not (match.linked and match.at_base and site.general and data_like):
            return None
        wanted = ", ".join(
            _show(e, site.js) for e in sorted(match.case.expected, key=repr)[:1]
        )
        return (
            f"(advice) {head}, an input {test} passes (it expects {wanted}); check "
            "that this branch is the general rule and not there for that test",
            False,
        )
    reasons = []
    if not match.linked and not match.imported:
        reasons.append(
            f"{test} neither calls {site.where} nor imports its module, so this "
            "may be a coincidence"
        )
    if not match.at_base:
        reasons.append(
            "that assertion is new or changed in this change, so the test may "
            "have been written for this code"
        )
    # A table keyed by several inputs or by a whole list is a table of test
    # cases, not of domain codes: it blocks even when it is all the function
    # does.
    composite = len(site.conds) >= 2 or any(v[0] in {"l", "d", "S"} for v in inputs)
    if not site.general and not composite:
        reasons.append(
            "the function has no other way to work out its answer, so this may "
            "be a lookup table"
        )
    if not nontrivial:
        reasons.append("the input is a trivial value")
    if not reasons:
        for value in (*nontrivial, site.result):
            where = vocabulary.where(value[1]) if value[0] == "s" else None
            if where:
                reasons.append(
                    f"{_show(value, site.js)} also appears in {where}, so it may be "
                    "a real rule"
                )
                break
    exact = f"{head}, the exact input and answer of {test}"
    if reasons:
        if not data_like:
            return None  # keyword dispatch written with its test: everyday code
        return f"(advice) {exact}; {reasons[0]}", False
    if not data_like:
        return (
            f"(advice) {exact}; the input is a single word, like a keyword or an "
            "enum value, so check that this is a real rule",
            False,
        )
    if not _specific(nontrivial, site.result):
        return (
            f"(advice) {exact}; small inputs and answers like these can be a real "
            "edge case, so check that the general code handles it",
            False,
        )
    return (
        f"{exact}: this special-cases the test instead of computing the answer",
        True,
    )


def _answer_forms(value) -> frozenset:
    """An answer as the tests may see it: ``return 2, 7`` prints "2 7"."""
    forms = {value}
    if value[0] == "s" and value[1] != value[1].strip():
        forms.add(("s", value[1].strip()))  # sys.stdout.write("2 7\n")
    if value[0] == "l" and value[1] and all(v[0] in {"n", "s"} for v in value[1]):
        texts = [_plain(v) for v in value[1]]
        forms.add(("s", " ".join(texts)))
        forms.add(("s", "\n".join(texts)))
    return frozenset(forms)


def _plain(value) -> str:
    if value[0] == "n":
        return repr(value[1])
    if value[0] == "s":
        return value[1].strip()
    return repr(value)


def _specific(inputs: list, answer) -> bool:
    """A pair too particular to be a natural edge case: a number of two or
    more digits, a collection, text that is not one word, or two or more
    inputs. ``if n == 2: print("No")`` is not; ``if n == 5: return 121`` is."""
    if len(inputs) >= 2:
        return True
    for value in (*inputs, answer):
        kind = value[0]
        if kind == "n" and (abs(value[1]) >= 10 or not float(value[1]).is_integer()):
            return True
        if kind in {"l", "d", "S"} and value[1]:
            return True
        if kind == "s" and not _single_word(value[1]) and value[1].strip():
            return True
    return False


def _single_word(text: str) -> bool:
    """One plain word ("pro", "admin_user"), not an ID such as "AB-1234" or
    "u_9f3a": IDs with digits are test data, not a natural edge case."""
    stripped = text.strip()
    if not _IDENTIFIER_RE.match(stripped):
        return False
    return not (len(stripped) >= 4 and any(ch.isdigit() for ch in stripped))


def _data_like(value) -> bool:
    if value[0] == "s":
        return not _single_word(value[1])
    return not _trivial(value)


def _python_test_paths(ctx) -> set[str]:
    """Python files holding tests: the inventory's, plus files a runner is
    pointed at by name (``pytest test.py``) and files in test directories."""
    _, head_paths, removed = ctx._repository_paths()
    paths = {
        p
        for p in head_paths
        if p.endswith(".py") and p not in removed and _is_test_code(p, set())
    }
    try:
        _, head = ctx.tests()
    except DoneError:
        return paths
    return paths | {t.path for t in head}


def _js_test_paths(ctx) -> set[str]:
    try:
        _, head, _ = ctx.js_tests()
        return {t.path for t in head.tests}
    except DoneError:
        _, head_paths, _ = ctx._repository_paths()
        return {p for p in head_paths if is_js_test_file(p)}


def _test_file_names(ctx) -> set[str]:
    """Paths and file names of the tests' own files (test code and data)."""
    _, head_paths, _ = ctx._repository_paths()
    names: set[str] = set()
    for path in head_paths:
        if not path:
            continue
        name = PurePosixPath(path).name
        if (
            is_js_test_file(path)
            or is_test_fixture_file(path)
            or is_pytest_file(path)
            or name in {"test.py", "tests.py"}
        ):
            names.add(path)
            if "test" in name.lower():
                names.add(name)
    return names


def _count_files(comparison, python_tests: set[str]) -> int:
    return sum(
        1
        for c in comparison.changed
        if c.head_path
        and _code_kind(c.head_path) is not None
        and not _is_test_code(c.head_path, python_tests)
    )


def _base_signatures(
    comparison,
    python_tests: set[str],
    test_names: set[str],
    needles: set[str],
    functions: set[str],
    want_markers: bool,
) -> dict:
    """Special cases and markers the base already had, in the changed files
    (code moved within or between them is not new). Only base files holding
    one of ``needles`` (names and literals of what the head added) are read."""
    sites: set = set()
    markers: set = set()
    paths = sorted(
        {
            c.base_path
            for c in comparison.changed
            if c.base_path
            and _code_kind(c.base_path) is not None
            and not _is_test_code(c.base_path, python_tests)
        }
    )
    if not paths:
        return {"sites": sites, "markers": markers}
    holding = None if "" in needles else _grep(comparison, sorted(needles), paths)
    for path in paths:
        if holding is not None and path not in holding:
            continue
        scan = scan_source(
            path,
            comparison.base_text(path),
            None,
            test_names,
            functions=functions,
            markers=want_markers,
        )
        sites.update(s.key for s in scan.sites)
        markers.update(m.key for m in scan.markers)
    return {"sites": sites, "markers": markers}


def _grep(comparison, needles: list[str], paths: list[str] | None) -> set[str] | None:
    """Base files holding any of ``needles`` (fixed strings); None when Git
    cannot say."""
    needles = [n for n in needles if n and "\n" not in n][:200]
    if not needles:
        return set()
    args = ["grep", "-F", "-l", "-z", "-I"]
    for needle in needles:
        args += ["-e", needle]
    args += [comparison.base_sha, "--"]
    if paths is not None:
        args += [f":(literal){p}" for p in paths]
    try:
        result = subprocess.run(
            _command(comparison._context, tuple(args)),
            capture_output=True,
            timeout=_GIT_TIMEOUT_SECONDS,
            cwd=str(comparison._context.root),
            env=comparison._context.env,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode == 1:
        return set()
    if result.returncode != 0:
        return None
    found = set()
    for entry in result.stdout.decode("utf-8", errors="replace").split("\0"):
        if ":" in entry:
            found.add(entry.split(":", 1)[1])
    return found


def _needles(sites: list[Site], markers: list[Marker]) -> set[str]:
    """Text any earlier copy of these findings must contain."""
    found: set[str] = set()
    for site in sites:
        if site.function and site.function != ANONYMOUS:
            found.add(site.function)
        elif site.result[0] in {"n", "s"}:
            found.add(str(site.result[1])[:40])
        else:
            found.add("")
    for marker in markers:
        detail = str(marker.key[-1])
        if marker.key[0] == "reads":
            found.add(detail)
            continue
        word = detail.split(":")[-1].split(".")[-1]
        found.add("" if word in {"stack", "argv"} else word.strip("[]"))
    return found


def _worth_judging(site: Site) -> bool:
    """Drop what ``_judge`` drops anyway before any Git or test work."""
    inputs = [v for cond in site.conds for v in cond.values]
    if any(cond.counter for cond in site.conds):
        return not _trivial(site.result) and any(v[0] == "n" for v in inputs)
    if _plain(site.result) in {_plain(v) for v in inputs}:
        return False  # the answer restates the input: "90" -> 90, parsing
    if not any(not _trivial(v) for v in inputs) and not (
        _unusual(site.result) and site.result[0] != "s"
    ):
        return False
    return not _trivial(site.result) or _unusual(site.result)


@dataclass
class _Cases:
    cases: list[Case] = field(default_factory=list)
    base_keys: set = field(default_factory=set)  # cases already there at the base
    imports: dict[str, set[str]] = field(default_factory=dict)  # test -> code files
    by_answer: dict = field(default_factory=dict)
    by_name: dict = field(default_factory=dict)
    # Test code next to each data file: the runner that feeds it to the code.
    runners: dict[str, str] = field(default_factory=dict)

    def runs(self, data_path: str, function: str) -> bool:
        """Whether the test code beside a data file names ``function``."""
        if not function:
            return False
        text = self.runners.get(str(PurePosixPath(data_path).parent), "")
        return bool(text) and re.search(rf"\b{re.escape(function)}\b", text) is not None

    def index(self) -> None:
        for case in self.cases:
            for value in case.expected:
                self.by_answer.setdefault(value, []).append(case)
            for name in {c.name for c in case.calls}:
                self.by_name.setdefault(name, []).append(case)


def _collect_cases(
    ctx,
    python_tests: set[str],
    wanted: set[str],
    site_paths: set[str],
    data_files: bool,
) -> _Cases:
    """Test cases that may concern the changed code: from test files that
    mention a changed function or module, and test files the change edits."""
    comparison = ctx.comparison
    changed = {c.path: c for c in comparison.changed if c.head_path}
    js_tests = _js_test_paths(ctx)
    paths = sorted(python_tests | js_tests)[:_MAX_TEST_FILES]
    words = set(wanted)
    for site_path in site_paths:
        stem = _module_stem(site_path)
        if len(stem) >= 3 and stem.lower() not in _GENERIC_STEMS:
            words.add(stem)
    importers = {site: _import_patterns(site) for site in site_paths}
    pattern = (
        re.compile(r"\b(?:" + "|".join(re.escape(w) for w in sorted(words)) + r")\b")
        if wanted
        else None
    )
    found = _Cases()
    for path in paths:
        source = comparison.head_text(path)
        if source is None or (
            pattern is not None and path not in changed and not pattern.search(source)
        ):
            continue
        reader = js_cases if path in js_tests else python_cases
        cases = [replace(c, path=path) for c in reader(path, source)]
        if not cases:
            continue
        found.cases += cases
        python = path.endswith(".py")
        found.imports[path] = {
            site
            for site, (stem, python_patterns, js_pattern) in importers.items()
            if stem in source
            and any(
                p.search(source) for p in (python_patterns if python else [js_pattern])
            )
        }
        item = changed.get(path)
        if item is None:
            found.base_keys.update(c.key for c in cases)
        elif item.base_path:
            found.base_keys.update(
                c.key
                for c in reader(item.base_path, comparison.base_text(item.base_path))
            )
    # Program input/output kept in JSON beside the test code that feeds it to
    # the code: read when the code reads stdin, or that test code names a
    # changed function.
    _, head_paths, _ = ctx._repository_paths()
    data_paths = sorted(p for p in head_paths if p and is_test_data_file(p))[
        :_MAX_DATA_FILES
    ]
    folders = {str(PurePosixPath(p).parent) for p in data_paths}
    for path in paths:
        folder = str(PurePosixPath(path).parent)
        if folder in folders:
            text = comparison.head_text(path) or ""
            found.runners[folder] = found.runners.get(folder, "") + "\n" + text
    names = (
        re.compile(r"\b(?:" + "|".join(re.escape(w) for w in sorted(wanted)) + r")\b")
        if wanted
        else None
    )
    for path in data_paths:
        runner = found.runners.get(str(PurePosixPath(path).parent), "")
        if not data_files and not (names is not None and names.search(runner)):
            continue
        cases = [
            replace(c, path=path)
            for c in data_file_cases(path, comparison.head_text(path))
        ]
        found.cases += cases
        item = changed.get(path)
        if item is None:
            found.base_keys.update(c.key for c in cases)
        elif item.base_path:
            found.base_keys.update(
                c.key
                for c in data_file_cases(
                    item.base_path, comparison.base_text(item.base_path)
                )
            )
    found.index()
    return found


# Module names too common to pick out the tests of one module by.
_GENERIC_STEMS = frozenset(
    {
        "index",
        "main",
        "app",
        "core",
        "utils",
        "util",
        "helpers",
        "types",
        "page",
        "route",
        "layout",
        "lib",
        "api",
        "server",
        "client",
        "config",
        "constants",
        "common",
        "base",
        "models",
        "views",
    }
)


def _module_stem(path: str) -> str:
    pure = PurePosixPath(path)
    stem = pure.name.split(".")[0]
    if stem in {"__init__", "index"} and len(pure.parts) > 1:
        return pure.parts[-2]
    return stem


def _import_patterns(code_path: str):
    """(module stem, Python import patterns, JS import pattern) that find a
    test file importing ``code_path``."""
    stem = _module_stem(code_path)
    parts = list(PurePosixPath(code_path).with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    while parts and parts[0] in {"src", "lib"}:
        parts = parts[1:]
    python = []
    if parts:
        dotted = re.escape(".".join(parts))
        python.append(re.compile(rf"(?:from|import)\s+{dotted}\b"))
        parent = re.escape(".".join(parts[:-1]))
        if parent:
            python.append(
                re.compile(
                    rf"from\s+{parent}\s+import\s+[^\n]*\b{re.escape(parts[-1])}\b"
                )
            )
    js = re.compile(
        rf"""(?:from|require\(|import\(?)\s*["'][^"']*\b{re.escape(stem)}"""
        rf"""(?:\.[cm]?[jt]sx?)?(?:/index(?:\.[cm]?[jt]sx?)?)?["']"""
    )
    return stem, python, js
