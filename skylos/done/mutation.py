"""SKY-A120: the tests check the changed lines.

For each changed, executable line in non-test Python code, Skylos asks two
questions, using the test run the tests_pass check already made:

1. Does any test run this line? The run is traced, so each changed line is
   mapped to the tests that execute it. A line no test runs is unverified.
2. Does any test notice if the line is wrong? Skylos changes the line on
   purpose (one mutation, chosen by what the line does), reruns only the tests
   that run it, and checks that one of them fails. If they all still pass, no
   test checks that line.

The mutant is loaded in memory inside the test process (pytest_probe.py);
the working tree is never modified. Logging, imports, docstrings, type hints
and module-level code are skipped. At most MAX_MUTANTS mutants run, within
changed_lines_budget_seconds; lines past either limit are reported as not
checked, never as passing.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

import libcst as cst
from libcst.metadata import MetadataWrapper, PositionProvider

if TYPE_CHECKING:
    from skylos.done.checks import CheckContext, CheckResult

RULE_ID = "SKY-A120"
MAX_MUTANTS = 20
MAX_COVERING_TESTS = 300
_MIN_MUTANT_SECONDS = 5.0
_STARTUP_ALLOWANCE_SECONDS = 15.0

_TEST_DIRS = frozenset({"test", "tests", "testing"})
_LOGGER_NAMES = frozenset(
    {"logging", "logger", "log", "_log", "_logger", "LOGGER", "LOG", "warnings"}
)
_LOG_METHODS = frozenset(
    {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
)

# Lower is more informative: a flipped comparison says more than a dropped call.
P_COMPARE, P_BOOL, P_NEGATE, P_RETURN, P_INTEGER, P_ARITH, P_ARG, P_ASSIGN, P_CALL = (
    range(9)
)

_FLIPPED_OPERATORS = {
    cst.GreaterThan: (cst.GreaterThanEqual, ">", ">="),
    cst.GreaterThanEqual: (cst.GreaterThan, ">=", ">"),
    cst.LessThan: (cst.LessThanEqual, "<", "<="),
    cst.LessThanEqual: (cst.LessThan, "<=", "<"),
    cst.Equal: (cst.NotEqual, "==", "!="),
    cst.NotEqual: (cst.Equal, "!=", "=="),
    cst.In: (cst.NotIn, "in", "not in"),
    cst.NotIn: (cst.In, "not in", "in"),
    cst.Is: (cst.IsNot, "is", "is not"),
    cst.IsNot: (cst.Is, "is not", "is"),
}


@dataclass(frozen=True)
class TargetLine:
    path: str
    line: int  # first line of the statement or condition (what the trace sees)
    function: str = ""  # qualified name of the enclosing function
    changed: tuple[int, ...] = ()  # the lines of this statement the change touched

    @property
    def shown_line(self) -> int:
        return self.changed[0] if self.changed else self.line


@dataclass(frozen=True)
class Mutant:
    path: str
    line: int
    description: str  # "changes `>` to `>=`"
    source: str  # the whole mutated file
    priority: int


# ---------------------------------------------------------------------------
# Which lines
# ---------------------------------------------------------------------------


def is_test_path(path: str, test_paths: set[str]) -> bool:
    pure = PurePosixPath(path)
    name = pure.name
    return (
        path in test_paths
        or name == "conftest.py"
        or name in {"test.py", "tests.py"}
        or name.startswith("test_")
        or name.endswith("_test.py")
        or any(part in _TEST_DIRS for part in pure.parts[:-1])
    )


def select_targets(comparison, test_paths: set[str]) -> list[TargetLine]:
    """Changed lines in non-test Python files, anchored to their statement."""
    targets: list[TargetLine] = []
    for changed in comparison.changed:
        path = changed.head_path
        if not path or not path.endswith(".py") or is_test_path(path, test_paths):
            continue
        if "migrations" in PurePosixPath(path).parts:
            continue  # generated schema migrations
        added = comparison.added_lines(changed)
        if not added:
            continue
        source = comparison.head_text(path)
        if source is None:
            continue
        units = statement_units(source)
        chosen: dict[int, tuple[str, list[int]]] = {}
        for line in sorted(added):
            unit = _innermost(units, line)
            if unit is not None:
                chosen.setdefault(unit.start, (unit.function, []))[1].append(line)
        targets += [
            TargetLine(path, start, function, (line,))
            for start, (function, lines) in sorted(chosen.items())
            for line in lines
        ]
    return targets


@dataclass(frozen=True)
class _Unit:
    start: int
    end: int
    node: cst.CSTNode  # a SimpleStatementLine, or the test of an if/while
    kind: str  # "simple" or "condition"
    function: str = ""


def statement_units(source: str) -> list[_Unit]:
    """Checkable statements inside functions, with their line ranges."""
    try:
        wrapper = MetadataWrapper(cst.parse_module(source))
    except (cst.ParserSyntaxError, RecursionError, ValueError):
        return []
    collector = _UnitCollector()
    wrapper.visit(collector)
    return collector.units


def _innermost(units: list[_Unit], line: int) -> _Unit | None:
    containing = [u for u in units if u.start <= line <= u.end]
    if not containing:
        return None
    return min(containing, key=lambda u: (u.end - u.start, -u.start))


class _UnitCollector(cst.CSTVisitor):
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self) -> None:
        super().__init__()
        self.units: list[_Unit] = []
        self.depth = 0  # function nesting
        self.names: list[str] = []  # enclosing classes and functions

    def visit_ClassDef(self, node: cst.ClassDef) -> None:
        self.names.append(node.name.value)

    def leave_ClassDef(self, original_node: cst.ClassDef) -> None:
        self.names.pop()

    def visit_FunctionDef(self, node: cst.FunctionDef) -> None:
        self.depth += 1
        self.names.append(node.name.value)

    def leave_FunctionDef(self, original_node: cst.FunctionDef) -> None:
        self.depth -= 1
        self.names.pop()

    def visit_SimpleStatementLine(self, node: cst.SimpleStatementLine) -> None:
        if self.depth and not _skippable_line(node):
            position = self.get_metadata(PositionProvider, node)
            self.units.append(
                _Unit(
                    position.start.line,
                    position.end.line,
                    node,
                    "simple",
                    ".".join(self.names),
                )
            )

    def _condition(self, node: cst.If | cst.While) -> None:
        if not self.depth or _skippable_condition(node.test):
            return
        start = self.get_metadata(PositionProvider, node).start.line
        end = self.get_metadata(PositionProvider, node.test).end.line
        self.units.append(
            _Unit(start, end, node.test, "condition", ".".join(self.names))
        )

    def visit_If(self, node: cst.If) -> None:
        self._condition(node)

    def visit_While(self, node: cst.While) -> None:
        self._condition(node)


def _dotted(node: cst.BaseExpression) -> tuple[str, ...]:
    parts: list[str] = []
    while isinstance(node, cst.Attribute):
        parts.append(node.attr.value)
        node = node.value
    if isinstance(node, cst.Name):
        parts.append(node.value)
        return tuple(reversed(parts))
    if isinstance(node, cst.Call):
        return _dotted(node.func) + tuple(reversed(parts))
    return ()


def _is_logging_call(node: cst.BaseExpression) -> bool:
    if not isinstance(node, cst.Call):
        return False
    name = _dotted(node.func)
    if not name:
        return False
    if name == ("print",):
        return True
    if name[0] in _LOGGER_NAMES or (len(name) >= 2 and name[-2] in _LOGGER_NAMES):
        return True
    return len(name) >= 2 and name[-1] in _LOG_METHODS and "log" in name[-2].lower()


def _skippable_small(statement: cst.BaseSmallStatement) -> bool:
    if isinstance(
        statement,
        (
            cst.Import,
            cst.ImportFrom,
            cst.Pass,
            cst.Global,
            cst.Nonlocal,
            cst.Break,
            cst.Continue,
        ),
    ):
        return True
    if isinstance(statement, cst.Expr):
        value = statement.value
        if isinstance(
            value,
            (
                cst.SimpleString,
                cst.ConcatenatedString,
                cst.FormattedString,
                cst.Ellipsis,
            ),
        ):
            return True  # docstrings and stub bodies
        return _is_logging_call(value)
    if isinstance(statement, cst.AnnAssign) and statement.value is None:
        return True  # a type hint
    if isinstance(statement, cst.Raise) and statement.exc is not None:
        return _dotted(statement.exc)[-1:] == ("NotImplementedError",)
    return False


def _skippable_line(node: cst.SimpleStatementLine) -> bool:
    return all(_skippable_small(statement) for statement in node.body)


def _skippable_condition(test: cst.BaseExpression) -> bool:
    if isinstance(test, cst.Name) and test.value == "TYPE_CHECKING":
        return True
    if _dotted(test)[-1:] == ("TYPE_CHECKING",):
        return True
    return (
        isinstance(test, cst.Comparison)
        and isinstance(test.left, cst.Name)
        and test.left.value == "__name__"
    )


# ---------------------------------------------------------------------------
# Mutations
# ---------------------------------------------------------------------------


def make_mutant(
    path: str, source: str, line: int, changed: tuple[int, ...] | None = None
) -> Mutant | None:
    """One mutation of the statement starting on ``line``, or None.

    Only code on ``changed`` lines is mutated (default: the statement's first
    line): a multi-line statement may hold unchanged code, and a finding about
    it would not be about this change.
    """
    try:
        wrapper = MetadataWrapper(cst.parse_module(source))
    except (cst.ParserSyntaxError, RecursionError, ValueError):
        return None
    collector = _UnitCollector()
    wrapper.visit(collector)
    unit = next((u for u in collector.units if u.start == line), None)
    if unit is None:
        return None
    positions = wrapper.resolve(PositionProvider)
    allowed = set(changed or (line,))
    candidates = [
        c
        for c in _candidates(unit)
        if c[1] in positions and positions[c[1]].start.line in allowed
    ]
    if not candidates:
        return None
    priority, old, new, description = min(candidates, key=lambda c: c[0])
    mutated = wrapper.module.deep_replace(old, new)
    code = mutated.code if isinstance(mutated, cst.Module) else None
    if not code or code == source:
        return None
    try:
        compile(code, path, "exec", dont_inherit=True)
    except (SyntaxError, ValueError):
        return None
    return Mutant(path, positions[old].start.line, description, code, priority)


def _candidates(unit: _Unit) -> list[tuple[int, cst.CSTNode, cst.CSTNode, str]]:
    found: list[tuple[int, cst.CSTNode, cst.CSTNode, str]] = []
    if unit.kind == "condition":
        _expression_candidates(unit.node, found)
        if not any(c[0] in (P_COMPARE, P_BOOL) for c in found):
            found.append(
                (P_NEGATE, unit.node, _negated(unit.node), "negates the condition")
            )
        return found
    for statement in unit.node.body:
        if _skippable_small(statement):
            continue
        if isinstance(statement, cst.Return) and statement.value is not None:
            _expression_candidates(statement.value, found)
            replacement = _return_default(statement.value)
            if replacement is not None:
                new_value, text = replacement
                found.append((P_RETURN, statement.value, new_value, text))
        elif isinstance(statement, cst.Assert):
            _expression_candidates(statement.test, found)
            if not any(c[0] in (P_COMPARE, P_BOOL) for c in found):
                found.append(
                    (
                        P_NEGATE,
                        statement.test,
                        _negated(statement.test),
                        "negates the assertion",
                    )
                )
        elif isinstance(statement, cst.AugAssign):
            _expression_candidates(statement.value, found)
            swapped = {
                cst.AddAssign: (cst.SubtractAssign, "+=", "-="),
                cst.SubtractAssign: (cst.AddAssign, "-=", "+="),
            }
            entry = swapped.get(type(statement.operator))
            if entry:
                new_type, before, after = entry
                found.append(
                    (
                        P_ARITH,
                        statement.operator,
                        _same_spacing(statement.operator, new_type),
                        f"changes `{before}` to `{after}`",
                    )
                )
        elif (
            isinstance(statement, (cst.Assign, cst.AnnAssign))
            and statement.value is not None
        ):
            _expression_candidates(statement.value, found)
            if not (
                isinstance(statement.value, cst.Name)
                and statement.value.value == "None"
            ):
                found.append(
                    (
                        P_ASSIGN,
                        statement.value,
                        cst.Name("None"),
                        "assigns None instead",
                    )
                )
        elif isinstance(statement, cst.Expr):
            _expression_candidates(statement.value, found)
            if isinstance(statement.value, cst.Call):
                name = ".".join(_dotted(statement.value.func)) or "the function"
                found.append(
                    (P_CALL, statement, cst.Pass(), f"removes the call to `{name}()`")
                )
        elif isinstance(statement, cst.Raise) and statement.exc is not None:
            # The exception's own arguments are messages: only decisions in
            # the expression (a conditional raise) are worth mutating.
            _expression_candidates(statement.exc, found)
            found[:] = [c for c in found if c[0] != P_ARG]
    return found


def _expression_candidates(node: cst.CSTNode, found: list) -> None:
    """Comparison, boolean, integer and arithmetic mutations inside ``node``."""
    stack = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, (cst.Lambda, cst.FunctionDef)):
            continue
        if isinstance(current, cst.Comparison) and current.comparisons:
            first = current.comparisons[0]
            entry = _FLIPPED_OPERATORS.get(type(first.operator))
            if entry:
                new_type, before, after = entry
                new_first = first.with_changes(
                    operator=_same_spacing(first.operator, new_type)
                )
                found.append(
                    (
                        P_COMPARE,
                        current,
                        current.with_changes(
                            comparisons=[new_first, *current.comparisons[1:]]
                        ),
                        f"changes `{before}` to `{after}`",
                    )
                )
        elif isinstance(current, cst.BooleanOperation):
            if isinstance(current.operator, cst.And):
                new_op, text = (
                    _same_spacing(current.operator, cst.Or),
                    "changes `and` to `or`",
                )
            else:
                new_op, text = (
                    _same_spacing(current.operator, cst.And),
                    "changes `or` to `and`",
                )
            found.append((P_BOOL, current, current.with_changes(operator=new_op), text))
        elif isinstance(current, cst.Integer):
            try:
                value = int(current.value.replace("_", ""), 0)
            except ValueError:
                value = None
            if value is not None:
                found.append(
                    (
                        P_INTEGER,
                        current,
                        cst.Integer(str(value + 1)),
                        f"changes {value} to {value + 1}",
                    )
                )
        elif isinstance(current, cst.Call):
            name = ".".join(_dotted(current.func)) or "the call"
            for position, argument in enumerate(current.args, 1):
                # Text arguments are usually messages and labels; dropping
                # one says little about what the code does.
                if argument.star or isinstance(
                    argument.value,
                    (cst.SimpleString, cst.ConcatenatedString, cst.FormattedString),
                ):
                    continue
                if (
                    isinstance(argument.value, cst.Name)
                    and argument.value.value == "None"
                ):
                    continue
                label = (
                    f"`{argument.keyword.value}`"
                    if argument.keyword
                    else f"argument {position} of `{name}()`"
                )
                found.append(
                    (P_ARG, argument.value, cst.Name("None"), f"passes None as {label}")
                )
        elif isinstance(current, cst.BinaryOperation):
            swapped = {
                cst.Add: (cst.Subtract, "+", "-"),
                cst.Subtract: (cst.Add, "-", "+"),
            }
            entry = swapped.get(type(current.operator))
            if entry:
                new_type, before, after = entry
                found.append(
                    (
                        P_ARITH,
                        current,
                        current.with_changes(
                            operator=_same_spacing(current.operator, new_type)
                        ),
                        f"changes `{before}` to `{after}`",
                    )
                )
        stack.extend(reversed(list(current.children)))


def _same_spacing(old: cst.CSTNode, new_type: type) -> cst.CSTNode:
    kwargs = {}
    for name in ("whitespace_before", "whitespace_after"):
        if hasattr(old, name):
            kwargs[name] = getattr(old, name)
    return new_type(**kwargs)


def _negated(test: cst.BaseExpression) -> cst.BaseExpression:
    if isinstance(test, cst.UnaryOperation) and isinstance(test.operator, cst.Not):
        return test.expression
    wrapped = (
        test
        if test.lpar
        else test.with_changes(lpar=[cst.LeftParen()], rpar=[cst.RightParen()])
    )
    return cst.UnaryOperation(operator=cst.Not(), expression=wrapped)


def _return_default(value: cst.BaseExpression) -> tuple[cst.BaseExpression, str] | None:
    if isinstance(value, cst.Name):
        if value.value == "True":
            return cst.Name("False"), "returns False instead of True"
        if value.value == "False":
            return cst.Name("True"), "returns True instead of False"
        if value.value == "None":
            return None
    if isinstance(value, cst.Integer):
        return (
            (cst.Integer("1"), "returns 1 instead of 0")
            if value.value == "0"
            else (
                cst.Integer("0"),
                f"returns 0 instead of {value.value}",
            )
        )
    if isinstance(value, cst.SimpleString) and value.evaluated_value:
        return cst.SimpleString('""'), "returns an empty string instead"
    return cst.Name("None"), "returns None instead"


# ---------------------------------------------------------------------------
# The check
# ---------------------------------------------------------------------------


@dataclass
class _Tally:
    targets: int = 0
    uncovered: int = 0
    mutants: int = 0
    killed: int = 0
    survived: int = 0
    not_checked: int = 0
    covered_only: int = 0
    unverified: list[tuple[str, int]] = field(default_factory=list)


def check_changed_lines(ctx: CheckContext) -> CheckResult:
    from skylos.done.checks import CheckResult, Finding

    def skipped(reason: str) -> CheckResult:
        return CheckResult(
            id="changed_lines_checked",
            rule=RULE_ID,
            status="skipped",
            summary=reason,
            evidence={"summary": reason[:120]},
        )

    if not ctx.run_tests:
        return skipped("Tests not run (--no-tests)")
    run = ctx.test_run
    if run is None:
        return skipped("Needs the tests_pass check, which did not run")
    # The line map is sound whenever the run finished and every test passed;
    # tests_pass may still be unfinished for bookkeeping reasons (for example
    # parameter cases it cannot count), which do not affect which lines ran.
    if run.failures or not run.run or run.status == "skipped":
        return skipped(
            "The tests must run and pass before Skylos checks them against changed lines"
        )
    if not run.pytest:
        return skipped("Needs pytest: other test commands cannot be traced yet")
    targets = ctx.change_targets()
    if not targets:
        summary = "No changed lines in non-test Python code to check"
        return CheckResult(
            id="changed_lines_checked",
            rule=RULE_ID,
            status="pass",
            summary=summary,
            evidence={"changed_lines": 0, "summary": summary},
        )
    trace = run.trace or {}
    if run.line_map is None or not trace.get("ok"):
        summary = f"Could not map lines to tests: {trace.get('reason') or 'no trace'}"
        return CheckResult(
            id="changed_lines_checked",
            rule=RULE_ID,
            status="incomplete",
            summary=summary,
            evidence={
                "changed_lines": len(targets),
                "not_checked": len(targets),
                "summary": summary[:120],
            },
            unverified=sorted({(target.path, target.shown_line) for target in targets}),
        )

    tally = _Tally(targets=len(targets))
    findings = []
    candidates: list[tuple[TargetLine, set[str]]] = []
    shadowed = trace.get("shadowed") or {}
    not_run: dict[tuple[str, str], list[int]] = {}
    for target in targets:
        covering = run.line_map.get((target.path, target.line), set())
        if target.path in shadowed:
            tally.not_checked += 1
            tally.unverified.append((target.path, target.shown_line))
        elif covering:
            candidates.append((target, covering))
        elif (target.path, target.line) in run.import_lines:
            tally.not_checked += 1  # only ran while modules were imported
            tally.unverified.append((target.path, target.shown_line))
        else:
            tally.uncovered += 1
            tally.unverified.append((target.path, target.shown_line))
            not_run.setdefault((target.path, target.function), []).append(
                target.shown_line
            )
    # One finding per function: an untested function is one gap, not ten.
    for (path, function), lines in not_run.items():
        inside = f" (in `{function}`)" if function else ""
        findings.append(
            Finding(
                RULE_ID,
                path,
                lines[0],
                f"No test runs {path}:{_line_ranges(lines)}{inside}. "
                "Add a test that does.",
            )
        )

    deadline = time.monotonic() + ctx.config.changed_lines_budget_seconds
    sources: dict[str, str | None] = {}
    mutants: list[tuple[Mutant, set[str]]] = []
    for target, covering in candidates:
        if target.path not in sources:
            sources[target.path] = ctx.comparison.head_text(target.path)
        source = sources[target.path]
        mutant = (
            make_mutant(target.path, source, target.line, target.changed)
            if source
            else None
        )
        if mutant is None:
            tally.covered_only += 1  # runs under test; no mutation applies
            tally.not_checked += 1
            tally.unverified.append((target.path, target.shown_line))
        else:
            mutants.append((mutant, covering))

    for index, (mutant, covering) in enumerate(_spread(mutants)):
        remaining = deadline - time.monotonic()
        if index >= MAX_MUTANTS or remaining < _MIN_MUTANT_SECONDS:
            tally.not_checked += 1
            tally.unverified.append((mutant.path, mutant.line))
            continue
        if len(covering) > MAX_COVERING_TESTS:
            tally.not_checked += 1
            tally.unverified.append((mutant.path, mutant.line))
            continue
        from skylos.done.runner import run_mutant

        normal = sum(run.node_seconds.get(node, 0.0) for node in covering)
        outcome = run_mutant(
            ctx.comparison,
            ctx.config,
            node_ids=sorted(covering),
            path=mutant.path,
            source=mutant.source,
            timeout=min(remaining, 2 * normal + _STARTUP_ALLOWANCE_SECONDS),
        )
        tally.mutants += 1
        if outcome.outcome == "killed":
            tally.killed += 1
        elif outcome.outcome == "survived":
            tally.survived += 1
            tally.unverified.append((mutant.path, mutant.line))
            findings.append(
                Finding(
                    RULE_ID,
                    mutant.path,
                    mutant.line,
                    f"No test fails if {mutant.path}:{mutant.line} {mutant.description}. "
                    "Add an assertion that would.",
                )
            )
        else:
            tally.not_checked += 1
            tally.unverified.append((mutant.path, mutant.line))

    if findings:
        status = "fail"
    elif tally.not_checked:
        status = "incomplete"
    else:
        status = "pass"
    unchecked = tally.uncovered + tally.survived
    summary = (
        f"{unchecked} of {tally.targets} changed lines are not checked by any test"
        if unchecked
        else f"Tests checked {tally.killed} of {tally.targets} changed lines"
        if tally.not_checked
        else f"Tests check all {tally.targets} changed lines"
    )
    if tally.not_checked:
        summary += f" ({tally.not_checked} could not be checked)"
    findings.sort(key=lambda f: (f.file or "", f.line or 0))
    result = CheckResult(
        id="changed_lines_checked",
        rule=RULE_ID,
        status=status,
        summary=summary,
        evidence={
            "changed_lines": tally.targets,
            "not_run_by_tests": tally.uncovered,
            "mutants": tally.mutants,
            "caught": tally.killed,
            "missed": tally.survived,
            "not_checked": tally.not_checked,
            "covered_only": tally.covered_only,
            "summary": summary[:120],
        },
        findings=findings,
    )
    result.unverified = sorted(set(tally.unverified))
    return result


def _line_ranges(lines: list[int]) -> str:
    """[25, 26, 27, 31] -> "25-27, 31" (statement start lines, in order)."""
    ordered = sorted(set(lines))
    parts = []
    start = previous = ordered[0]
    for line in ordered[1:]:
        if line != previous + 1:
            parts.append(str(start) if start == previous else f"{start}-{previous}")
            start = line
        previous = line
    parts.append(str(start) if start == previous else f"{start}-{previous}")
    return ", ".join(parts)


def _spread(mutants: list[tuple[Mutant, set[str]]]) -> list[tuple[Mutant, set[str]]]:
    """Most informative mutations first, taking turns across files."""
    by_file: dict[str, list[tuple[Mutant, set[str]]]] = {}
    for item in sorted(mutants, key=lambda m: (m[0].priority, m[0].path, m[0].line)):
        by_file.setdefault(item[0].path, []).append(item)
    ordered = []
    queues = [by_file[path] for path in sorted(by_file)]
    while any(queues):
        for queue in queues:
            if queue:
                ordered.append(queue.pop(0))
    return ordered
