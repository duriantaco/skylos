"""The checks ``skylos done`` runs, one function per check id.

Each check returns a status (pass, fail, incomplete or skipped), up to 12
scalar evidence values and findings. A finding marked ``blocking=False`` is
shown but never decides the status: it is advice inside a blocking check.
"""

from __future__ import annotations

import ast
import fnmatch
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from skylos.done.base import Comparison, DoneError, _git_text
from skylos.done.config import DoneConfig
from skylos.done.inventory import (
    TestItem,
    collect_tests,
    compare_inventories,
    is_pytest_file,
)

if TYPE_CHECKING:
    from skylos.done.runner import TestRunResult

logger = logging.getLogger(__name__)

RULE_DELETED_TEST = "SKY-A110"
RULE_SKIPPED_TEST = "SKY-A111"
RULE_TEST_CONFIG = "SKY-A112"
RULE_TESTS_PASS = "SKY-A113"
RULE_GATE_TAMPERING = "SKY-A114"
RULE_ASSERTION_WEAKENING = "SKY-A101"


@dataclass
class Finding:
    rule: str | None
    file: str | None
    line: int | None
    message: str
    blocking: bool = True


@dataclass
class CheckResult:
    id: str
    rule: str | None
    status: str  # "pass", "fail", "incomplete" or "skipped"
    summary: str
    evidence: dict[str, str | int | float | bool] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    # Changed lines no test checks (file, line): the receipt's "unverified".
    unverified: list[tuple[str, int]] = field(default_factory=list)


@dataclass
class CheckContext:
    comparison: Comparison
    config: DoneConfig
    run_tests: bool = True
    deadline: float | None = None
    _tests: tuple[list[TestItem], list[TestItem]] | None = None
    # The tests_pass run, reused by the changed-lines check.
    test_run: TestRunResult | None = None
    _targets: list | None = None

    def change_targets(self) -> list:
        """Changed lines in non-test Python code that the tests should check."""
        if self._targets is None:
            from skylos.done.mutation import select_targets

            _, head = self.tests()
            self._targets = select_targets(self.comparison, {t.path for t in head})
        return self._targets

    def tests(self) -> tuple[list[TestItem], list[TestItem]]:
        """Complete static Python test inventories, including unchanged files.

        Production code, plugins and helper changes can suppress existing
        tests without editing their definitions.
        """
        if self._tests is None:
            from skylos.done.runner import _is_pytest
            from skylos.done.test_config import base_excluded_tests

            base: list[TestItem] = []
            head: list[TestItem] = []
            base_paths = _git_text(
                self.comparison._context,
                "ls-tree",
                "-r",
                "--name-only",
                "-z",
                self.comparison.base_sha,
            )
            head_paths = _git_text(
                self.comparison._context,
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            )
            if base_paths is None or head_paths is None:
                raise DoneError("could not inventory the repository's tests")
            removed_head_paths = {
                item.base_path
                for item in self.comparison.changed
                if item.status in {"deleted", "renamed"}
            }
            argv = self.config.test_command or ("pytest",)
            for paths, destination, read in (
                (base_paths, base, self.comparison.base_text),
                (head_paths, head, self.comparison.head_text),
            ):
                python_paths = sorted(
                    {path for path in paths.split("\0") if path.endswith(".py")}
                )
                if len(python_paths) > 10000:
                    raise DoneError("the Python test inventory exceeds 10000 files")
                for path in python_paths:
                    if destination is head and path in removed_head_paths:
                        continue
                    candidate = is_pytest_file(path) or PurePosixPath(path).name in {
                        "test.py",
                        "tests.py",
                    }
                    source = read(path)
                    try:
                        destination.extend(
                            collect_tests(path, source, strict=candidate)
                        )
                    except ValueError as exc:
                        opaque = TestItem(
                            path, (), "test_inventory", 1, "", "", unittest_style=True
                        )
                        excluded = (
                            base_excluded_tests(
                                self.comparison,
                                [opaque],
                                argv,
                                base_tests=[],
                                file_only=True,
                            )
                            if _is_pytest(argv)
                            else set()
                        )
                        if opaque.id not in excluded:
                            raise DoneError(f"Cannot inventory {path}: {exc}") from None
            self._tests = (base, head)
        return self._tests


def _status(findings: list[Finding]) -> str:
    return "fail" if any(f.blocking for f in findings) else "pass"


# ---------------------------------------------------------------------------
# test_tampering: A110 deleted, A111 skipped, A112 loosened config, A101 advice
# ---------------------------------------------------------------------------


def check_test_tampering(ctx: CheckContext) -> CheckResult:
    from skylos.done.test_config import detect_loosened_test_config

    comparison = ctx.comparison
    base_tests, head_tests = ctx.tests()
    renamed = {
        c.base_path: c.path
        for c in comparison.changed
        if c.status == "renamed" and c.base_path
    }
    diff = compare_inventories(base_tests, head_tests, renamed)
    removed_modules = _removed_modules(comparison)
    findings: list[Finding] = []

    for deleted in diff.deleted:
        test = deleted.test
        if _tests_removed_feature(comparison, test, removed_modules):
            findings.append(
                Finding(
                    RULE_DELETED_TEST,
                    test.path,
                    test.line,
                    f"{test.local_id} was deleted together with the module it imports "
                    "(feature removal)",
                    blocking=False,
                )
            )
            continue
        findings.append(
            Finding(
                RULE_DELETED_TEST,
                test.path,
                test.line,
                f"{test.local_id} was deleted; no test with the same body exists now",
            )
        )
    for dropped in diff.dropped_cases:
        findings.append(
            Finding(
                RULE_DELETED_TEST,
                dropped.test.path,
                dropped.test.line,
                f"{dropped.test.local_id} went from {dropped.before} to "
                f"{dropped.after} parametrize cases",
            )
        )
    for skipped in diff.newly_skipped:
        findings.append(
            Finding(
                RULE_SKIPPED_TEST,
                skipped.test.path,
                skipped.test.line,
                f"{skipped.test.local_id} now skips or expects failure "
                f"({', '.join(sorted(skipped.added))})",
            )
        )
    config_findings = detect_loosened_test_config(comparison)
    for item in config_findings:
        findings.append(Finding(RULE_TEST_CONFIG, item.file, item.line, item.message))

    weakened = _assertion_weakening(comparison, base_tests, head_tests, renamed)
    findings += weakened

    blocking = [f for f in findings if f.blocking]
    status = _status(findings)
    summary = (
        f"{len(blocking)} test change(s) weaken what the tests check"
        if blocking
        else f"No tests deleted, skipped or loosened ({len(base_tests)} compared)"
    )
    return CheckResult(
        id="test_tampering",
        rule=next((f.rule for f in findings if f.blocking), RULE_DELETED_TEST),
        status=status,
        summary=summary,
        evidence={
            "tests_compared": len(base_tests),
            "deleted": sum(
                f.rule == RULE_DELETED_TEST and f.blocking for f in findings
            ),
            "skipped": len(diff.newly_skipped),
            "config_loosened": len(config_findings),
            "weakened_advice": len(weakened),
            "summary": summary[:120],
        },
        findings=findings,
    )


def _removed_modules(comparison: Comparison) -> set[str]:
    modules = set()
    for item in comparison.changed:
        if (
            item.status == "deleted"
            and item.base_path
            and item.base_path.endswith(".py")
        ):
            path = PurePosixPath(item.base_path)
            if (
                is_pytest_file(item.base_path)
                or path.name in {"conftest.py", "tests.py"}
                or {"test", "tests"}.intersection(path.parts[:-1])
                or collect_tests(item.base_path, comparison.base_text(item.base_path))
            ):
                continue
            parts = path.with_suffix("").parts
            if parts and parts[-1] == "__init__":
                parts = parts[:-1]
            if parts:
                modules.add(".".join(parts))
    return modules


def _tests_removed_feature(
    comparison: Comparison, test: TestItem, removed_modules: set[str]
) -> bool:
    """A deleted test must itself reference a deleted production module.

    Imports elsewhere in its file and renamed modules do not prove that the
    feature tested here disappeared.
    """
    if not removed_modules:
        return False
    source = comparison.base_text(test.path)
    try:
        tree = ast.parse(source or "")
    except (SyntaxError, ValueError):
        return False
    function = next(
        (
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.lineno == test.line
            and node.name == test.name
        ),
        None,
    )
    if function is None:
        return False
    bindings = _import_bindings(tree.body)
    shadowed = {
        node.id
        for node in ast.walk(function)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
    }
    shadowed.update(
        argument.arg
        for argument in ast.walk(function.args)
        if isinstance(argument, ast.arg)
    )
    for name in shadowed:
        bindings.pop(name, None)
    bindings.update(_import_bindings(ast.walk(function)))
    for node in ast.walk(function):
        if not isinstance(node, (ast.Name, ast.Attribute)) or not isinstance(
            node.ctx, ast.Load
        ):
            continue
        parts = _reference_parts(node)
        if not parts or parts[0] not in bindings:
            continue
        name = ".".join((bindings[parts[0]], *parts[1:]))
        # A src/ package root may not be part of the imported dotted name.
        prefixes = [
            ".".join(name.split(".")[:index])
            for index in range(1, len(name.split(".")) + 1)
        ]
        if any(
            removed == prefix or removed.endswith("." + prefix)
            for removed in removed_modules
            for prefix in prefixes
        ):
            return True
    return False


def _import_bindings(nodes) -> dict[str, str]:
    bindings = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                bindings[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                if alias.name != "*":
                    bindings[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return bindings


def _reference_parts(node: ast.AST) -> tuple[str, ...]:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ()
    return (node.id, *reversed(parts))


def _assertion_weakening(
    comparison: Comparison,
    base_tests: list[TestItem],
    head_tests: list[TestItem],
    renamed: dict[str, str],
) -> list[Finding]:
    from skylos.rules.ai_defect.assertion_weakening import detect_assertion_weakening

    test_files = {t.path for t in head_tests}
    base_ids = {
        "::".join((renamed.get(t.path, t.path), *t.classes, t.name)) for t in base_tests
    }
    # Tests written in this change may do anything, skips included.
    new_test_ranges: dict[str, list[tuple[int, int]]] = {}
    for test in head_tests:
        if test.id not in base_ids:
            new_test_ranges.setdefault(test.path, []).append((test.line, test.end_line))
    findings = []
    for changed in comparison.changed:
        if changed.status == "deleted" or changed.path not in test_files:
            continue
        try:
            raw = detect_assertion_weakening(
                comparison.file_diff(changed), changed.path
            )
        except Exception:  # an advisory detector must never break the gate
            logger.debug(
                "assertion weakening failed for %s", changed.path, exc_info=True
            )
            continue
        in_strings = _string_literal_lines(comparison.head_text(changed.path))
        for item in raw:
            line = _int(item.get("line"))
            if line in in_strings:
                continue  # text inside a string literal, not test code
            if line is not None and any(
                start <= line <= end
                for start, end in new_test_ranges.get(changed.path, ())
            ):
                continue
            message = str(item.get("message") or "").removeprefix("AI defect: ")
            findings.append(
                Finding(
                    RULE_ASSERTION_WEAKENING,
                    changed.path,
                    line,
                    f"(advice) {message}",
                    blocking=False,
                )
            )
    return findings


def _string_literal_lines(source: str | None) -> set[int]:
    """Lines inside multi-line string literals (after their first line)."""
    if not source:
        return set()
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return set()
    lines: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.end_lineno
            and node.end_lineno > node.lineno
        ):
            lines.update(range(node.lineno + 1, node.end_lineno + 1))
    return lines


# ---------------------------------------------------------------------------
# tests_pass: A113
# ---------------------------------------------------------------------------


def check_tests_pass(ctx: CheckContext) -> CheckResult:
    from skylos.done.runner import run_tests

    if not ctx.run_tests:
        return CheckResult(
            id="tests_pass",
            rule=RULE_TESTS_PASS,
            status="skipped",
            summary="Tests not run (--no-tests)",
            evidence={"summary": "Tests not run (--no-tests)"},
        )
    base_tests, head_tests = ctx.tests()
    trace_targets = None
    if ctx.config.mode("changed_lines_checked") != "off":
        # Map the changed lines to the tests that run them in this same run.
        trace_targets = {}
        for target in ctx.change_targets():
            trace_targets.setdefault(target.path, []).append(target.line)
    result = run_tests(
        ctx.comparison,
        ctx.config,
        changed_tests=head_tests,
        base_tests=base_tests,
        deadline=ctx.deadline,
        trace_targets=trace_targets,
    )
    ctx.test_run = result
    findings = [
        Finding(
            RULE_TESTS_PASS,
            case.file,
            case.line,
            f"{case.node_id or case.name} failed"
            + (f": {case.message}" if case.message else ""),
        )
        for case in result.failures
    ]
    findings += [
        Finding(
            RULE_TESTS_PASS,
            case.file,
            case.line,
            f"{case.node_id or case.name} failed once and passed on a rerun (flaky)",
            blocking=False,
        )
        for case in result.flaky
    ]
    findings += [
        Finding(
            RULE_TESTS_PASS,
            test.path,
            test.line,
            f"{test.local_id} did not run although its file did",
        )
        for test in result.missing
    ]
    findings += [
        Finding(
            RULE_TESTS_PASS,
            path,
            None,
            "This test file reported no results without a proven base selection exclusion; restore its execution or configure an explicit selector at the base",
        )
        for path in result.silent_files
    ]
    if result.status == "pass" and result.run:
        summary = f"{result.run} tests run by Skylos, {result.passed} passed ({result.seconds:.0f} s)"
        if result.flaky:
            summary += f", {len(result.flaky)} flaky"
    else:
        summary = result.reason[0].upper() + result.reason[1:] if result.reason else ""
    findings += [
        Finding(
            RULE_TESTS_PASS,
            test.path,
            test.line,
            f"{test.local_id} reported {after} of {before} literal parameter cases; remaining cases lack proven base exclusions",
        )
        for test, before, after in result.missing_cases
    ]
    findings += [
        Finding(
            RULE_TESTS_PASS,
            test.path,
            test.line,
            f"{test.local_id} has a computed parameter case total that cannot be independently inventoried; use literal case lists or simple local constants",
        )
        for test in result.unknown_cases
    ]
    evidence: dict[str, str | int | float | bool] = {
        "run": result.run,
        "passed": result.passed,
        "failed": len(result.failures),
        "skipped": result.skipped,
        "flaky": len(result.flaky),
        "not_run": len(result.missing)
        + sum(before - after for _, before, after in result.missing_cases),
        "unknown_case_totals": len(result.unknown_cases),
        "seconds": result.seconds,
        "summary": summary[:120],
    }
    if result.command:
        evidence["command"] = result.command[:120]
        evidence["auto_command"] = result.auto_command
    return CheckResult(
        id="tests_pass",
        rule=RULE_TESTS_PASS,
        status=result.status,
        summary=summary,
        evidence=evidence,
        findings=findings,
    )


# ---------------------------------------------------------------------------
# gate_tampering: A114
# ---------------------------------------------------------------------------


def check_gate_tampering(ctx: CheckContext) -> CheckResult:
    comparison = ctx.comparison
    findings: list[Finding] = []
    for changed in comparison.changed:
        for path in dict.fromkeys(p for p in (changed.base_path, changed.path) if p):
            pattern = _protected_match(path, ctx.config.protected_paths)
            if pattern:
                findings.append(
                    Finding(
                        RULE_GATE_TAMPERING,
                        path,
                        None,
                        f"changes {path}, which is protected ({pattern} in protected_paths)",
                    )
                )
                break
        name = PurePosixPath(changed.path).name
        if name == "pyproject.toml" and changed.head_path:
            before = _skylos_table(comparison.base_text(changed.base_path))
            after = _skylos_table(comparison.head_text(changed.head_path))
            if before != after:
                findings.append(
                    Finding(
                        RULE_GATE_TAMPERING,
                        changed.path,
                        _line_of(
                            comparison.head_text(changed.head_path), "[tool.skylos"
                        ),
                        "changes Skylos settings ([tool.skylos])",
                    )
                )
        if _is_workflow(changed.base_path or ""):
            base_text = comparison.base_text(changed.base_path) or ""
            if "skylos" in base_text.lower():
                findings.append(
                    Finding(
                        RULE_GATE_TAMPERING,
                        changed.base_path,
                        None,
                        "changes the CI workflow that runs Skylos",
                    )
                )
    summary = (
        f"{len(findings)} change(s) to Skylos settings or hooks"
        if findings
        else "Skylos settings, hooks and protected paths unchanged"
    )
    return CheckResult(
        id="gate_tampering",
        rule=RULE_GATE_TAMPERING,
        status=_status(findings),
        summary=summary,
        evidence={
            "protected_paths": len(ctx.config.protected_paths),
            "summary": summary[:120],
        },
        findings=findings,
    )


def _protected_match(path: str, patterns: tuple[str, ...]) -> str | None:
    for pattern in patterns:
        if pattern.endswith("/"):
            if path.startswith(pattern):
                return pattern
        elif any(ch in pattern for ch in "*?["):
            if fnmatch.fnmatchcase(path, pattern):
                return pattern
        elif path == pattern or path.startswith(pattern + "/"):
            return pattern
    return None


def _skylos_table(text: str | None):
    from skylos.done.test_config import _toml

    data = _toml(text) or {}
    tool = data.get("tool") if isinstance(data.get("tool"), dict) else {}
    return tool.get("skylos")


def _is_workflow(path: str) -> bool:
    return path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))


# ---------------------------------------------------------------------------
# secrets
# ---------------------------------------------------------------------------


def check_secrets(ctx: CheckContext) -> CheckResult:
    from skylos.rules.secrets import IGNORE_DIRECTIVE, scan_ctx

    comparison = ctx.comparison
    findings: list[Finding] = []
    scanned = 0
    for changed in comparison.changed:
        if changed.head_path is None:
            continue
        added = comparison.added_lines(changed)
        if not added:
            continue
        text = comparison.head_text(changed.head_path)
        if text is None:
            continue
        scanned += 1
        lines = text.splitlines(True)
        # Suppression comments written in this change do not count: the
        # change under review cannot excuse itself.
        raw = scan_ctx(
            {
                "relpath": changed.path,
                "lines": lines,
                "tree": None,
                "honor_inline_ignores": False,
            },
            ignore_tests=False,
        )
        seen = set()
        for item in raw:
            line = _int(item.get("line"))
            # One finding per line: a token matched by a provider pattern is
            # often matched by the generic high-entropy pattern too.
            if line is None or line not in added or line in seen:
                continue
            seen.add(line)
            provider = str(item.get("provider") or "secret").replace("_", " ")
            suppressed = (
                IGNORE_DIRECTIVE in lines[line - 1] if line <= len(lines) else False
            )
            findings.append(
                Finding(
                    str(item.get("rule_id") or "SKY-S101"),
                    changed.path,
                    line,
                    f"Hard-coded {provider} secret added"
                    + (
                        " (a suppression comment added in this change does not count)"
                        if suppressed
                        else ""
                    ),
                )
            )
    summary = f"{len(findings)} secret(s) added" if findings else "No secrets added"
    return CheckResult(
        id="secrets",
        rule="SKY-S101",
        status=_status(findings),
        summary=summary,
        evidence={
            "files_scanned": scanned,
            "secrets": len(findings),
            "summary": summary,
        },
        findings=findings,
    )


# ---------------------------------------------------------------------------
# unknown_imports
# ---------------------------------------------------------------------------


def check_unknown_imports(ctx: CheckContext) -> CheckResult:
    from skylos.rules.ai_defect.dependency_hallucination import RULE_ID_UNDECLARED
    from skylos.rules.ai_defect.diff_dependencies import (
        scan_diff_dependency_hallucinations,
    )

    result = scan_diff_dependency_hallucinations(
        ctx.comparison.diff_text(), str(ctx.comparison.root)
    )
    findings = []
    import_lines: dict[str, set[int] | None] = {}
    for item in result.get("findings") or []:
        rule = str(item.get("rule_id") or "") or None
        file = _relative_file(item.get("file"), ctx.comparison)
        line = _int(item.get("line"))
        # The diff scanner reads import-shaped lines; one inside a string
        # (a test fixture, a docstring example) is not an import.
        if file and file.endswith(".py") and line is not None:
            if file not in import_lines:
                import_lines[file] = _python_import_lines(
                    ctx.comparison.head_text(file)
                )
            known = import_lines[file]
            if known is not None and line not in known:
                continue
        # "Undeclared" and "unverified" mean the name could not be tied to a
        # declared package: advice, never a claim that it does not exist.
        blocking = rule != RULE_ID_UNDECLARED
        message = str(item.get("message") or "import could not be resolved")
        findings.append(
            Finding(
                rule,
                file,
                line,
                message if blocking else f"(advice) {message}",
                blocking=blocking,
            )
        )
    unreachable = bool(result.get("registry_unreachable"))
    status = _status(findings)
    if status == "pass" and unreachable:
        status = "incomplete"
    blocking = sum(f.blocking for f in findings)
    summary = (
        f"{blocking} import(s) or package(s) do not exist"
        if blocking
        else "Could not reach the package registry"
        if unreachable
        else "Every added import and package resolves"
    )
    return CheckResult(
        id="unknown_imports",
        rule=next((f.rule for f in findings if f.blocking), "SKY-D222"),
        status=status,
        summary=summary,
        evidence={
            "missing": blocking,
            "unresolved": len(findings) - blocking,
            "registry_unreachable": unreachable,
            "summary": summary,
        },
        findings=findings,
    )


def _python_import_lines(source: str | None) -> set[int] | None:
    """Lines where import statements start; None when the file won't parse."""
    if source is None:
        return None
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    return {
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
    }


def _relative_file(value, comparison: Comparison) -> str | None:
    if not value:
        return None
    text = str(value).replace("\\", "/")
    if text.startswith("/"):
        return comparison.relative_path(text)
    return text


def _check_changed_lines(ctx: CheckContext) -> CheckResult:
    from skylos.done.mutation import check_changed_lines

    return check_changed_lines(ctx)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

CHECKS: dict[str, tuple[Callable[[CheckContext], CheckResult], str]] = {
    # id: (function, rule shown when the check is skipped or off)
    "tests_pass": (check_tests_pass, RULE_TESTS_PASS),
    "test_tampering": (check_test_tampering, RULE_DELETED_TEST),
    "gate_tampering": (check_gate_tampering, RULE_GATE_TAMPERING),
    "secrets": (check_secrets, "SKY-S101"),
    "unknown_imports": (check_unknown_imports, "SKY-D222"),
    "changed_lines_checked": (_check_changed_lines, "SKY-A120"),
}
# Cheap checks first; the test run (slowest) last.
RUN_ORDER = (
    "gate_tampering",
    "test_tampering",
    "secrets",
    "unknown_imports",
    "tests_pass",
    "changed_lines_checked",  # reuses the tests_pass run and its line trace
)


def run_check(check_id: str, ctx: CheckContext) -> CheckResult:
    function, rule = CHECKS[check_id]
    started = time.monotonic()
    try:
        result = function(ctx)
    except Exception as exc:
        # One broken check makes the receipt incomplete; it never crashes the
        # gate or turns into a pass.
        logger.debug("check %s failed", check_id, exc_info=True)
        summary = (
            str(exc)
            if isinstance(exc, DoneError)
            else f"Check could not finish ({type(exc).__name__})"
        )
        return CheckResult(
            id=check_id,
            rule=rule,
            status="incomplete",
            summary=summary,
            evidence={"summary": summary},
        )
    result.evidence.setdefault("check_seconds", round(time.monotonic() - started, 1))
    return result


def _line_of(text: str | None, needle: str) -> int | None:
    if not text:
        return None
    for index, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return index
    return None


def _int(value) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 1 else None
