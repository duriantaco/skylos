"""SKY-A113: the tests pass, run by Skylos itself.

What an agent says about its own test run is ignored. Skylos runs the
configured test command, reads the JUnit XML it writes, and decides:

* pass: every test that ran passed (or failed once and passed on a rerun,
  which is reported as flaky);
* fail: a test failed twice;
* incomplete: the run did not finish within the budget, produced no
  results, exited with an error it did not explain, or a test in a changed
  test file did not report a result although its file ran;
* skipped: there is no test command to run.

For pytest, Skylos adds its own ``--junitxml`` (xunit1, which records each
test's file) and drops PYTEST_ADDOPTS/PYTEST_PLUGINS from the environment, so
neither the change nor the CI step can narrow the run.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from skylos.done.base import Comparison
from skylos.done.config import DoneConfig
from skylos.done.inventory import TestItem
from skylos.core.safe_cache_io import (
    _fallback_output_parent_is_safe,
    _open_output_parent,
)

RULE_ID = "SKY-A113"

MAX_JUNIT_BYTES = 64 * 1024 * 1024
MAX_RERUN_TESTS = 50
OUTPUT_TAIL_CHARS = 4000
_MIN_RERUN_SECONDS = 5.0
_STRIPPED_ENV = ("PYTEST_ADDOPTS", "PYTEST_PLUGINS")
_PYTEST_CONFIG_FILES = (
    "pytest.ini",
    ".pytest.ini",
    "conftest.py",
    "tox.ini",
    "setup.cfg",
)

# A standalone pytest plugin (it imports nothing from Skylos, so it loads in
# any environment) that records the tests pytest itself deselected: -m, -k
# and --deselect from the base's settings. A test that vanishes without being
# deselected was dropped some other way, such as a conftest.py hook.
_PLUGIN_MODULE = "skylos_done_pytest_plugin"
_PLUGIN_SOURCE = """\
import json
import os

_deselected = []


def pytest_deselected(items):
    _deselected.extend(item.nodeid for item in items)


def pytest_sessionfinish(session, exitstatus):
    path = os.environ.get("SKYLOS_DONE_DESELECTED")
    if path:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(_deselected[:100000], handle)
"""
_MAX_DESELECTED_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class CaseResult:
    file: str | None
    classname: str
    name: str
    line: int | None
    outcome: str  # "passed", "failed", "error" or "skipped"
    message: str = ""

    @property
    def classes(self) -> tuple[str, ...]:
        """Class chain inside the module, from an xunit1 classname."""
        if not self.file:
            return ()
        parts = self.classname.split(".") if self.classname else []
        # classname is "<module path from pytest's rootdir>.<classes>". The
        # rootdir may differ from the repository root, so anchor on the
        # module's own name rather than its full dotted path.
        module = PurePosixPath(self.file).with_suffix("").parts
        candidates = [
            (size, start + size)
            for size in range(1, len(module) + 1)
            for start in range(len(parts) - size + 1)
            if tuple(parts[start : start + size]) == module[-size:]
        ]
        if candidates:
            _, end = max(candidates, key=lambda match: (match[0], -match[1]))
            return tuple(parts[end:])
        return ()

    @property
    def node_id(self) -> str | None:
        if not self.file:
            return None
        return "::".join((self.file, *self.classes, self.name))


@dataclass
class TestRunResult:
    status: str
    reason: str
    command: str = ""
    seconds: float = 0.0
    run: int = 0
    passed: int = 0
    skipped: int = 0
    failures: list[CaseResult] = field(default_factory=list)
    flaky: list[CaseResult] = field(default_factory=list)
    missing: list[TestItem] = field(default_factory=list)
    missing_cases: list[tuple[TestItem, int, int]] = field(default_factory=list)
    unknown_cases: list[TestItem] = field(default_factory=list)
    silent_files: list[str] = field(default_factory=list)
    output_tail: str = ""
    auto_command: bool = False


@dataclass(frozen=True)
class _Invocation:
    argv: tuple[str, ...]
    pytest: bool
    auto: bool


def run_tests(
    comparison: Comparison,
    config: DoneConfig,
    *,
    changed_tests: list[TestItem],
    base_tests: list[TestItem] | None = None,
    deadline: float | None = None,
) -> TestRunResult:
    root = comparison.root
    invocation = _invocation(root, config)
    if invocation is None:
        return TestRunResult(
            status="skipped",
            reason=(
                "no test command: set test_command in [tool.skylos.done] "
                "(no pytest project was found to run automatically)"
            ),
        )
    from skylos.done.test_config import base_excluded_tests

    excluded = (
        base_excluded_tests(
            comparison, changed_tests, invocation.argv, base_tests=base_tests
        )
        if invocation.pytest
        else set()
    )
    budget_end = deadline or (time.monotonic() + config.test_budget_seconds)
    shown = _shown_command(invocation)
    workdir = Path(tempfile.mkdtemp(prefix="skylos-done-")).resolve()
    try:
        (workdir / f"{_PLUGIN_MODULE}.py").write_text(_PLUGIN_SOURCE, encoding="utf-8")
        first = _run_once(root, config, invocation, (), workdir / "run.xml", budget_end)
        result = _assess(first, invocation, shown)
        if result.status != "fail" or not invocation.pytest:
            return _with_missing(result, first, changed_tests, invocation, excluded)

        # Rerun what failed once: a test that passes now is flaky, not failed.
        rerun_ids = [c.node_id for c in result.failures if c.node_id][:MAX_RERUN_TESTS]
        if rerun_ids and budget_end - time.monotonic() > _MIN_RERUN_SECONDS:
            second = _run_once(
                root,
                config,
                invocation,
                tuple(rerun_ids),
                workdir / "rerun.xml",
                budget_end,
            )
            if second.error is None and second.cases:
                passed_now = {c.node_id for c in second.cases if c.outcome == "passed"}
                result.flaky = [c for c in result.failures if c.node_id in passed_now]
                result.failures = [
                    c for c in result.failures if c.node_id not in passed_now
                ]
                if not result.failures:
                    result.status = "pass"
                    result.reason = (
                        f"{result.passed + len(result.flaky)} of {result.run} tests passed; "
                        f"{len(result.flaky)} failed once and passed on a rerun (flaky)"
                    )
        return _with_missing(result, first, changed_tests, invocation, excluded)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Choosing and running the command
# ---------------------------------------------------------------------------


def _invocation(root: Path, config: DoneConfig) -> _Invocation | None:
    if config.test_command:
        argv = tuple(config.test_command)
        return _Invocation(argv, _is_pytest(argv), auto=False)
    if _looks_like_pytest_project(root) and importlib.util.find_spec("pytest"):
        return _Invocation((sys.executable, "-m", "pytest"), True, auto=True)
    return None


def _is_pytest(argv: tuple[str, ...]) -> bool:
    program = PurePosixPath(argv[0].replace("\\", "/")).name
    if program in {"pytest", "py.test"}:
        return True
    return (
        program.startswith("python")
        and len(argv) >= 3
        and argv[1] == "-m"
        and argv[2] == "pytest"
    )


def _looks_like_pytest_project(root: Path) -> bool:
    if any((root / name).is_file() for name in _PYTEST_CONFIG_FILES[:3]):
        return True
    pyproject = root / "pyproject.toml"
    try:
        if pyproject.is_file() and "[tool.pytest" in pyproject.read_text("utf-8"):
            return True
    except (OSError, UnicodeError):
        pass
    return any((root / name).is_dir() for name in ("tests", "test"))


def _shown_command(invocation: _Invocation) -> str:
    argv = list(invocation.argv)
    if invocation.auto:
        argv[0] = "python"
    return " ".join(argv)[:120]


@dataclass
class _RunOutcome:
    exit_code: int | None
    seconds: float
    cases: list[CaseResult]
    junit_found: bool
    output_tail: str
    error: str | None = None  # "timeout", "not_found" or "junit_unreadable"
    deselected: frozenset[str] = frozenset()
    junit_expected: bool = False


def _run_once(
    root: Path,
    config: DoneConfig,
    invocation: _Invocation,
    node_ids: tuple[str, ...],
    junit_path: Path,
    budget_end: float,
) -> _RunOutcome:
    argv = list(invocation.argv)
    if invocation.pytest:
        argv += [
            f"--junitxml={junit_path}",
            "-o",
            "junit_family=xunit1",
            "-o",
            "junit_logging=no",
            "-p",
            _PLUGIN_MODULE,
            *node_ids,
        ]
        junit = junit_path
    else:
        junit = (root / config.junit_xml) if config.junit_xml else None

    env = {k: v for k, v in os.environ.items() if k not in _STRIPPED_ENV}
    # Reading/importing the project's tests must not dirty an otherwise clean
    # checkout with bytecode that invalidates its receipt.
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    deselected_path = junit_path.with_suffix(".deselected.json")
    if invocation.pytest:
        env["PYTHONPATH"] = os.pathsep.join(
            p for p in (str(junit_path.parent), env.get("PYTHONPATH", "")) if p
        )
        env["SKYLOS_DONE_DESELECTED"] = str(deselected_path)
    log_path = junit_path.with_suffix(".log")
    started_wall = time.time()
    started = time.monotonic()
    timeout = max(0.0, budget_end - started)
    # The test process runs repository code with our workdir paths in its
    # environment. Create the log exclusively and read it back through our own
    # descriptor, so a swapped-in symlink or FIFO cannot redirect or stall us.
    try:
        log_fd = _create_log(log_path)
    except OSError as exc:
        return _RunOutcome(None, 0.0, [], False, str(exc), "not_found")
    try:
        try:
            process = subprocess.Popen(
                argv,
                cwd=str(root),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=log_fd,
                stderr=subprocess.STDOUT,
                start_new_session=(os.name == "posix"),
            )
        except FileNotFoundError:
            return _RunOutcome(None, 0.0, [], False, "", "not_found")
        except OSError as exc:
            return _RunOutcome(None, 0.0, [], False, str(exc), "not_found")
        try:
            exit_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill(process)
            return _RunOutcome(
                None, time.monotonic() - started, [], False, _tail(log_fd), "timeout"
            )
        tail = _tail(log_fd)
    finally:
        os.close(log_fd)

    seconds = time.monotonic() - started
    cases: list[CaseResult] = []
    found = False
    error = None
    if junit is not None:
        data = _read_regular(junit, MAX_JUNIT_BYTES, newer_than=started_wall - 1)
        if data is not None:
            found = True
            parsed = _parse_junit_bytes(data, root)
            if parsed is None:
                error = "junit_unreadable"
            else:
                cases = parsed
    return _RunOutcome(
        exit_code,
        seconds,
        cases,
        found,
        tail,
        error,
        _read_deselected(deselected_path),
        junit_expected=junit is not None,
    )


def _create_log(path: Path) -> int:
    path = Path(os.path.abspath(path))
    parent = path.parent.resolve(strict=True)
    if path.parent != parent:
        raise OSError("The test log directory contains a symlink")
    output_path = parent / path.name
    try:
        output_path.resolve(strict=False).relative_to(parent)
    except (OSError, RuntimeError, ValueError) as exc:
        raise OSError("The test log path escapes its directory") from exc
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if os.open in os.supports_dir_fd and os.name != "nt" and hasattr(os, "O_NOFOLLOW"):
        directory_fd = _open_output_parent(output_path)
        if directory_fd is None:
            raise OSError("The test log directory cannot be opened without symlinks")
        try:
            return os.open(output_path.name, flags, 0o600, dir_fd=directory_fd)
        finally:
            os.close(directory_fd)
    if not _fallback_output_parent_is_safe(output_path):
        raise OSError("The test log path contains a symlink or an invalid parent")
    return os.open(output_path, flags, 0o600)


def _open_result(path: Path) -> int | None:
    """Pin every parent directory and open only the selected file's basename."""
    output_path = Path(os.path.abspath(path))
    try:
        output_path.resolve(strict=False).relative_to(output_path.parent)
    except (OSError, RuntimeError, ValueError):
        return None
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if os.open in os.supports_dir_fd and os.name != "nt" and hasattr(os, "O_NOFOLLOW"):
        directory_fd = _open_output_parent(output_path)
        if directory_fd is None:
            return None
        try:
            return os.open(output_path.name, flags, dir_fd=directory_fd)
        except OSError:
            return None
        finally:
            os.close(directory_fd)
    if not _fallback_output_parent_is_safe(output_path):
        return None
    # The fallback has rejected every symlink component. Keep the basename
    # inside that verified real parent when opening the selected result.
    parent = output_path.parent.resolve(strict=True)
    candidate = parent / output_path.name
    try:
        candidate.resolve(strict=False).relative_to(parent)
    except (OSError, RuntimeError, ValueError):
        return None
    try:
        before = candidate.lstat()
        if not stat.S_ISREG(before.st_mode):
            return None
        descriptor = os.open(candidate, flags)
    except OSError:
        return None
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            os.close(descriptor)
            return None
    except OSError:
        os.close(descriptor)
        return None
    return descriptor


def _read_regular(
    path: Path, max_bytes: int, *, newer_than: float | None = None
) -> bytes | None:
    """A regular file's bytes, never through a symlink and never blocking."""
    try:
        fd = _open_result(path)
    except OSError:
        return None
    if fd is None:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
            return None
        if newer_than is not None and info.st_mtime < newer_than:
            return None  # left over from an earlier run
        chunks = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        return data if len(data) <= max_bytes else None
    except OSError:
        return None
    finally:
        os.close(fd)


def _read_deselected(path: Path) -> frozenset[str]:
    raw = _read_regular(path, _MAX_DESELECTED_BYTES)
    if raw is None:
        return frozenset()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return frozenset()
    if not isinstance(data, list):
        return frozenset()
    return frozenset(item for item in data if isinstance(item, str))


def _kill(process: subprocess.Popen) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:  # pragma: no cover - Windows
            process.kill()
    except (OSError, ProcessLookupError):
        pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:  # pragma: no cover - defensive
        pass


def _tail(fd: int) -> str:
    try:
        size = os.fstat(fd).st_size
        os.lseek(fd, max(0, size - OUTPUT_TAIL_CHARS), os.SEEK_SET)
        return os.read(fd, OUTPUT_TAIL_CHARS).decode("utf-8", errors="replace")
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


def _assess(outcome: _RunOutcome, invocation: _Invocation, shown: str) -> TestRunResult:
    result = TestRunResult(
        status="incomplete",
        reason="",
        command=shown,
        seconds=round(outcome.seconds, 1),
        output_tail=outcome.output_tail,
        auto_command=invocation.auto,
    )
    if outcome.error == "timeout":
        result.reason = f"the tests ran out of time after {outcome.seconds:.0f} s (test_budget_seconds)"
        return result
    if outcome.error == "not_found":
        result.reason = f"the test command could not start: {shown}"
        return result
    if outcome.error == "junit_unreadable":
        result.reason = "the test results (JUnit XML) could not be read"
        return result

    cases = outcome.cases
    result.run = len(cases)
    result.passed = sum(c.outcome == "passed" for c in cases)
    result.skipped = sum(c.outcome == "skipped" for c in cases)
    result.failures = [c for c in cases if c.outcome in {"failed", "error"}]
    code = outcome.exit_code

    if not outcome.junit_found:
        if invocation.pytest or code is None or outcome.junit_expected:
            result.reason = "the test command wrote no test results"
            return result
        # A command without JUnit output: only its exit code is evidence.
        result.status = "pass" if code == 0 else "fail"
        result.reason = (
            "the test command succeeded (no JUnit results: exit code only)"
            if code == 0
            else f"the test command failed with exit code {code} (no JUnit results)"
        )
        return result
    if result.failures:
        result.status = "fail"
        result.reason = f"{len(result.failures)} of {result.run} tests failed"
        return result
    if result.run == 0 or result.run == result.skipped:
        result.reason = "no tests ran" if result.run == 0 else "every test was skipped"
        return result
    if code not in (0, None):
        result.reason = (
            f"the test command exited with code {code} but reported no failing test"
        )
        return result
    result.status = "pass"
    result.reason = f"{result.passed} of {result.run} tests passed" + (
        f" ({result.skipped} skipped)" if result.skipped else ""
    )
    return result


def _with_missing(
    result: TestRunResult,
    outcome: _RunOutcome,
    changed_tests: list[TestItem],
    invocation: _Invocation,
    base_excluded: set[str],
) -> TestRunResult:
    """Inventory tests whose execution cannot be proved.

    Only statically proven base exclusions excuse a missing result. A runtime
    ``pytest_deselected`` notification comes from PR code and is not proof.
    """
    cases = outcome.cases
    if not invocation.pytest or not cases or result.status == "incomplete":
        return result
    reported_files = {c.file for c in cases if c.file}
    reported = {}
    for case in cases:
        key = (case.file, case.classes, case.name.split("[", 1)[0])
        reported.setdefault(key, set()).add(case.name)
    expected = [t for t in changed_tests if t.id not in base_excluded]
    result.missing = [
        t
        for t in expected
        if t.path in reported_files and (t.path, t.classes, t.name) not in reported
    ]
    result.silent_files = sorted(
        {t.path for t in expected if t.path not in reported_files}
    )
    result.missing_cases = [
        (test, test.param_cases, count)
        for test in expected
        if test.param_cases is not None
        and (count := len(reported.get((test.path, test.classes, test.name), ()))) > 0
        and count < test.param_cases
    ]
    result.unknown_cases = [
        test for test in expected if test.parametrized and test.param_cases is None
    ]
    if (
        result.missing
        or result.silent_files
        or result.missing_cases
        or result.unknown_cases
    ) and result.status == "pass":
        result.status = "incomplete"
        result.reason = (
            f"{len(result.missing)} test(s), {sum(before - after for _, before, after in result.missing_cases)} parameter case(s), and {len(result.silent_files)} "
            "test file(s) reported no results without a proven base selection exclusion. "
            "Restore their execution or configure an explicit selector at the base."
        )
        if result.unknown_cases:
            result.reason += (
                f" Expected case totals for {len(result.unknown_cases)} computed parametrized test(s) "
                "cannot be independently inventoried; use literal case lists or simple local constants."
            )
    return result


def parse_junit(path: Path, root: Path) -> list[CaseResult] | None:
    """Test cases from a JUnit XML file; None when it cannot be trusted."""
    data = _read_regular(path, MAX_JUNIT_BYTES)
    if data is None:
        return None
    return _parse_junit_bytes(data, root)


def _parse_junit_bytes(data: bytes, root: Path) -> list[CaseResult] | None:
    # Test runners never emit DTDs; refusing them rules out entity expansion.
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        return None
    try:
        tree = ElementTree.fromstring(data)
    except ElementTree.ParseError:
        return None
    cases = []
    for case in tree.iter("testcase"):
        outcome = "passed"
        message = ""
        for child in case:
            if child.tag in {"failure", "error", "skipped"}:
                outcome = {"failure": "failed", "error": "error", "skipped": "skipped"}[
                    child.tag
                ]
                message = (child.get("message") or "").strip()
                if outcome != "skipped":
                    break
        file_attr = case.get("file")
        cases.append(
            CaseResult(
                file=_relative(file_attr, root) if file_attr else None,
                classname=case.get("classname") or "",
                name=case.get("name") or "",
                line=_int(case.get("line")),
                outcome=outcome,
                message=message,
            )
        )
    return cases


def _relative(file_attr: str, root: Path) -> str:
    path = file_attr.replace("\\", "/")
    try:
        candidate = Path(path)
        if candidate.is_absolute():
            return candidate.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return path
    while path.startswith("./"):
        path = path[2:]
    return path


def _int(value: str | None) -> int | None:
    try:
        number = int(value or "")
    except ValueError:
        return None
    # xunit1 line numbers are 0-based.
    return number + 1 if number >= 0 else None
