"""Explicit cleanup checks using Done's bounded process, JUnit and line-trace runner."""

from __future__ import annotations

import difflib
from pathlib import Path, PurePosixPath
import shutil
import tempfile
import time

from skylos.done.config import DoneConfig
from skylos.done import runner


def validate_junit_path(value: str | None) -> None:
    if value is None:
        return
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in value
        or ":" in value
        or "\x00" in value
    ):
        raise ValueError("JUnit report must be a project-relative file")


def changed_lines(before: str, after: str) -> list[int]:
    lines = set()
    for operation, _a, _b, start, end in difflib.SequenceMatcher(
        a=before.splitlines(), b=after.splitlines(), autojunk=False
    ).get_opcodes():
        if operation in {"insert", "replace"}:
            lines.update(range(start + 1, end + 1))
    return sorted(lines)


def _signature(path):
    try:
        metadata = path.lstat()
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
    except OSError:
        return None


def run_cleanup_tests(
    root: Path, argv, *, file: str, before: str, after: str, timeout=300, junit_xml=None
):
    """Only called after explicit test authorization; suggestions never call this."""
    validate_junit_path(junit_xml)
    root = Path(root)
    argv = tuple(argv)
    pytest = runner._is_pytest(argv)
    config = DoneConfig(
        test_command=argv, junit_xml=junit_xml, test_budget_seconds=timeout
    )
    invocation = runner._Invocation(argv, pytest, auto=False)
    targets = changed_lines(before, after) if Path(file).suffix == ".py" else []
    report = root / junit_xml if junit_xml else None
    previous = _signature(report) if report is not None else None
    directory = Path(tempfile.mkdtemp(prefix="skylos-cleanup-tests-")).resolve()
    try:
        (directory / f"{runner._PLUGIN_MODULE}.py").write_text(
            runner._PLUGIN_SOURCE, encoding="utf-8"
        )
        trace_env, trace_path = runner._trace_environment(
            root, directory, {file: targets} if pytest and targets else None
        )
        outcome = runner._run_once(
            root,
            config,
            invocation,
            (),
            directory / "tests.xml",
            time.monotonic() + timeout,
            extra_env=trace_env,
        )
        result = runner._assess(outcome, invocation, " ".join(argv))
        result.pytest = pytest
        if trace_path is not None:
            runner._read_trace(result, trace_path, root)
        observed = bool(result.run > result.skipped and outcome.junit_found)
        evidence = (
            "pytest_junit"
            if pytest and outcome.junit_found
            else "junit"
            if outcome.junit_found
            else "exit_code"
        )
        status = {
            "pass": "passed",
            "fail": "failed",
            "incomplete": "incomplete",
            "skipped": "skipped",
        }[result.status]
        if (
            report is not None
            and outcome.junit_found
            and previous == _signature(report)
        ):
            status, observed = "incomplete", False
            result.reason = (
                "The configured JUnit report was not changed by this invocation"
            )
        exercised = None
        if targets and result.trace and result.trace.get("ok"):
            exercised = any(
                result.line_map and result.line_map.get((file, line))
                for line in targets
            )
        return {
            "status": status,
            "command": list(argv),
            "returncode": outcome.exit_code,
            "evidence": evidence,
            "count": result.run if outcome.junit_found else None,
            "passed_count": result.passed if outcome.junit_found else None,
            "skipped_count": result.skipped if outcome.junit_found else None,
            "observed": observed,
            "exercised_change": exercised,
            "duration_s": result.seconds,
            "reason": result.reason,
            "output": result.output_tail,
            "trace": {
                "status": "available"
                if result.trace and result.trace.get("ok")
                else "unavailable",
                "changed_lines": targets,
                "test_nodes": sorted(
                    {
                        node
                        for line in targets
                        for node in (result.line_map or {}).get((file, line), ())
                    }
                ),
            },
        }
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def compare_cleanup_behavior(file, before, after):
    """Compare matching module-level functions in the existing restricted model."""
    import ast
    from skylos.verification.behavior import compare_python_behavior

    result = {
        "status": "skipped",
        "model": "python-source-effects-v1",
        "functions": [],
        "limitations": [],
    }
    if Path(file).suffix != ".py":
        result["limitations"].append(
            "This source effect model currently supports Python"
        )
        return result
    try:
        trees = [ast.parse(source) for source in (before, after)]
        functions = [
            {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
            for tree in trees
        ]
        changed = [
            name
            for name in functions[0].keys() & functions[1].keys()
            if ast.dump(functions[0][name], include_attributes=False)
            != ast.dump(functions[1][name], include_attributes=False)
        ]
        for name in sorted(changed)[:10]:
            check = compare_python_behavior(
                {file: before}, {file: after}, file=file, symbol=name
            )
            result["functions"].append(check)
        if len(changed) > 10:
            result["limitations"].append("Effect model function budget reached")
        if any(check["status"] == "different" for check in result["functions"]):
            result["status"] = "failed"
        elif (
            result["functions"]
            and all(check["status"] == "equivalent" for check in result["functions"])
            and not result["limitations"]
        ):
            result["status"] = "passed"
        elif result["functions"]:
            result["status"] = "incomplete"
        else:
            result["limitations"].append(
                "No matching changed module-level function; import and deletion behavior is outside this model"
            )
    except (SyntaxError, ValueError, RecursionError):
        result["status"] = "incomplete"
        result["limitations"].append(
            "The source effect model could not parse the patch"
        )
    return result
