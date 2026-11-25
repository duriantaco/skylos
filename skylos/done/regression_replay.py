"""Prototype. Replay one committed pytest case against pinned source variants."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path, PurePosixPath

from skylos.core.git_safety import read_only_git_command, read_only_git_environment
from skylos.done.config import DoneConfig
from skylos.done.runner import _Invocation, _read_regular, _run_once


def _git(root: Path, *args: str, output=None) -> bytes:
    result = subprocess.run(
        read_only_git_command(args, literal_pathspecs=True),
        cwd=root,
        env=read_only_git_environment(),
        stdout=output if output is not None else subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    if result.returncode:
        raise ValueError(result.stderr.decode(errors="replace").strip())
    return result.stdout or b""


def _commit(root: Path, ref: str) -> str:
    return (
        _git(root, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}")
        .decode()
        .strip()
    )


def _python_path(value: str) -> str:
    parts = value.split("/")
    if (
        any(part in {"", ".", ".."} or part.casefold() == ".git" for part in parts)
        or re.fullmatch(r"[\w./-]+\.py", value) is None
    ):
        raise ValueError(f"Expected a repository-relative Python file: {value!r}")
    return value


def _blob(root: Path, commit: str, path: str) -> bytes:
    entry = _git(root, "ls-tree", "-z", commit, "--", path)
    match = re.fullmatch(rb"100(?:644|755) blob ([0-9a-f]+)\t([^\0]+)\0", entry)
    if match is None or match[2] != path.encode():
        raise ValueError(f"{path} must be a regular tracked file in {commit[:12]}")
    return _git(root, "cat-file", "blob", match[1].decode())


def _regular_archive_member(member: tarfile.TarInfo, path: str) -> tarfile.TarInfo:
    if not (member.isdir() or member.isfile()):
        raise ValueError(f"Unsupported archive entry: {member.name}")
    return tarfile.data_filter(member, path)


def _run(
    directory: Path,
    archive: Path,
    node_id: str,
    expected_files: dict[str, bytes],
    replacements: dict[str, bytes],
    timeout: float,
    submitted_test: tuple[str, bytes] | None = None,
) -> dict:
    checkout = directory / "checkout"
    home = directory / "home"
    tmp = directory / "tmp"
    for path in (checkout, home, tmp):
        path.mkdir(parents=True)
    with tarfile.open(archive) as snapshot:
        snapshot.extractall(checkout, filter=_regular_archive_member)
    for path, content in expected_files.items():
        if not (checkout / path).is_file() or (checkout / path).read_bytes() != content:
            raise ValueError(f"Git archive omitted or substituted {path}")
    for path, content in replacements.items():
        (checkout / path).write_bytes(content)
    if submitted_test is not None:
        path, content = submitted_test
        destination = checkout / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as output:
            output.write(content)
        expected_files = {**expected_files, path: content}

    plugin = f"skylos_replay_probe_{secrets.token_hex(8)}"
    shutil.copyfile(
        Path(__file__).with_name("_regression_replay_probe.py"),
        directory / f"{plugin}.py",
    )
    evidence = directory / "assertion.json"
    invocation = _Invocation(
        (
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-o",
            "addopts=",
            "-p",
            "no:cacheprovider",
            "-p",
            plugin,
            f"--replay-evidence={evidence}",
            f"--rootdir={checkout}",
        ),
        pytest=True,
        auto=False,
    )
    run = _run_once(
        checkout,
        DoneConfig(),
        invocation,
        (node_id,),
        directory / "junit.xml",
        time.monotonic() + timeout,
        environment={
            "HOME": str(home),
            "TMPDIR": str(tmp),
            "PATH": os.pathsep.join((str(Path(sys.executable).parent), os.defpath)),
            "PYTHONPATH": str(checkout / "src"),
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        },
        strict_evidence=True,
    )
    for path, content in (expected_files | replacements).items():
        if not (checkout / path).is_file() or (checkout / path).read_bytes() != content:
            return {"status": "inconclusive", "detail": f"The run changed {path}"}
    if run.error or run.probe_problem:
        return {
            "status": "inconclusive",
            "detail": run.error or run.probe_problem,
            "exit_code": run.exit_code,
        }
    if len(run.cases) != 1 or run.cases[0].node_id != node_id:
        return {
            "status": "inconclusive",
            "detail": "pytest did not report exactly the requested test case",
            "exit_code": run.exit_code,
        }

    case = run.cases[0]
    if run.exit_code == 0 and case.outcome == "passed":
        return {"status": "passed"}
    raw = _read_regular(evidence, 16384)
    assertion = json.loads(raw) if raw else {}
    if (
        run.exit_code == 1
        and case.outcome == "failed"
        and isinstance(assertion, dict)
        and assertion.get("node_id") == node_id
        and type(assertion.get("line")) is int
    ):
        return {
            "status": "assertion_failed",
            "line": assertion["line"],
            "detail": case.message[:600],
        }
    return {
        "status": "inconclusive",
        "detail": f"{case.outcome}: {case.message[:550]}",
        "exit_code": run.exit_code,
    }


def _verdict(records: list[dict], expected_line: int | None) -> str:
    if any(record["status"] == "inconclusive" for record in records):
        return "INCONCLUSIVE"
    if records[0]["status"] != "passed":
        return "REFERENCE_FAILED"
    if any(r["status"] != "passed" for r in records if r["role"] == "correct"):
        return "REJECTED_CORRECT_VARIANT"
    if any(r["status"] == "passed" for r in records if r["role"] == "buggy"):
        return "BUG_SURVIVED"
    if expected_line is not None and any(
        r["runs"][0]["line"] != expected_line for r in records if r["role"] == "buggy"
    ):
        return "UNEXPECTED_ASSERTION"
    return "DETECTED"


def _test_path(node_id: str) -> str:
    test_path, separator, test_name = node_id.partition("::")
    if not separator or not test_name:
        raise ValueError("Select one pytest case with FILE::TEST")
    return _python_path(test_path)


def _compare(baseline: dict, candidate: dict) -> dict:
    pairs = []
    for before, after in zip(baseline["variants"], candidate["variants"], strict=True):
        left, right = before["status"], after["status"]
        if "inconclusive" in (left, right):
            outcome = "inconclusive"
        elif before["role"] != "buggy":
            outcome = (
                "control_passed" if left == right == "passed" else "control_failed"
            )
        elif (
            right == "assertion_failed"
            and candidate["expected_assertion"] is not None
            and after["runs"][0]["line"] != candidate["expected_assertion"]
        ):
            outcome = "unexpected_assertion"
        else:
            outcome = {
                ("passed", "passed"): "missed_by_both",
                ("passed", "assertion_failed"): "candidate_only",
                ("assertion_failed", "passed"): "baseline_only",
                ("assertion_failed", "assertion_failed"): "caught_by_both",
            }[left, right]
        pairs.append(
            {"role": before["role"], "commit": before["commit"], "outcome": outcome}
        )

    outcomes = {pair["outcome"] for pair in pairs}
    if "control_failed" in outcomes:
        verdict = "CONTROL_FAILED"
    elif outcomes & {"inconclusive", "unexpected_assertion"}:
        verdict = "INCONCLUSIVE"
    elif {"candidate_only", "baseline_only"} <= outcomes:
        verdict = "MIXED"
    elif "candidate_only" in outcomes:
        verdict = "IMPROVED"
    elif "baseline_only" in outcomes:
        verdict = "REGRESSED"
    else:
        verdict = "NO_CHANGE"
    return {
        "schema_version": 1,
        "verdict": verdict,
        "baseline": baseline,
        "candidate": candidate,
        "pairs": pairs,
    }


def replay(args: argparse.Namespace) -> dict:
    root = args.repo.resolve()
    root = Path(
        os.fsdecode(_git(root, "rev-parse", "--show-toplevel").removesuffix(b"\n"))
    )
    arms = {"candidate": (args.test, args.expect_assertion)}
    if args.baseline_test is not None:
        arms["baseline"] = (args.baseline_test, None)
    test_paths = {node_id: _test_path(node_id) for node_id, _ in arms.values()}
    sources = tuple(dict.fromkeys(_python_path(path) for path in args.source))
    for path in sources:
        name = PurePosixPath(path).name
        if (
            path in test_paths.values()
            or name == "conftest.py"
            or name.startswith("test_")
            or name.endswith("_test.py")
        ):
            raise ValueError(f"Source substitution cannot replace a test: {path}")
    fixed = _commit(root, args.fixed)
    fixed_sources = {path: _blob(root, fixed, path) for path in sources}
    submitted_test = None
    test_revision = args.test_revision
    archived_paths = set(test_paths.values())
    if test_revision is not None:
        submitted_path = test_paths[args.test]
        if (
            not PurePosixPath(submitted_path).name.startswith("test_")
            or _git(root, "ls-tree", "-z", fixed, "--", submitted_path)
            or (args.baseline_test and submitted_path == test_paths[args.baseline_test])
        ):
            raise ValueError(
                "Submit a new test_*.py file at an unused path in the fixed tree"
            )
        test_revision = _commit(root, test_revision)
        submitted_test = (submitted_path, _blob(root, test_revision, submitted_path))
        archived_paths.remove(submitted_path)
    expected_files = {
        **fixed_sources,
        **{path: _blob(root, fixed, path) for path in archived_paths},
    }
    variants = [("fixed", fixed, {})]
    seen = {fixed}
    for role, refs in (("buggy", args.buggy), ("correct", args.correct)):
        for ref in refs:
            sha = _commit(root, ref)
            if sha in seen:
                raise ValueError(f"Duplicate revision: {ref}")
            seen.add(sha)
            replacements = {path: _blob(root, sha, path) for path in sources}
            if replacements == fixed_sources:
                raise ValueError(f"{ref} has no variant on the specified source files")
            variants.append((role, sha, replacements))

    results = {}
    with tempfile.TemporaryDirectory(prefix="skylos-regression-replay-") as directory:
        scratch = Path(directory).resolve()
        archive = scratch / "fixed.tar"
        with archive.open("wb") as output:
            _git(root, "archive", "--format=tar", fixed, output=output)
        for arm, (node_id, expected_line) in arms.items():
            records = []
            for index, (role, sha, replacements) in enumerate(variants):
                runs = [
                    _run(
                        scratch / f"run-{arm}-{index}-{attempt}",
                        archive,
                        node_id,
                        expected_files,
                        replacements,
                        args.timeout,
                        submitted_test if arm == "candidate" else None,
                    )
                    for attempt in (1, 2)
                ]
                stable = all(
                    runs[0].get(key) == runs[1].get(key) for key in ("status", "line")
                )
                records.append(
                    {
                        "role": role,
                        "commit": sha,
                        "status": runs[0]["status"] if stable else "inconclusive",
                        "runs": runs,
                        **({} if stable else {"detail": "fresh runs disagreed"}),
                    }
                )
            results[arm] = {
                "verdict": _verdict(records, expected_line),
                "test": node_id,
                "test_sha256": hashlib.sha256(
                    submitted_test[1]
                    if arm == "candidate" and submitted_test is not None
                    else expected_files[test_paths[node_id]]
                ).hexdigest(),
                "source_files": list(sources),
                "expected_assertion": expected_line,
                "variants": records,
            }
            if arm == "candidate" and submitted_test is not None:
                results[arm]["test_commit"] = test_revision
    if "baseline" in results:
        return _compare(results["baseline"], results["candidate"])
    return results["candidate"]


def main(argv: list[str] | None = None, *, prog: str | None = None) -> int:
    parser = argparse.ArgumentParser(prog=prog, description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--fixed", default="HEAD")
    parser.add_argument("--buggy", action="append", required=True)
    parser.add_argument("--correct", action="append", default=[])
    parser.add_argument("--source", action="append", required=True)
    parser.add_argument("--test", required=True)
    parser.add_argument(
        "--baseline-test", help="Compare against a committed pytest case"
    )
    parser.add_argument(
        "--test-revision", help="Read a new test file from this revision"
    )
    parser.add_argument("--expect-assertion", type=int, metavar="LINE")
    parser.add_argument(
        "--timeout", type=int, default=30, help="Seconds per pytest run"
    )
    parser.add_argument(
        "--allow-local-execution",
        action="store_true",
        required=True,
        help="Execute trusted project code with your local permissions",
    )
    args = parser.parse_args(argv)
    if args.timeout < 1 or (
        args.expect_assertion is not None and args.expect_assertion < 1
    ):
        parser.error("Timeout and assertion line must be positive")
    try:
        result = replay(args)
    except (OSError, ValueError, tarfile.TarError, subprocess.TimeoutExpired) as exc:
        result = {"verdict": "INCONCLUSIVE", "detail": str(exc)}
    print(json.dumps(result, indent=2))
    return {"DETECTED": 0, "IMPROVED": 0, "INCONCLUSIVE": 2}.get(result["verdict"], 1)


if __name__ == "__main__":
    raise SystemExit(main())
