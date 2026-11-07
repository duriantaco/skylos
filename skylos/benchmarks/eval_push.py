"""Check exact outgoing Skylos commits with a pinned, three-case smoke harness.

The controller imports no analyzer. Only its isolated worker imports the commit
under test, after the entry point selects that snapshot's core package.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from typing import Any


HARNESS_ROOT = Path(__file__).resolve().parents[2]
SMOKE_CASES = {
    "security": ["ssrf-tainted-host", "ssrf-fixed-host-path"],
    "dead-code": ["fastapi-route-used"],
}
_OID = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")
_GIT_LOCAL = {
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_DIR",
    "GIT_GRAFT_FILE",
    "GIT_INDEX_FILE",
    "GIT_INTERNAL_SUPER_PREFIX",
    "GIT_NAMESPACE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_OBJECT_DIRECTORY",
    "GIT_PREFIX",
    "GIT_REPLACE_REF_BASE",
    "GIT_SHALLOW_FILE",
    "GIT_WORK_TREE",
    "GIT_IMPLICIT_WORK_TREE",
}


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as output:
        output.write(_json(value))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_environment() -> dict[str, str]:
    """Remove hook-local Git repository overrides for foreign snapshot commands."""
    env = dict(os.environ)
    for name in list(env):
        if name in _GIT_LOCAL or name.startswith(
            ("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")
        ):
            env.pop(name, None)
    # A local clone needs neither credentials nor checkout filters from global
    # configuration. This changes child processes only, never the caller's Git.
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    return env


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        env=git_environment(),
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    if result.returncode:
        raise ValueError(f"Git could not {' '.join(args[:2])}: {result.stderr.strip()}")
    return result.stdout.strip()


def parse_updates(text: str) -> list[dict[str, str]]:
    """Parse native pre-push input without interpreting ref names as commands."""
    if len(text.encode()) > 1024 * 1024:
        raise ValueError("pre-push ref input exceeds 1 MiB")
    updates = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 4 or any("\x00" in field for field in fields):
            raise ValueError(f"invalid pre-push ref record on line {number}")
        local_ref, local_oid, remote_ref, remote_oid = fields
        if not _OID.fullmatch(local_oid) or not _OID.fullmatch(remote_oid):
            raise ValueError(f"invalid object ID on pre-push line {number}")
        local_oid, remote_oid = local_oid.lower(), remote_oid.lower()
        if set(local_oid) == {"0"} or local_oid == remote_oid:
            continue
        updates.append(
            {
                "local_ref": local_ref,
                "local_oid": local_oid,
                "remote_ref": remote_ref,
                "remote_oid": remote_oid,
            }
        )
    return updates


def resolve_updates(repo: Path, updates: list[dict[str, str]]) -> list[dict]:
    """Peel tags to commits and deduplicate tips shared by multiple pushed refs."""
    commits: dict[str, dict] = {}
    for update in updates:
        commit = _git(repo, "rev-parse", "--verify", update["local_oid"] + "^{commit}")
        if not _OID.fullmatch(commit):
            raise ValueError("pushed object did not resolve to a complete commit ID")
        if commit not in commits:
            tree = _git(repo, "rev-parse", "--verify", commit + "^{tree}")
            if not _OID.fullmatch(tree):
                raise ValueError("pushed commit has no valid tree identity")
            commits[commit] = {"commit": commit, "tree": tree, "refs": []}
        commits[commit]["refs"].append(update)
    return list(commits.values())


def harness_identity() -> dict:
    files = [HARNESS_ROOT / "scripts/eval_pre_push.py"]
    files.extend(sorted((HARNESS_ROOT / "skylos/benchmarks").glob("*.py")))
    if not files[0].is_file():
        raise ValueError("the pinned pre-push entry point is missing")
    for suite, ids in SMOKE_CASES.items():
        module_name = "security" if suite == "security" else "dead_code"
        manifest = HARNESS_ROOT / "benchmarks" / module_name / "manifest.json"
        document = json.loads(manifest.read_text())
        cases = document.get("cases")
        if not isinstance(cases, list):
            raise ValueError("pinned smoke manifest has no case inventory")
        selected = [
            case for case in cases if isinstance(case, dict) and case.get("id") in ids
        ]
        if len(selected) != len(ids) or {case["id"] for case in selected} != set(ids):
            raise ValueError(
                "pinned harness is missing required smoke case definitions"
            )
        files.append(manifest)
        for case in selected:
            relative = case.get("path")
            if not isinstance(relative, str) or Path(relative).is_absolute():
                raise ValueError("pinned fixture path must be manifest-relative")
            fixture = (manifest.parent / relative).resolve(strict=True)
            if not fixture.is_relative_to(manifest.parent.resolve()):
                raise ValueError("pinned fixture escapes its manifest directory")
            children = [fixture] if fixture.is_file() else list(fixture.rglob("*"))
            for child in children:
                if child.is_symlink():
                    raise ValueError("pinned fixture must not contain symbolic links")
                if child.is_file():
                    files.append(child)
    entries = {p.relative_to(HARNESS_ROOT).as_posix(): _sha(p) for p in files}
    digest = hashlib.sha256(_json(entries).encode()).hexdigest()
    return {"sha256": digest, "files": entries}


def _artifact_hashes(directory: Path) -> dict[str, str]:
    return {
        p.relative_to(directory).as_posix(): _sha(p)
        for p in sorted(directory.rglob("*"))
        if p.is_file()
    }


def worker(snapshot: Path, output: Path) -> int:
    """Run pinned graders/approved fixtures against the snapshot's analyzer."""
    snapshot = snapshot.resolve(strict=True)
    output.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    receipt: dict[str, Any] = {
        "scope": "three selected smoke cases only",
        "snapshot": str(snapshot),
        "cases": {},
        "errors": failures,
        "passed": False,
    }
    try:
        analyzer = importlib.import_module("skylos.analyzer")
        analyzer_path = Path(inspect.getsourcefile(analyzer.analyze) or "").resolve(
            strict=True
        )
        if not analyzer_path.is_relative_to(snapshot):
            raise ValueError(
                "worker imported an analyzer outside the pushed commit snapshot"
            )
        receipt["analyzer_path"] = str(analyzer_path)
        receipt["analyzer_sha256"] = _sha(analyzer_path)
        workflow = importlib.import_module("skylos.benchmarks.eval_workflow")
        validation = importlib.import_module("skylos.benchmarks._analysis_validation")
        for suite, ids in SMOKE_CASES.items():
            directory = output / suite
            try:
                module_name = "security" if suite == "security" else "dead_code"
                module = importlib.import_module("skylos.benchmarks." + module_name)
                if not Path(module.__file__).resolve().is_relative_to(HARNESS_ROOT):
                    raise ValueError(
                        "benchmark grader did not load from the pinned harness"
                    )
                manifest = HARNESS_ROOT / "benchmarks" / module_name / "manifest.json"
                dataset = workflow._selected_dataset(manifest, ids)
                dataset["suite"] = suite
                _write(directory / "dataset.json", dataset)
                numbers = {
                    entry["case"]["id"]: i for i, entry in enumerate(dataset["cases"])
                }
                captured = {}

                def capture(case_id: str, raw: object) -> None:
                    if case_id not in numbers or case_id in captured:
                        raise ValueError(
                            "captured case inventory differs from required smoke scope"
                        )
                    captured[case_id] = raw
                    _write(
                        directory / "cases" / str(numbers[case_id]) / "actual.raw.json",
                        raw,
                    )

                options = {"selected_cases": set(ids), "capture_result": capture}
                if suite == "dead-code":
                    options["strict_labels"] = True
                summary = module.run_manifest(manifest, **options)
                _write(directory / "summary.json", summary)
                reports, errors = workflow._case_reports(dataset, directory)
                if set(captured) != set(ids) or len(reports) != len(ids):
                    errors.append("missing required smoke case execution or raw output")
                for raw in captured.values():
                    errors.extend(validation.analysis_issues(raw, scanner="skylos"))
                clean = not errors and all(
                    case["status"] == "passed"
                    and not case["failures"]
                    and not case["unresolved_findings"]
                    for case in reports
                )
                receipt["cases"][suite] = {
                    "passed": clean,
                    "dataset_sha256": workflow._digest(dataset),
                    "results": reports,
                    "errors": list(dict.fromkeys(errors)),
                }
                if not clean:
                    failures.append(
                        f"{suite}: selected smoke checks failed or were incomplete"
                    )
                print(
                    f"{suite}: {sum(c['status'] == 'passed' for c in reports)}/{len(ids)} "
                    f"selected cases passed; {'PASS' if clean else 'CHECKS FAILED'}"
                )
            except Exception as error:
                failures.append(
                    f"{suite}: required case/support data unavailable: {error}"
                )
        if _sha(analyzer_path) != receipt["analyzer_sha256"]:
            failures.append("snapshot analyzer changed during execution")
    except Exception as error:
        failures.append(f"snapshot analyzer or pinned support unavailable: {error}")
    receipt["passed"] = not failures and set(receipt["cases"]) == set(SMOKE_CASES)
    receipt["artifacts"] = _artifact_hashes(output)
    _write(output / "worker-receipt.json", receipt)
    return 0 if receipt["passed"] else 1


def check_commit(repo: Path, revision: dict, output: Path) -> dict:
    """Evaluate one immutable commit in a detached foreign checkout."""
    repo = repo.resolve(strict=True)
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    before_harness = harness_identity()
    receipt: dict[str, Any] = {
        "schema_version": 1,
        **revision,
        "scope": "three selected smoke cases only",
        "harness": before_harness,
        "passed": False,
        "errors": [],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        with tempfile.TemporaryDirectory(prefix="skylos-pre-push-") as temp:
            snapshot = Path(temp) / "snapshot"
            clone = subprocess.run(
                ["git", "clone", "--shared", "--no-checkout", str(repo), str(snapshot)],
                env=git_environment(),
                capture_output=True,
                text=True,
                timeout=120,
            )
            (output / "clone.stdout.txt").write_text(clone.stdout)
            (output / "clone.stderr.txt").write_text(clone.stderr)
            if clone.returncode:
                raise ValueError(
                    "could not create an isolated snapshot of the pushed commit"
                )
            # This configuration is confined to the newly created scratch repo.
            _git(snapshot, "config", "core.hooksPath", os.devnull)
            _git(snapshot, "checkout", "--detach", revision["commit"])
            if _git(snapshot, "rev-parse", "HEAD") != revision["commit"]:
                raise ValueError("snapshot HEAD differs from the pushed commit")
            if _git(snapshot, "rev-parse", "HEAD^{tree}") != revision["tree"]:
                raise ValueError("snapshot tree differs from the pushed commit tree")
            command = [
                sys.executable,
                "-B",
                str(HARNESS_ROOT / "scripts/eval_pre_push.py"),
                "--worker",
                "--snapshot",
                str(snapshot),
                "--output",
                str(output / "checks"),
            ]
            receipt["command"] = command
            env = git_environment()
            env["PYTHONPATH"] = str(snapshot)
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            env = {
                key: value
                for key, value in env.items()
                if not key.startswith("SKYLOS_")
            }
            env.update(
                SKYLOS_CUSTOM_RULES="[]",
                SKYLOS_NO_UPLOAD="1",
                SKYLOS_NO_TELEMETRY="1",
                PYTHONHASHSEED="0",
            )
            with (
                (output / "stdout.txt").open("x") as stdout,
                (output / "stderr.txt").open("x") as stderr,
            ):
                process = subprocess.run(
                    command,
                    cwd=snapshot,
                    env=env,
                    stdout=stdout,
                    stderr=stderr,
                    timeout=180,
                    check=False,
                )
            receipt["worker_exit_code"] = process.returncode
            worker_receipt = json.loads(
                (output / "checks/worker-receipt.json").read_text()
            )
            receipt["worker"] = worker_receipt
            if process.returncode != 0 or worker_receipt.get("passed") is not True:
                receipt["errors"].append(
                    "selected smoke checks failed; inspect stdout.txt and checks/"
                )
            if _git(snapshot, "status", "--porcelain", "--untracked-files=no"):
                receipt["errors"].append(
                    "tracked snapshot inputs changed during execution"
                )
            if harness_identity() != before_harness:
                receipt["errors"].append("pinned harness changed during execution")
            receipt["passed"] = not receipt["errors"]
    except Exception as error:
        receipt["errors"].append(str(error))
    receipt["elapsed_seconds"] = round(time.monotonic() - started, 4)
    receipt["artifacts"] = _artifact_hashes(output)
    _write(output / "receipt.json", receipt)
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("remote_name", nargs="?", default="origin")
    parser.add_argument("remote_url", nargs="?", default="")
    args = parser.parse_args(argv)
    if args.worker:
        if args.snapshot is None or args.output is None:
            parser.error("--worker requires --snapshot and --output")
        return worker(args.snapshot, args.output)
    try:
        updates = parse_updates(sys.stdin.read(1024 * 1024 + 1))
        if not updates:
            print(
                "Skylos pre-push: no changed commit tips to check (deletes/unchanged refs)."
            )
            return 0
        location = (args.repo or Path.cwd()).resolve(strict=True)
        repo = Path(_git(location, "rev-parse", "--show-toplevel")).resolve(strict=True)
        revisions = resolve_updates(repo, updates)
        output = repo / ".skylos/evals/pre-push/runs" / str(time.time_ns())
        output.mkdir(parents=True, exist_ok=False)
        runs = []
        for revision in revisions:
            print(
                f"Skylos pre-push: checking committed snapshot {revision['commit'][:12]} "
                "(3 smoke cases; broader CI is separate).",
                flush=True,
            )
            report = check_commit(repo, revision, output / revision["commit"])
            runs.append(report)
            print(
                f"Skylos pre-push: {'PASS' if report['passed'] else 'CHECKS FAILED'} "
                f"{revision['commit'][:12]}; receipt: {output / revision['commit'] / 'receipt.json'}",
                flush=True,
            )
        passed = all(run["passed"] for run in runs)
        _write(
            output / "push-receipt.json",
            {
                "remote_name": args.remote_name,
                "remote_url_sha256": hashlib.sha256(
                    args.remote_url.encode()
                ).hexdigest(),
                "commits": [
                    {
                        "commit": run["commit"],
                        "tree": run["tree"],
                        "passed": run["passed"],
                    }
                    for run in runs
                ],
                "passed": passed,
                "comparison": "absolute checks; no before/after regression inference",
            },
        )
        return 0 if passed else 1
    except Exception as error:
        print(f"Skylos pre-push checks failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
