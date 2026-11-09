"""Native agent hook adapter for explicitly scoped internal Skylos smoke evals.

Only trusted local checkouts are supported. Hook state is local coordination,
not authenticated evidence or a substitute for broader required CI checks.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any

from skylos.benchmarks import eval_workflow as workflow
from skylos.benchmarks.eval_identity import environment_identity, source_identity
from skylos.benchmarks.eval_report import _inspect, compare_receipts, format_comparison


ROOT = Path(__file__).resolve().parents[2]
SMOKE_CASES = {
    "security": ["ssrf-tainted-host", "ssrf-fixed-host-path"],
    "dead-code": ["fastapi-route-used"],
}
_READ_TOOLS = {
    "Read",
    "Glob",
    "Grep",
    "WebFetch",
    "WebSearch",
    "AskUserQuestion",
    "ExitPlanMode",
    "TodoWrite",
    "TaskCreate",
    "TaskGet",
    "TaskList",
    "TaskUpdate",
}


class HookError(ValueError):
    """The evidence required for a clean hook result is unavailable."""


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


def _tool_identity() -> dict:
    facts = {
        "path_sha256": hashlib.sha256(os.environ.get("PATH", "").encode()).hexdigest()
    }
    for name in ("git", "rg", "ag", "grep"):
        found = shutil.which(name)
        if found is None:
            facts[name] = None
            continue
        path = Path(found).resolve(strict=True)
        if not path.is_file():
            raise HookError(
                "an external grep/git tool is not a regular executable file"
            )
        facts[name] = {
            "path": str(path),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "mode": path.stat().st_mode,
        }
    return facts


def _signature(repo: Path) -> dict:
    suites = {}
    environment = environment_identity()["sha256"]
    for suite, case_ids in SMOKE_CASES.items():
        manifest = repo / "benchmarks" / workflow.SUITES[suite] / "manifest.json"
        dataset = workflow._selected_dataset(manifest, case_ids)
        dataset["suite"] = suite
        suites[suite] = {
            "dataset_sha256": workflow._digest(dataset),
            "harness_sha256": workflow._harness_identity(repo, suite),
            "environment_sha256": environment,
            "options": {
                "scanner": "skylos",
                "strict_labels": suite == "dead-code",
                "worker_settings": workflow.WORKER_SETTINGS,
                "inherit_skylos_environment": False,
            },
        }
    return {
        "source": source_identity(repo)["snapshot_sha256"],
        "inputs": suites,
        "external_tools": _tool_identity(),
    }


def _validate_repo(repo: Path, event: dict) -> None:
    cwd_value = event.get("cwd")
    if not isinstance(cwd_value, str) or not cwd_value:
        raise HookError(
            "hook has no working directory; checkout identity is unavailable"
        )
    cwd = Path(cwd_value).resolve(strict=True)
    if not cwd.is_relative_to(repo):
        raise HookError("hook working directory is outside its configured checkout")
    result = subprocess.run(
        ["git", "-C", str(cwd), "rev-parse", "--show-toplevel"],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode or Path(result.stdout.strip()).resolve() != repo:
        raise HookError("hook working directory belongs to a different Git checkout")
    if not (repo / "scripts/eval_check.py").is_file():
        raise HookError(
            "eval runner is absent in this checkout; another checkout's result cannot validate it"
        )
    if event.get("hook_event_name") == "PreToolUse" and _may_mutate(event):
        data = event.get("tool_input")
        if isinstance(data, dict):
            for field in ("cwd", "workdir", "file_path"):
                value = data.get(field)
                if not isinstance(value, str) or not value:
                    continue
                target = Path(value)
                target = (
                    (cwd / target).resolve()
                    if not target.is_absolute()
                    else target.resolve()
                )
                if not target.is_relative_to(repo):
                    raise HookError(
                        "tool explicitly targets a path outside the configured checkout; its evals cannot validate another repository"
                    )
                probe = target if target.is_dir() else target.parent
                while not probe.exists() and probe != repo:
                    probe = probe.parent
                target_root = subprocess.run(
                    ["git", "-C", str(probe), "rev-parse", "--show-toplevel"],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                if (
                    target_root.returncode
                    or Path(target_root.stdout.strip()).resolve() != repo
                ):
                    raise HookError(
                        "tool explicitly targets a nested different Git checkout; its source is outside this eval scope"
                    )


def _state_directory(repo: Path, client: str, session: str) -> Path:
    directory = repo / ".skylos/evals/hooks" / _digest([str(repo), client, session])
    for path in (
        repo / ".skylos",
        repo / ".skylos/evals",
        repo / ".skylos/evals/hooks",
        directory,
    ):
        if path.is_symlink():
            raise HookError("hook state directories must not be symlinks")
    if not directory.resolve().is_relative_to(repo):
        raise HookError("hook state path escapes the checkout")
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _save(directory: Path, state: dict) -> None:
    temporary = directory / "state.tmp"
    for path in (temporary, directory / "state.json"):
        if path.is_symlink():
            raise HookError("hook state files must not be symlinks")
    temporary.write_text(
        json.dumps(state, indent=2, sort_keys=True, allow_nan=False) + "\n"
    )
    temporary.replace(directory / "state.json")


def _new_episode(state: dict, event: dict, signature: dict, directory: Path) -> dict:
    if state:
        if not isinstance(state.get("episode"), str) or not state["episode"].isdigit():
            raise HookError("hook state episode identifier is invalid")
        history = directory / "episodes"
        if history.is_symlink():
            raise HookError("hook episode history must not be a symlink")
        history.mkdir(exist_ok=True)
        target = history / (str(state["episode"]) + ".json")
        if target.is_symlink():
            raise HookError("hook episode history file must not be a symlink")
        target.write_text(json.dumps(state, indent=2) + "\n")
    return {
        "schema_version": 1,
        "episode": str(time.time_ns()),
        "phase": "armed",
        "request_id": str(
            event.get("prompt_id") or event.get("turn_id") or "unavailable"
        ),
        "initial_signature": signature,
        "baselines": {},
        "candidates": {},
        "run_count": 0,
        "failure_reported_signature": None,
    }


def _may_mutate(event: dict) -> bool:
    name = event.get("tool_name")
    if name in _READ_TOOLS:
        return False
    if name == "Bash":
        data = event.get("tool_input")
        # Flags such as rg --pre can execute code. Shell classification is not a
        # reliable proof of read-only behavior; native Read/Grep/Glob stay cheap.
        return not isinstance(data, dict) or data.get("command") != ""
    # Agent dispatch, MCP calls and unrecognized tools can write indirectly.
    return True


def _invoke(
    repo: Path, action: str, suite: str, output: Path, baseline: Path | None = None
) -> tuple[int, str, str]:
    command = [
        sys.executable,
        "-B",
        str(repo / "scripts/eval_check.py"),
        action,
        "--output",
        str(output),
        "--timeout",
        "90",
    ]
    if action == "baseline":
        command += ["--suite", suite]
        for case in SMOKE_CASES[suite]:
            command += ["--case", case]
    else:
        command += ["--baseline", str(baseline)]
    process = subprocess.run(
        command, cwd=repo, capture_output=True, text=True, timeout=120, check=False
    )
    return process.returncode, process.stdout, process.stderr


def _load(path: Path) -> dict:
    return workflow.load_receipt(path)


def _health(
    receipt: dict, suite: str, signature: dict, phase: str
) -> tuple[bool, bool]:
    inspection, _, counts = _inspect(receipt, phase)
    if inspection:
        return False, False
    if receipt.get("phase") != phase or receipt.get("suite") != suite:
        raise HookError("saved receipt has the wrong phase or suite")
    if (
        receipt.get("schema_version") != 1
        or receipt.get("source_unchanged") is not True
    ):
        raise HookError("saved receipt does not establish stable source execution")
    if receipt.get("inputs") != signature["inputs"][suite]:
        raise HookError("saved receipt does not match the selected inputs/runtime")
    if (receipt.get("source") or {}).get("snapshot_sha256") != signature["source"]:
        raise HookError("saved receipt does not match the checked source")
    if receipt.get("runtime_errors"):
        return False, False
    cases = receipt.get("cases")
    expected = set(SMOKE_CASES[suite])
    if (
        not isinstance(cases, list)
        or len(cases) != len(expected)
        or set(receipt.get("case_ids", [])) != expected
        or any(not isinstance(case, dict) for case in cases)
        or {case.get("id") for case in cases} != expected
    ):
        raise HookError("saved receipt has missing or duplicate smoke cases")
    complete = all(case.get("status") in {"passed", "failed"} for case in cases)
    clean = (
        complete
        and not counts["failed"]
        and not counts["incomplete"]
        and not counts["unresolved"]
    )
    return complete, clean


def _inputs_equal(left: dict, right: dict) -> bool:
    return (
        left["inputs"] == right["inputs"]
        and left["external_tools"] == right["external_tools"]
    )


def _run_checks(
    repo: Path, state: dict, directory: Path, action: str, signature: dict
) -> dict[str, str]:
    paths = {}
    for suite in SMOKE_CASES:
        state["run_count"] += 1
        _save(directory, state)
        output = (
            directory
            / "runs"
            / state["episode"]
            / f"{state['run_count']:04}-{action}-{suite}"
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        baseline = Path(state["baselines"][suite]) if action == "candidate" else None
        code, stdout, stderr = _invoke(repo, action, suite, output, baseline)
        (output.parent / (output.name + ".stdout.txt")).write_text(stdout)
        (output.parent / (output.name + ".stderr.txt")).write_text(stderr)
        if code not in (0, 1):
            raise HookError(f"{suite} {action} command failed; inspect {output.parent}")
        receipt = _load(output)
        complete, clean = _health(receipt, suite, signature, action)
        if not complete:
            raise HookError(
                f"{suite} {action} analysis is incomplete; inspect {output}"
            )
        # A complete semantic baseline failure is allowed so the agent can fix it.
        expected_code = (
            (0 if clean else 1)
            if action == "baseline"
            else compare_receipts(_load(baseline), receipt)["exit_code"]
        )
        if code != expected_code:
            raise HookError(f"{action} command exit status disagrees with its evidence")
        paths[suite] = str(output)
    if _signature(repo) != signature:
        raise HookError("source or eval inputs changed while smoke checks ran")
    return paths


def _context(event: str, message: str) -> dict:
    return {
        "hookSpecificOutput": {"hookEventName": event, "additionalContext": message}
    }


def _pretool_failure(message: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": message,
        }
    }


def _failure(state: dict, signature: Any, message: str, event: dict) -> dict:
    key = _digest(signature)
    repeated = (
        state.get("failure_reported_signature") == key
        or event.get("stop_hook_active") is True
    )
    state["phase"] = "failed"
    state["failure_reported_signature"] = key
    state["last_failure"] = message
    if repeated:
        return {
            "systemMessage": "Skylos smoke evals remain FAILED / INCOMPLETE. "
            + message
            + " Report this limitation; no clean eval result is established."
        }
    return {
        "decision": "block",
        "reason": "Skylos smoke evals did not pass. "
        + message
        + " Fix or report the specific failure; preserve the starting baseline.",
    }


def _evidence(paths: dict[str, str], signature: dict, phase: str) -> tuple[dict, bool]:
    if set(paths) != set(SMOKE_CASES):
        raise HookError("the paired smoke suites are missing saved evidence")
    receipts = {}
    clean = True
    for suite, path in paths.items():
        receipts[suite] = receipt = _load(Path(path))
        complete, passed = _health(receipt, suite, signature, phase)
        if not complete:
            raise HookError(f"{suite} saved analysis is incomplete")
        clean = clean and passed
    return receipts, clean


def _stop(
    repo: Path, state: dict, directory: Path, event: dict, signature: dict
) -> dict:
    baselines = state.get("baselines") or {}
    if not baselines:
        if state.get("phase") == "failed":
            return _failure(
                state,
                signature,
                state.get("last_pretool_error")
                or state.get("last_failure")
                or "A before-edit baseline was not established.",
                event,
            )
        if signature["source"] != state["initial_signature"]["source"]:
            return _failure(
                state,
                signature,
                "Source changed without a before-edit baseline; no comparable pair exists.",
                event,
            )
        state["phase"] = "no_changes"
        return {}
    before_signature = state["baseline_signature"]
    before, baseline_clean = _evidence(baselines, before_signature, "baseline")
    if not _inputs_equal(before_signature, signature):
        return _failure(
            state,
            signature,
            "Fixtures, grader, runtime/options or external grep/git tools changed since baseline; comparisons require matching reviewed inputs.",
            event,
        )
    if (
        state.get("phase") == "failed"
        and state.get("failure_reported_signature") == _digest(signature)
        and state.get("candidate_signature") != signature
    ):
        return _failure(
            state,
            signature,
            state.get("last_failure", "Required evidence remains unavailable."),
            event,
        )
    if signature == before_signature:
        if _signature(repo) != signature:
            raise HookError(
                "source or runtime changed while verifying saved baseline artifacts"
            )
        if not baseline_clean:
            return _failure(
                state,
                signature,
                "Existing baseline failures remain. Reused unchanged baseline evidence, not a new execution. "
                + "; ".join(baselines.values()),
                event,
            )
        state["phase"] = "passed"
        return {
            "systemMessage": "Skylos smoke evals: 3 selected cases passed. Source and inputs are unchanged; reused verified baseline receipts without rerunning. "
            + "; ".join(baselines.values())
            + ". Broader required validation remains separate."
        }

    cached = state.get("candidate_signature") == signature and state.get("candidates")
    if cached:
        try:
            after, _ = _evidence(state["candidates"], signature, "candidate")
        except (OSError, ValueError, KeyError, TypeError):
            cached = False
    if not cached:
        state["candidates"] = _run_checks(
            repo, state, directory, "candidate", signature
        )
        state["candidate_signature"] = signature
        after, _ = _evidence(state["candidates"], signature, "candidate")
    if _signature(repo) != signature:
        raise HookError("source or runtime changed while verifying candidate artifacts")
    comparisons = [
        compare_receipts(before[suite], after[suite]) for suite in SMOKE_CASES
    ]
    summary = "\n\n".join(format_comparison(comparison) for comparison in comparisons)
    paths = "; ".join(state["candidates"].values())
    reuse = (
        "Reused verified unchanged candidate evidence. "
        if cached
        else "Ran matching candidate checks. "
    )
    if any(comparison["exit_code"] for comparison in comparisons):
        return _failure(
            state, signature, reuse + summary + "\nReceipts: " + paths, event
        )
    state["phase"] = "passed"
    state["failure_reported_signature"] = None
    return {
        "systemMessage": "Skylos smoke evals: PASS (3 selected cases only). "
        + reuse
        + summary
        + "\nReceipts: "
        + paths
    }


def handle_event(event: dict, *, client: str, repo: Path = ROOT) -> dict:
    """Process one native event, returning exactly one client-compatible object."""
    kind = event.get("hook_event_name") if isinstance(event, dict) else None
    if kind not in {"UserPromptSubmit", "PreToolUse", "Stop"}:
        return {}
    state: dict = {}
    signature: Any = {"unavailable": True}
    try:
        repo = Path(repo).resolve(strict=True)
        _validate_repo(repo, event)
        session = event.get("session_id")
        if not isinstance(session, str) or not session:
            raise HookError("hook has no session identifier")
        directory = _state_directory(repo, client, session)
        lock = directory / "lock"
        if lock.is_symlink():
            raise HookError("hook lock must not be a symlink")
        with lock.open("a+") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            saved = directory / "state.json"
            if saved.is_symlink():
                raise HookError("hook state must not be a symlink")
            state = json.loads(saved.read_text()) if saved.exists() else {}
            if not isinstance(state, dict):
                state = {}
                raise HookError("hook state must be an object")
            if state and state.get("schema_version") != 1:
                raise HookError("unsupported hook state schema")
            if state and (
                not isinstance(state.get("episode"), str)
                or not state["episode"].isdigit()
                or len(state["episode"]) > 40
            ):
                raise HookError("hook state episode identifier is invalid")
            if kind == "PreToolUse" and not _may_mutate(event):
                return {}
            if (
                kind == "PreToolUse"
                and state.get("baseline_complete") is True
                and set(state.get("baselines", {})) == set(SMOKE_CASES)
                and state.get("phase") in {"active", "failed"}
            ):
                # Baseline was already established before this episode's edits.
                # Stop verifies its artifacts and all current identities again.
                return {}
            if kind == "UserPromptSubmit" and state.get("phase") in {
                "active",
                "failed",
            }:
                return _context(
                    kind,
                    "Skylos smoke evals: retained the pending starting baseline or recorded baseline failure across this request. Complete or report its matching candidate before claiming a pass.",
                )
            signature = _signature(repo)
            if kind == "UserPromptSubmit":
                state = _new_episode(state, event, signature, directory)
                response = _context(
                    kind,
                    "Skylos smoke evals armed for coding work: baseline before the first potentially mutating tool, matching candidate at Stop. Text replies and native Read/Grep/Glob run no cases; shell commands conservatively trigger a baseline. Scope is 3 smoke cases; select broader affected checks separately.",
                )
            elif kind == "PreToolUse":
                if not state or state.get("phase") in {"passed", "no_changes"}:
                    state = _new_episode(state, event, signature, directory)
                try:
                    if not state.get("baselines"):
                        if signature["source"] != state["initial_signature"]["source"]:
                            raise HookError(
                                "source changed before baseline capture; a before/after pair cannot be reconstructed automatically"
                            )
                        state["baseline_signature"] = signature
                        state["baselines"] = _run_checks(
                            repo, state, directory, "baseline", signature
                        )
                        state["baseline_complete"] = True
                    else:
                        _evidence(
                            state["baselines"], state["baseline_signature"], "baseline"
                        )
                except Exception as error:
                    state["phase"] = "failed"
                    state["last_pretool_error"] = str(error)
                    _save(directory, state)
                    raise
                state["phase"] = "active"
                response = _context(
                    kind,
                    "Skylos: before-edit smoke baseline retained (3 selected cases). Its complete existing failures, if any, remain visible. Run broader affected checks as needed. Baseline receipts: "
                    + "; ".join(state["baselines"].values()),
                )
            else:
                if not state:
                    return {
                        "systemMessage": "Skylos smoke evals were not armed; no before/after pass is claimed."
                    }
                try:
                    response = _stop(repo, state, directory, event, signature)
                except Exception as error:
                    response = _failure(
                        state,
                        signature,
                        "Required eval evidence is unavailable: " + str(error),
                        event,
                    )
            _save(directory, state)
            return response
    except Exception as error:
        message = "Skylos eval hook cannot establish required evidence: " + str(error)
        if kind == "PreToolUse":
            return _pretool_failure(message)
        if kind == "Stop":
            return _failure(state, signature, message, event)
        return _context(
            "UserPromptSubmit",
            message + ". Do not substitute another checkout's results.",
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", choices=("codex", "claude"), required=True)
    parser.add_argument("--repo", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        event = json.load(sys.stdin)
        if not isinstance(event, dict):
            raise ValueError("hook input must be an object")
    except (OSError, ValueError) as error:
        print(
            "Skylos eval hook received invalid event JSON: " + str(error),
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(
            handle_event(event, client=args.client, repo=args.repo), allow_nan=False
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
