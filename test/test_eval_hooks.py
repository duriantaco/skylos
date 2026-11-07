"""Behavioral contracts for native agent hook coordination, using sealed receipts."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

pytest.importorskip(
    "fcntl", reason="Native local eval hooks currently require POSIX locking"
)

from skylos.benchmarks import eval_hooks as hooks  # noqa: E402
from skylos.benchmarks import eval_workflow as workflow  # noqa: E402
from test.fixture_paths import write_fixture  # noqa: E402


def _hash(value):
    return hashlib.sha256(str(value).encode()).hexdigest()


@pytest.fixture
def rig(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "scripts").mkdir()
    (repo / "scripts/eval_check.py").write_text("# trusted test runner\n")
    (repo / "code.py").write_text("original\n")
    (repo / "fixture.txt").write_text("reviewed fixture\n")
    (repo / "grader.txt").write_text("reviewed grader\n")
    control = {
        "environment": "stable",
        "tools": "stable",
        "fault": False,
        "incomplete": False,
        "unresolved": False,
        "crash": False,
        "exit_mismatch": False,
        "calls": [],
        "signatures": 0,
    }

    def signature(root):
        control["signatures"] += 1
        inputs = {}
        for suite in hooks.SMOKE_CASES:
            inputs[suite] = {
                "dataset_sha256": _hash((root / "fixture.txt").read_text()),
                "harness_sha256": _hash((root / "grader.txt").read_text()),
                "environment_sha256": _hash(control["environment"]),
                "options": {"scanner": "skylos", "strict_labels": suite == "dead-code"},
            }
        return {
            "source": _hash((root / "code.py").read_text()),
            "inputs": inputs,
            "external_tools": {"digest": _hash(control["tools"])},
        }

    def invoke(root, action, suite, output, baseline=None):
        control["calls"].append((action, suite, output))
        if control["crash"]:
            output.mkdir(parents=True)
            return 2, "", "simulated worker failure"
        sig = signature(root)
        cases = []
        for case_id in hooks.SMOKE_CASES[suite]:
            failing = control["fault"] and case_id == "ssrf-tainted-host"
            incomplete = control["incomplete"] and case_id == "ssrf-tainted-host"
            failures = (
                [
                    {
                        "failure_type": "expectation",
                        "category": "danger",
                        "mode": "present",
                        "expected": "SKY-D216",
                        "found": [],
                    }
                ]
                if failing
                else []
            )
            cases.append(
                {
                    "id": case_id,
                    "status": "incomplete"
                    if incomplete
                    else "failed"
                    if failing
                    else "passed",
                    "failures": failures,
                    "findings": [],
                    "unresolved_findings": [{"rule_id": "SKY-D999"}]
                    if control["unresolved"]
                    else [],
                }
            )
        receipt = {
            "schema_version": 1,
            "phase": action,
            "suite": suite,
            "case_ids": list(hooks.SMOKE_CASES[suite]),
            "inputs": sig["inputs"][suite],
            "source": {"snapshot_sha256": sig["source"]},
            "source_unchanged": True,
            "runtime_errors": [],
            "cases": cases,
            "elapsed_seconds": 0.1,
        }
        output.mkdir(parents=True)
        artifact = write_fixture(
            tmp_path, output.relative_to(tmp_path) / "actual.json", json.dumps(cases)
        )
        receipt["artifacts"] = {
            "actual.json": hashlib.sha256(artifact.read_bytes()).hexdigest()
        }
        workflow._save_receipt(output / "receipt.json", receipt)
        if action == "baseline":
            code = (
                1
                if any(
                    c["status"] != "passed" or c["unresolved_findings"] for c in cases
                )
                else 0
            )
        else:
            code = hooks.compare_receipts(workflow.load_receipt(baseline), receipt)[
                "exit_code"
            ]
        if control["exit_mismatch"]:
            code = 1 - code
        return code, "scoped test execution\n", ""

    monkeypatch.setattr(hooks, "_signature", signature)
    monkeypatch.setattr(hooks, "_invoke", invoke)

    def event(kind, **extra):
        payload = {
            "hook_event_name": kind,
            "cwd": str(repo),
            "session_id": "session",
            "prompt_id": "request",
            **extra,
        }
        return hooks.handle_event(payload, client="claude", repo=repo)

    def edit():
        return event(
            "PreToolUse",
            tool_name="Edit",
            tool_input={"file_path": str(repo / "code.py")},
        )

    def state():
        return json.loads(
            next((repo / ".skylos/evals/hooks").glob("*/state.json")).read_text()
        )

    return repo, control, event, edit, state


def test_chat_and_native_reads_do_not_run_cases(rig):
    _, control, event, _, state = rig
    event("UserPromptSubmit", prompt="What does this mean?")
    for name in ("Read", "Grep", "Glob"):
        assert event("PreToolUse", tool_name=name, tool_input={}) == {}
    assert event("Stop") == {}
    assert control["calls"] == []
    assert state()["phase"] == "no_changes"


@pytest.mark.parametrize(
    "name,input",
    [
        ("Edit", {}),
        ("Write", {}),
        ("Bash", {"command": "rg --pre malicious pattern app.py"}),
        ("Bash", {"command": "pwd"}),
        ("Agent", {}),
        ("mcp__filesystem__write_file", {}),
    ],
)
def test_baseline_precedes_first_potential_mutation(rig, name, input):
    repo, control, event, _, state = rig
    event("UserPromptSubmit")
    result = event("PreToolUse", tool_name=name, tool_input=input)
    assert "permissionDecision" not in result.get("hookSpecificOutput", {})
    assert [(a, s) for a, s, _ in control["calls"]] == [
        ("baseline", "security"),
        ("baseline", "dead-code"),
    ]
    assert state()["baseline_signature"]["source"] == _hash(
        (repo / "code.py").read_text()
    )


def test_subsequent_edits_do_not_repeat_fingerprints_or_cases(rig):
    repo, control, event, edit, _ = rig
    event("UserPromptSubmit")
    edit()
    previous = control["signatures"]
    (repo / "code.py").write_text("changed\n")
    assert edit() == {}
    assert (
        event("PreToolUse", tool_name="Bash", tool_input={"command": "python edit.py"})
        == {}
    )
    assert control["signatures"] == previous
    assert len(control["calls"]) == 2


def test_unchanged_source_reuses_baseline_with_explicit_label(rig):
    _, control, event, edit, state = rig
    event("UserPromptSubmit")
    edit()
    result = event("Stop")
    assert "reused verified baseline" in result["systemMessage"]
    assert state()["phase"] == "passed"
    assert len(control["calls"]) == 2


def test_candidate_runs_after_change_and_exact_success_can_be_reused(rig):
    repo, control, event, edit, state = rig
    event("UserPromptSubmit")
    edit()
    (repo / "code.py").write_text("fixed\n")
    assert "PASS" in event("Stop")["systemMessage"]
    assert len(control["calls"]) == 4
    assert "Reused verified unchanged candidate" in event("Stop")["systemMessage"]
    assert len(control["calls"]) == 4
    assert state()["phase"] == "passed"


def test_failed_candidate_retains_baseline_across_steering_and_avoids_loop(rig):
    repo, control, event, edit, state = rig
    event("UserPromptSubmit")
    edit()
    original = copy.deepcopy(state()["baselines"])
    (repo / "code.py").write_text("broken\n")
    control["fault"] = True
    assert event("Stop")["decision"] == "block"
    assert "remain FAILED" in event("Stop", stop_hook_active=True)["systemMessage"]
    assert len(control["calls"]) == 4
    event("UserPromptSubmit", prompt_id="steering", prompt="Why did that fail?")
    assert state()["baselines"] == original
    assert "remain FAILED" in event("Stop")["systemMessage"]
    assert len(control["calls"]) == 4
    edit()
    control["fault"] = False
    (repo / "code.py").write_text("fixed again\n")
    assert "PASS" in event("Stop")["systemMessage"]
    assert state()["baselines"] == original


@pytest.mark.parametrize("change", ["fixture", "grader", "environment", "tools"])
def test_changed_eval_inputs_block_comparison_instead_of_reusing_green(rig, change):
    repo, control, event, edit, _ = rig
    event("UserPromptSubmit")
    edit()
    if change in {"fixture", "grader"}:
        (repo / (change + ".txt")).write_text("changed definition\n")
    else:
        control[change] = "changed"
    response = event("Stop")
    assert response["decision"] == "block"
    assert "matching reviewed inputs" in response["reason"]
    assert len(control["calls"]) == 2


def test_changed_source_invalidates_success_cache(rig):
    repo, control, event, edit, _ = rig
    event("UserPromptSubmit")
    edit()
    (repo / "code.py").write_text("candidate one\n")
    event("Stop")
    (repo / "code.py").write_text("candidate two\n")
    event("Stop")
    assert len(control["calls"]) == 6


def test_modified_candidate_artifacts_cannot_reuse_success(rig):
    repo, control, event, edit, state = rig
    event("UserPromptSubmit")
    edit()
    (repo / "code.py").write_text("candidate\n")
    event("Stop")
    (Path(state()["candidates"]["security"]) / "actual.json").write_text("corrupted")
    response = event("Stop")
    assert "Ran matching candidate" in response["systemMessage"]
    assert len(control["calls"]) == 6


def test_missing_before_edit_baseline_stays_failed_across_new_prompt(rig):
    repo, control, event, _, state = rig
    event("UserPromptSubmit")
    (repo / "code.py").write_text("unobserved mutation\n")
    assert event("Stop")["decision"] == "block"
    event("UserPromptSubmit", prompt_id="continuation")
    assert state()["phase"] == "failed"
    assert "remain FAILED" in event("Stop")["systemMessage"]
    assert control["calls"] == []


def test_complete_existing_failure_allows_editing_but_does_not_pass(rig):
    _, control, event, edit, _ = rig
    control["fault"] = True
    event("UserPromptSubmit")
    assert "permissionDecision" not in edit().get("hookSpecificOutput", {})
    assert event("Stop")["decision"] == "block"


def test_unresolved_complete_baseline_is_not_an_execution_error(rig):
    _, control, event, edit, _ = rig
    control["unresolved"] = True
    event("UserPromptSubmit")
    response = edit()
    assert "permissionDecision" not in response.get("hookSpecificOutput", {})
    assert event("Stop")["decision"] == "block"


def test_incomplete_baseline_blocks_edits(rig):
    _, control, event, edit, _ = rig
    control["incomplete"] = True
    event("UserPromptSubmit")
    assert edit()["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_failed_baseline_attempt_uses_fresh_paths_on_retry(rig):
    _, control, event, edit, _ = rig
    event("UserPromptSubmit")
    control["crash"] = True
    assert edit()["hookSpecificOutput"]["permissionDecision"] == "deny"
    failed_path = control["calls"][0][2]
    control["crash"] = False
    assert "permissionDecision" not in edit().get("hookSpecificOutput", {})
    assert all(path != failed_path for _, _, path in control["calls"][1:])


def test_candidate_exit_status_inconsistency_is_not_green(rig):
    repo, control, event, edit, _ = rig
    event("UserPromptSubmit")
    edit()
    (repo / "code.py").write_text("candidate\n")
    control["exit_mismatch"] = True
    response = event("Stop")
    assert response["decision"] == "block"
    assert "exit status disagrees" in response["reason"]
    previous = len(control["calls"])
    assert "remain FAILED" in event("Stop")["systemMessage"]
    assert len(control["calls"]) == previous


@pytest.mark.parametrize("field", ["cwd", "workdir", "file_path"])
def test_explicit_tool_target_outside_repo_is_rejected(rig, tmp_path, field):
    _, control, event, _, _ = rig
    response = event(
        "PreToolUse", tool_name="Write", tool_input={field: str(tmp_path / "other")}
    )
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert not control["calls"]


def test_missing_runner_is_unavailable_not_a_different_checkout_pass(rig):
    repo, control, event, edit, _ = rig
    (repo / "scripts/eval_check.py").unlink()
    assert (
        "absent in this checkout"
        in event("UserPromptSubmit")["hookSpecificOutput"]["additionalContext"]
    )
    assert edit()["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert not control["calls"]


def test_malicious_identifier_cannot_escape_hook_directory(rig):
    repo, _, event, _, _ = rig
    event("UserPromptSubmit", session_id="../../outside/secret")
    files = list((repo / ".skylos/evals/hooks").glob("*/state.json"))
    assert len(files) == 1
    assert len(files[0].parent.name) == 64
    assert not (repo.parent / "outside").exists()


@pytest.mark.parametrize("target", ["state.json", "state.tmp", "lock"])
def test_state_file_symlinks_fail_closed(rig, tmp_path, target):
    repo, _, event, edit, _ = rig
    event("UserPromptSubmit")
    directory = next((repo / ".skylos/evals/hooks").glob("*/state.json")).parent
    path = directory / target
    if path.exists():
        path.unlink()
    outside = tmp_path / "outside.json"
    outside.write_text("[]")
    path.symlink_to(outside)
    assert edit()["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert outside.read_text() == "[]"


def test_malformed_state_and_unexpected_errors_fail_closed(rig, monkeypatch):
    repo, _, event, edit, _ = rig
    event("UserPromptSubmit")
    path = next((repo / ".skylos/evals/hooks").glob("*/state.json"))
    path.write_text("[]")
    assert edit()["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert event("Stop")["decision"] == "block"
    path.unlink()
    monkeypatch.setattr(
        hooks,
        "_signature",
        lambda root: (_ for _ in ()).throw(RuntimeError("unexpected")),
    )
    assert edit()["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert event("Stop", stop_hook_active=True)["systemMessage"]


def test_external_binary_content_at_same_path_changes_identity(tmp_path, monkeypatch):
    binary = tmp_path / "rg"
    binary.write_bytes(b"first executable")
    binary.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    before = hooks._tool_identity()
    binary.write_bytes(b"changed executable")
    after = hooks._tool_identity()
    assert before["path_sha256"] == after["path_sha256"]
    assert before["rg"]["sha256"] != after["rg"]["sha256"]


def test_parallel_tools_share_one_before_edit_baseline(rig, monkeypatch):
    _, control, event, edit, state = rig
    event("UserPromptSubmit")
    invoke = hooks._invoke

    def slow_invoke(*args, **kwargs):
        time.sleep(0.03)
        return invoke(*args, **kwargs)

    monkeypatch.setattr(hooks, "_invoke", slow_invoke)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: edit(), range(2)))
    assert all(
        "permissionDecision" not in r.get("hookSpecificOutput", {}) for r in results
    )
    assert len(control["calls"]) == 2
    assert state()["baseline_complete"] is True


def test_source_change_while_cached_artifacts_are_verified_blocks_clean_claim(
    rig, monkeypatch
):
    repo, _, event, edit, _ = rig
    event("UserPromptSubmit")
    edit()
    (repo / "code.py").write_text("candidate one\n")
    event("Stop")
    load = hooks._load
    changed = False

    def edit_during_load(path):
        nonlocal changed
        result = load(path)
        if result["phase"] == "candidate" and not changed:
            changed = True
            (repo / "code.py").write_text("changed during evidence read\n")
        return result

    monkeypatch.setattr(hooks, "_load", edit_during_load)
    response = event("Stop")
    assert response["decision"] == "block"
    assert "changed while verifying" in response["reason"]


def test_unsafe_loaded_episode_cannot_redirect_run_or_history_paths(rig):
    repo, control, event, edit, _ = rig
    event("UserPromptSubmit")
    path = next((repo / ".skylos/evals/hooks").glob("*/state.json"))
    state = json.loads(path.read_text())
    state["episode"] = "../../outside"
    path.write_text(json.dumps(state))
    assert edit()["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert not control["calls"]


@pytest.mark.parametrize("field", ["workdir", "file_path"])
def test_explicit_nested_checkout_is_not_validated_as_parent(rig, field):
    repo, control, event, _, _ = rig
    nested = repo / ".claude/worktrees/other"
    nested.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(nested)], check=True)
    value = nested if field == "workdir" else nested / "app.py"
    response = event("PreToolUse", tool_name="Write", tool_input={field: str(value)})
    assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert not control["calls"]
