"""Checker origin labels require an actual, comparable project baseline."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from skylos.typecheck import comparison as checks


def git(root, *args):
    result = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "tsconfig.json").write_text(
        json.dumps(
            {"compilerOptions": {"strict": True, "noEmit": True}, "include": ["*.ts"]}
        )
    )
    (root / "api.ts").write_text("export function value(): number { return 42; }\n")
    (root / "caller.ts").write_text(
        'import { value } from "./api";\nexport const answer: number = value();\n'
    )
    (root / "legacy.ts").write_text('export const oldError: number = "old";\n')
    git(root, "init", "-q")
    git(root, "add", "tsconfig.json", "api.ts", "caller.ts", "legacy.ts")
    git(
        root,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-qm",
        "baseline",
    )
    return root


@pytest.fixture
def tsc(project):
    executable = os.environ.get("SKYLOS_TEST_TSC") or shutil.which("tsc")
    if not executable:
        pytest.skip(
            "An installed TypeScript compiler is needed for the real checker test"
        )
    directory = project / "node_modules/.bin"
    directory.mkdir(parents=True)
    (directory / "tsc").symlink_to(Path(executable).resolve())
    return executable


def test_real_compiler_baseline_and_unchanged_caller(project, tsc):
    # The caller is unchanged. Its new error must survive file/changed-line scope.
    (project / "api.ts").write_text(
        'export function value(): string { return "changed"; }\n'
    )
    report = checks.run_type_check(
        project / "api.ts", base_ref="HEAD", target_files=[project / "api.ts"]
    )
    assert report["complete"] is True, report
    assert report["status"] == "fail"
    assert report["comparison"]["status"] == "complete"
    assert report["comparison"]["base_run"] is True
    assert [
        (d["file"], d["code"], d["origin"], d["scope"]) for d in report["diagnostics"]
    ] == [("caller.ts", "TS2322", "introduced", "dependency_impact")]
    assert report["project_error_count"] == 2
    assert report["out_of_scope_count"] == 1
    # The comparison doesn't create worktrees or stage user edits.
    assert git(project, "diff", "--cached", "--name-only") == ""
    assert len(git(project, "worktree", "list", "--porcelain").split("worktree ")) == 2


def test_real_preexisting_error_is_visible_but_nonblocking(project, tsc):
    report = checks.run_type_check(project, base_ref="HEAD")
    assert report["status"] == "pass", report
    assert report["counts"] == {"introduced": 0, "preexisting": 1, "unclassified": 0}
    assert report["diagnostics"][0]["file"] == "legacy.ts"


def test_real_check_without_baseline_blocks_current_errors(project, tsc):
    report = checks.run_type_check(project)
    assert report["status"] == "fail", report
    assert report["comparison"]["status"] == "not_requested"
    assert report["counts"]["unclassified"] == 1


def test_real_compiler_green_with_new_escape_still_blocks(project, tsc):
    (project / "api.ts").write_text(
        'export function value(): number { return "changed" as any; }\n'
    )
    report = checks.run_type_check(project, base_ref="HEAD")
    assert report["status"] == "fail", report
    assert report["complete"] is True
    assert report["escape_guard"] == {"status": "complete", "added": 1}
    assert any(
        d["code"] == "type-escape" and d["origin"] == "introduced"
        for d in report["diagnostics"]
    )
    assert any(
        d["code"] == "TS2322" and d["origin"] == "preexisting"
        for d in report["diagnostics"]
    )


def test_real_single_file_scope_excludes_twin(project, tsc):
    twin = project / "nested"
    twin.mkdir()
    (twin / "api.ts").write_text('export const twin: number = "bad";\n')
    config = json.loads((project / "tsconfig.json").read_text())
    config["include"] = ["**/*.ts"]
    (project / "tsconfig.json").write_text(json.dumps(config))
    report = checks.run_type_check(
        project / "api.ts", target_files=[project / "api.ts"]
    )
    assert report["status"] == "pass", report
    assert report["diagnostics"] == []
    assert report["project_error_count"] == 2
    assert report["out_of_scope_count"] == 2


def test_clean_head_with_weakened_config_is_incomplete(project, tsc):
    (project / "tsconfig.json").write_text(
        json.dumps({"compilerOptions": {"noCheck": True}, "include": ["*.ts"]})
    )
    report = checks.run_type_check(project, base_ref="HEAD")
    assert report["status"] == "incomplete", report
    assert "configuration differs" in report["comparison"]["reason"]
    assert report["comparison"]["base_run"] is False


def test_changed_dependency_environment_cannot_claim_preexisting(project, tsc):
    (project / "package-lock.json").write_text("{}\n")
    report = checks.run_type_check(project, base_ref="HEAD")
    assert report["status"] == "incomplete", report
    assert report["diagnostics"][0]["origin"] == "unclassified"
    assert "dependencies differ" in report["comparison"]["reason"]


def test_invalid_baseline_preserves_current_diagnostics(project, tsc):
    report = checks.run_type_check(project, base_ref="no-such-ref")
    assert report["status"] == "incomplete", report
    assert report["diagnostics"][0]["code"] == "TS2322"


def test_snapshot_ignores_export_ignore_and_preserves_blobs(project, tmp_path):
    helper = project / "helper.sh"
    helper.write_text("#!/bin/sh\nexit 0\n")
    helper.chmod(0o755)
    (project / ".gitattributes").write_text("legacy.ts export-ignore\n")
    git(project, "add", ".gitattributes", "helper.sh")
    git(
        project,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-qm",
        "archive attributes",
    )
    from skylos.done.base import open_comparison

    destination = tmp_path / "snapshot"
    destination.mkdir()
    checks._snapshot(open_comparison(project), destination)
    assert (destination / "legacy.ts").read_bytes() == (
        project / "legacy.ts"
    ).read_bytes()
    assert not (destination / ".git").exists()
    assert (destination / "helper.sh").stat().st_mode & 0o777 == 0o755


def test_snapshot_symlink_is_incomplete(project, tmp_path):
    (project / "link.ts").symlink_to("api.ts")
    git(project, "add", "link.ts")
    git(
        project,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-qm",
        "symlink",
    )
    from skylos.done.base import open_comparison

    with pytest.raises(ValueError, match="symlink"):
        checks._snapshot(open_comparison(project), tmp_path / "snapshot")


def test_ambiguous_moved_error_never_claims_preexisting(project):
    from skylos.done.base import open_comparison

    old = {
        "file": "legacy.ts",
        "line": 1,
        "column": 14,
        "code": "TS2322",
        "message": "bad",
        "severity": "error",
    }
    (project / "legacy.ts").write_text('export const oldError: number = "different";\n')
    head = [dict(old, origin="unclassified")]
    checks._attribute(head, [old], open_comparison(project), project)
    assert head[0]["origin"] == "unclassified"


@pytest.mark.parametrize("target_kind", ["outside", "directory", "missing"])
def test_invalid_selected_scope_never_becomes_a_clean_pass(project, target_kind):
    target = {
        "outside": project.parent / "outside.ts",
        "directory": project,
        "missing": project / "missing.ts",
    }[target_kind]
    current = {
        "status": "fail",
        "complete": True,
        "checker": "tsc",
        "comparison": {"status": "not_requested"},
        "diagnostics": [
            {
                "file": "legacy.ts",
                "line": 1,
                "column": 14,
                "code": "TS2322",
                "message": "bad",
                "severity": "error",
                "origin": "unclassified",
            }
        ],
    }
    result = checks._finish(current, [target], project)
    assert result["status"] == "incomplete"
    assert result["complete"] is False
    assert result["reason"] == "invalid_file_scope"
    assert result["diagnostics"][0]["code"] == "TS2322"


def test_filesystem_case_alias_does_not_hide_errors(project):
    alias = project / "LEGACY.ts"
    if not alias.exists():
        pytest.skip("This filesystem distinguishes upper and lower case paths")
    current = {
        "status": "fail",
        "complete": True,
        "checker": "tsc",
        "comparison": {"status": "not_requested"},
        "diagnostics": [
            {
                "file": "legacy.ts",
                "line": 1,
                "column": 14,
                "code": "TS2322",
                "message": "bad",
                "severity": "error",
                "origin": "unclassified",
            }
        ],
    }
    result = checks._finish(current, [alias], project)
    assert result["status"] == "fail"
    assert result["diagnostics"][0]["code"] == "TS2322"


@pytest.mark.parametrize(
    "timeout", [0, -1, float("nan"), float("inf"), "120", True, 3601]
)
def test_invalid_budget_never_executes_a_checker(project, monkeypatch, timeout):
    def unexpected(*args, **kwargs):
        raise AssertionError("Invalid budget must be rejected before execution")

    monkeypatch.setattr(checks, "run_project_checker", unexpected)
    result = checks.run_type_check(project, timeout_seconds=timeout)
    assert result["status"] == "incomplete"
    assert result["reason"] == "invalid_timeout"


def test_warn_alias_is_counted_as_a_warning(project):
    result = checks._finish(
        {
            "status": "pass",
            "complete": True,
            "checker": "pyrefly",
            "comparison": {"status": "not_requested"},
            "diagnostics": [
                {
                    "file": "api.ts",
                    "line": 1,
                    "column": 1,
                    "code": "warning-code",
                    "message": "note",
                    "severity": "warn",
                    "origin": "unclassified",
                }
            ],
        },
        None,
        project,
    )
    assert result["warning_count"] == 1
    assert result["error_count"] == 0
    assert result["status"] == "pass"
