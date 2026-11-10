from copy import deepcopy
from hashlib import sha256
import io
import json
import shlex
import sys

import pytest

from skylos.cleanup_execution import apply_cleanup_edit, plan_cleanup_edit
from skylos.commands.cleanup_cmd import run_cleanup_command


@pytest.fixture
def workspace(tmp_path):
    source = "import type { Shape } from './types';\nexport const count = 3;\n"
    (tmp_path / "consumer.ts").write_text(source)
    (tmp_path / "types.ts").write_text("export interface Shape { value: string }\n")
    (tmp_path / "tsconfig.json").write_text('{"compilerOptions":{"module":"ESNext"}}')
    finding = {"name": "Shape", "file": str(tmp_path / "consumer.ts"), "line": 1}
    report = {
        "analysis_errors": [],
        "analysis_summary": {
            "total_files": 2,
            "grade_categories": ["quality", "ai_defects", "dead_code"],
            "comparison_scope": {"scan_path": str(tmp_path)},
            "ai_verification": {"state": "complete"},
        },
        "unused_imports": [finding],
    }
    task = {
        "id": "a" * 64,
        "rule_id": "SKY-U002",
        "category": "dead_code",
        "file": "consumer.ts",
        "line": 1,
        "name": "Shape",
        "finding": finding,
        "source_sha256": sha256(source.encode()).hexdigest(),
        "source_anchor": None,
        "_baseline_report": report,
    }
    return tmp_path, task


def _after(task):
    report = deepcopy(task["_baseline_report"])
    report["unused_imports"] = []
    return report


def test_type_import_apply_rechecks_original_binding_and_leaves_tests_skipped(
    workspace,
):
    root, task = workspace
    provider = (root / "types.ts").read_bytes()
    edit = plan_cleanup_edit(task, root)
    assert "-import type" in edit["patch"]
    receipt = apply_cleanup_edit(edit, root, rescan=lambda: _after(task))
    assert receipt["status"] == "applied_unverified"
    assert receipt["tests"]["status"] == "skipped"
    assert receipt["rescan"]["status"] == "passed"
    assert receipt["rescan"]["original_present"] is False
    assert (root / "consumer.ts").read_text() == "export const count = 3;\n"
    assert (root / "types.ts").read_bytes() == provider


def test_provider_change_since_preview_refuses_the_edit_even_when_still_structural(
    workspace,
):
    root, task = workspace
    edit = plan_cleanup_edit(task, root)
    before = (root / "consumer.ts").read_bytes()
    (root / "types.ts").write_text("export interface Shape { value: number }\n")
    with pytest.raises(ValueError, match="proof changed"):
        apply_cleanup_edit(edit, root)
    assert (root / "consumer.ts").read_bytes() == before


@pytest.mark.parametrize(
    "file,source",
    [
        ("types.ts", "export interface Shape { value: number }\n"),
        ("types.d.ts", "export interface Shape { other: number }\n"),
        ("tsconfig.json", '{"compilerOptions":{"module":"CommonJS"}}'),
    ],
)
def test_changed_proof_dependencies_during_checks_leave_an_incomplete_receipt(
    workspace, file, source
):
    root, task = workspace
    edit = plan_cleanup_edit(task, root)

    def rescan():
        (root / file).write_text(source)
        return _after(task)

    receipt = apply_cleanup_edit(edit, root, rescan=rescan)
    assert receipt["status"] == "incomplete"
    assert receipt["applied"] is True
    assert any("resolution changed" in item for item in receipt["limitations"])
    assert (root / file).read_text() == source


def test_failed_explicit_check_rolls_back_only_the_consumer(workspace):
    root, task = workspace
    before = (root / "consumer.ts").read_bytes()
    receipt = apply_cleanup_edit(
        plan_cleanup_edit(task, root),
        root,
        test_cmd=shlex.join([sys.executable, "-c", "raise SystemExit(1)"]),
        rescan=lambda: _after(task),
    )
    assert receipt["status"] == "failed"
    assert receipt["rolled_back"] is True
    assert (root / "consumer.ts").read_bytes() == before


def test_native_typescript_queue_preview_apply_roundtrip(workspace):
    root, _ = workspace

    def run(*args):
        output = io.StringIO()
        code = run_cleanup_command(
            [str(root), *args, "--format", "json"], stdout=output
        )
        report = json.loads(output.getvalue())
        assert code == 0, report
        return report

    queue = run()
    task = next(row for row in queue["tasks"] if row["rule_id"] == "SKY-U002")
    preview = run("--task", task["id"])
    assert "-import type" in preview["edit"]["patch"]
    applied = run("--task", task["id"], "--apply")
    assert applied["execution"]["status"] == "applied_unverified"
    assert applied["execution"]["rescan"]["status"] == "passed"
    assert applied["execution"]["rescan"]["original_present"] is False
