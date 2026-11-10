"""Cleanup applies only reviewed source and never treats skipped checks as passes."""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import ast
import inspect
import json
import shlex
import sys
import textwrap

import pytest

from skylos.cleanup_execution import (
    apply_cleanup_edit,
    compare_cleanup_reports,
    plan_cleanup_edit,
)
from skylos.cleanup_identity import source_anchor, source_anchor_digest


def _report(root, rows=(), **changes):
    return {
        "quality": list(rows),
        "analysis_errors": [],
        "analysis_summary": {
            "total_files": 1,
            "grade_categories": ["quality", "ai_defects", "dead_code"],
            "comparison_scope": {"scan_path": str(root), "excluded_folders": []},
            "ai_verification": {"state": "complete"},
        },
        **changes,
    }


def _task(
    root,
    source="import math\nanswer = 42\n",
    *,
    rule="SKY-U002",
    line=1,
    name="math",
    column=None,
):
    path = root / "app.py"
    path.write_text(source, encoding="utf-8", newline="")
    finding = {
        "rule_id": rule,
        "file": str(path),
        "line": line,
        "name": name,
        "severity": "LOW",
    }
    if column is not None:
        finding["col"] = column
    section = (
        "unused_imports"
        if rule == "SKY-U002"
        else "unused_functions"
        if rule == "SKY-U001"
        else "quality"
    )
    baseline = _report(root, **{section: [deepcopy(finding)]})
    return {
        "id": "task-1",
        "rule_id": rule,
        "file": "app.py",
        "line": line,
        "name": name,
        "category": "dead_code" if rule.startswith("SKY-U") else "quality",
        "finding": finding,
        "source_sha256": sha256(path.read_bytes()).hexdigest(),
        "source_anchor": source_anchor_digest(finding, root),
        "scope": {
            "target": str(root),
            "project_root": str(root),
            "config_digest": "fixed",
        },
        "_baseline_report": baseline,
    }


def _command(code):
    return f"{shlex.quote(sys.executable)} -c {shlex.quote(code)}"


def _passing_tests(root):
    (root / "test_app.py").write_text(
        "import app\n\ndef test_answer():\n    assert app.answer == 42\n"
    )
    return shlex.join([sys.executable, "-m", "pytest", "-q", "test_app.py"])


def test_import_preview_reuses_codemod_and_writes_nothing(tmp_path):
    task = _task(tmp_path)
    before = (tmp_path / "app.py").read_bytes()
    edit = plan_cleanup_edit(task, tmp_path)
    assert edit["status"] == "planned"
    assert "-import math" in edit["patch"]
    assert edit["_replacement"] == "answer = 42\n"
    assert (tmp_path / "app.py").read_bytes() == before
    assert edit["source_sha256"] != edit["applied_sha256"]


def test_function_preview_preserves_surrounding_code(tmp_path):
    task = _task(
        tmp_path,
        "def unused():\n    return 1\n\nanswer = 42\n",
        rule="SKY-U001",
        name="unused",
    )
    edit = plan_cleanup_edit(task, tmp_path)
    assert "def unused" not in edit["_replacement"]
    assert "answer = 42" in edit["_replacement"]


@pytest.mark.parametrize(
    "source",
    [
        "@register\ndef unused():\n    pass\n",
        "def unused(value=register()):\n    pass\n",
        "def unused(value: register()):\n    pass\n",
        "def unused(*values: register()):\n    pass\n",
    ],
)
def test_definition_time_effects_require_manual_review(tmp_path, source):
    line = 2 if source.startswith("@") else 1
    task = _task(tmp_path, source, rule="SKY-U001", name="unused", line=line)
    with pytest.raises(ValueError, match="definition-time|annotations"):
        plan_cleanup_edit(task, tmp_path)


@pytest.mark.parametrize(
    "source",
    [
        "import local_plugin\n",
        "from local_plugin import factory\n",
        "import math_plugin\n",
    ],
)
def test_unknown_import_effects_are_not_automatically_removed(tmp_path, source):
    name = source.split()[1]
    task = _task(tmp_path, source, name=name)
    with pytest.raises(ValueError, match="side effects"):
        plan_cleanup_edit(task, tmp_path)


def test_stdlib_lookalike_in_project_is_not_trusted(tmp_path):
    task = _task(tmp_path)
    (tmp_path / "math.py").write_text("raise RuntimeError('plugin side effect')\n")
    with pytest.raises(ValueError, match="shadow"):
        plan_cleanup_edit(task, tmp_path)


def test_l038_revalidates_builtin_and_preserves_format_spec_and_comments(tmp_path):
    source = (
        'def render(value):\n    return f"result {str(value):>10}"  # retain this\n'
    )
    task = _task(
        tmp_path, source, rule="SKY-L038", line=2, name="str() in f-string", column=21
    )
    edit = plan_cleanup_edit(task, tmp_path)
    assert edit["_replacement"] == source.replace("{str(value):>10}", "{value!s:>10}")

    def original(value: object) -> str:
        return f"result {str(value):>10}"

    def rewritten(value: object) -> str:
        return f"result {value!s:>10}"

    # Bind the generated return expressions to directly defined test functions.
    # The complete-source assertion above separately preserves the comment.
    for candidate, reference in ((source, original), (edit["_replacement"], rewritten)):
        candidate_return = ast.parse(candidate).body[0].body[0]
        reference_return = (
            ast.parse(textwrap.dedent(inspect.getsource(reference))).body[0].body[0]
        )
        assert ast.dump(candidate_return, include_attributes=False) == ast.dump(
            reference_return, include_attributes=False
        )
    for value in [1, None, "abc", ["x"]]:
        assert original(value) == rewritten(value)


def test_l038_refuses_shadowed_builtin_and_ruff_disabled_rule(tmp_path):
    source = 'def render(value, str):\n    return f"{str(value)}"\n'
    task = _task(
        tmp_path, source, rule="SKY-L038", line=2, name="str() in f-string", column=14
    )
    with pytest.raises(ValueError, match="no longer proves"):
        plan_cleanup_edit(task, tmp_path)
    task = _task(
        tmp_path,
        'result = f"{str(value)}"\n',
        rule="SKY-L038",
        name="str() in f-string",
        column=12,
    )
    (tmp_path / "pyproject.toml").write_text('[tool.ruff.lint]\nignore = ["RUF010"]\n')
    with pytest.raises(ValueError, match="no longer proves"):
        plan_cleanup_edit(task, tmp_path)


def test_stale_hash_and_forged_anchor_cannot_plan(tmp_path):
    task = _task(tmp_path)
    task["source_anchor"] = "f" * 64
    with pytest.raises(ValueError, match="anchor"):
        plan_cleanup_edit(task, tmp_path)
    task = _task(tmp_path)
    (tmp_path / "app.py").write_text("user = 7\n")
    with pytest.raises(ValueError, match="stale"):
        plan_cleanup_edit(task, tmp_path)


def test_source_symlinks_parent_symlinks_hardlinks_and_escape_are_rejected(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    task = _task(root)
    outside = tmp_path / "outside.py"
    outside.write_text("import math\n")
    (root / "app.py").unlink()
    (root / "app.py").symlink_to(outside)
    with pytest.raises((OSError, ValueError)):
        plan_cleanup_edit(task, root)
    task["file"] = "../outside.py"
    with pytest.raises(ValueError):
        plan_cleanup_edit(task, root)
    (root / "app.py").unlink()
    task = _task(root)
    linked = root / "linked.py"
    linked.hardlink_to(root / "app.py")
    with pytest.raises(ValueError, match="one link"):
        plan_cleanup_edit(task, root)
    linked.unlink()
    directory = root / "alias"
    directory.symlink_to(tmp_path, target_is_directory=True)
    task["file"] = "alias/outside.py"
    with pytest.raises((OSError, ValueError)):
        plan_cleanup_edit(task, root)


def test_duplicate_source_anchors_require_explicit_manual_review(tmp_path):
    task = _task(tmp_path, "import math\nimport math\n", line=1)
    with pytest.raises(ValueError, match="ambiguous"):
        plan_cleanup_edit(task, tmp_path)


def test_atomic_apply_without_tests_or_rescan_is_unverified(tmp_path):
    edit = plan_cleanup_edit(_task(tmp_path), tmp_path)
    (tmp_path / "app.py").chmod(0o640)
    receipt = apply_cleanup_edit(edit, tmp_path)
    assert receipt["status"] == "applied_unverified"
    assert receipt["tests"]["status"] == "skipped"
    assert receipt["rescan"]["status"] == "skipped"
    assert (tmp_path / "app.py").read_text() == "answer = 42\n"
    assert (tmp_path / "app.py").stat().st_mode & 0o777 == 0o640
    assert not list(tmp_path.glob(".skylos-cleanup-*"))


def test_stale_and_tampered_edits_cannot_overwrite_changes(tmp_path):
    edit = plan_cleanup_edit(_task(tmp_path), tmp_path)
    edit["applied_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="patch changed"):
        apply_cleanup_edit(edit, tmp_path)
    edit = plan_cleanup_edit(_task(tmp_path), tmp_path)
    (tmp_path / "app.py").write_text("new_user_change = True\n")
    with pytest.raises(ValueError, match="stale"):
        apply_cleanup_edit(edit, tmp_path)
    assert (tmp_path / "app.py").read_text() == "new_user_change = True\n"


def test_failed_explicit_test_rolls_back_exact_applied_bytes(tmp_path):
    task = _task(tmp_path)
    original = (tmp_path / "app.py").read_bytes()
    receipt = apply_cleanup_edit(
        plan_cleanup_edit(task, tmp_path),
        tmp_path,
        test_cmd=_command("raise SystemExit(3)"),
    )
    assert receipt["status"] == "failed"
    assert receipt["tests"]["status"] == "failed"
    assert receipt["rolled_back"] is True
    assert receipt["applied"] is False
    assert (tmp_path / "app.py").read_bytes() == original


def test_failed_test_preserves_a_user_change_instead_of_rollback(tmp_path, monkeypatch):
    edit = plan_cleanup_edit(_task(tmp_path), tmp_path)

    def concurrent_edit(root, argv, **kwargs):
        assert root == tmp_path
        assert argv == ["pytest", "-q"]
        (tmp_path / "app.py").write_text("preserve_this_edit = True\n")
        return {
            "status": "failed",
            "returncode": 1,
            "observed": True,
            "evidence": "pytest_junit",
            "count": 1,
        }

    monkeypatch.setattr("skylos.cleanup_checks.run_cleanup_tests", concurrent_edit)
    receipt = apply_cleanup_edit(edit, tmp_path, test_cmd="pytest -q")
    assert receipt["status"] == "failed"
    assert receipt["rolled_back"] is False
    assert (tmp_path / "app.py").read_text() == "preserve_this_edit = True\n"
    assert any("Rollback was not applied" in line for line in receipt["limitations"])


@pytest.mark.parametrize(
    "command", ["pytest; echo unsafe", "pytest | cat", "", "pytest $(whoami)"]
)
def test_unsafe_test_commands_are_rejected_before_writing(tmp_path, command):
    edit = plan_cleanup_edit(_task(tmp_path), tmp_path)
    before = (tmp_path / "app.py").read_bytes()
    with pytest.raises(ValueError, match="test command"):
        apply_cleanup_edit(edit, tmp_path, test_cmd=command)
    assert (tmp_path / "app.py").read_bytes() == before


def test_test_command_unavailable_is_incomplete_never_passed(tmp_path):
    edit = plan_cleanup_edit(_task(tmp_path), tmp_path)
    receipt = apply_cleanup_edit(
        edit, tmp_path, test_cmd="skylos-nonexistent-test-binary"
    )
    assert receipt["status"] == "incomplete"
    assert receipt["tests"]["status"] == "incomplete"
    assert receipt["applied"] is True


def test_complete_rescan_and_authorized_tests_are_required_for_verified(tmp_path):
    edit = plan_cleanup_edit(_task(tmp_path), tmp_path)
    receipt = apply_cleanup_edit(
        edit,
        tmp_path,
        test_cmd=_passing_tests(tmp_path),
        rescan=lambda: _report(tmp_path),
    )
    assert receipt["status"] == "verified"
    assert receipt["tests"]["status"] == "passed"
    assert receipt["rescan"]["status"] == "passed"
    assert receipt["rescan"]["original_present"] is False


def test_rescan_alone_does_not_claim_runtime_verification(tmp_path):
    edit = plan_cleanup_edit(_task(tmp_path), tmp_path)
    receipt = apply_cleanup_edit(edit, tmp_path, rescan=lambda: _report(tmp_path))
    assert receipt["status"] == "applied_unverified"
    assert receipt["rescan"]["status"] == "passed"
    assert receipt["tests"]["status"] == "skipped"


def test_zero_exit_without_observed_tests_cannot_verify_a_cleanup(tmp_path):
    edit = plan_cleanup_edit(_task(tmp_path), tmp_path)
    receipt = apply_cleanup_edit(
        edit, tmp_path, test_cmd=_command("pass"), rescan=lambda: _report(tmp_path)
    )
    assert receipt["status"] == "applied_unverified"
    assert receipt["tests"]["returncode"] == 0
    assert receipt["tests"]["evidence"] == "exit_code"
    assert receipt["tests"]["observed"] is False
    assert receipt["rescan"]["status"] == "passed"


def test_source_removed_after_rescan_preserves_the_incomplete_receipt(
    tmp_path, monkeypatch
):
    import skylos.cleanup_execution as execution

    edit = plan_cleanup_edit(_task(tmp_path), tmp_path)
    compare = execution.compare_cleanup_reports

    def concurrent_removal(*args, **kwargs):
        result = compare(*args, **kwargs)
        (tmp_path / "app.py").unlink()
        return result

    monkeypatch.setattr(execution, "compare_cleanup_reports", concurrent_removal)
    receipt = apply_cleanup_edit(
        edit,
        tmp_path,
        test_cmd=_passing_tests(tmp_path),
        rescan=lambda: _report(tmp_path),
    )
    assert receipt["status"] == "incomplete"
    assert receipt["tests"]["status"] == receipt["rescan"]["status"] == "passed"
    assert receipt["rolled_back"] is False
    assert not (tmp_path / "app.py").exists()
    assert "source changed" in receipt["limitations"][-1]


def test_new_high_risk_finding_rolls_back_but_existing_shift_does_not(tmp_path):
    high = {
        "rule_id": "SKY-L012",
        "file": str(tmp_path / "app.py"),
        "line": 20,
        "name": "check_auth",
        "message": "Missing symbol",
        "severity": "CRITICAL",
    }
    task = _task(tmp_path)
    task["_baseline_report"]["ai_defects"] = [high]
    shifted = {**high, "line": 19}
    after = _report(tmp_path, ai_defects=[shifted])
    receipt = apply_cleanup_edit(
        plan_cleanup_edit(task, tmp_path),
        tmp_path,
        test_cmd=_passing_tests(tmp_path),
        rescan=lambda: after,
    )
    assert receipt["status"] == "verified"
    task = _task(tmp_path)
    receipt = apply_cleanup_edit(
        plan_cleanup_edit(task, tmp_path),
        tmp_path,
        test_cmd=_command("pass"),
        rescan=lambda: after,
    )
    assert receipt["status"] == "failed"
    assert receipt["rolled_back"] is True
    assert receipt["rescan"]["new_findings"] == [shifted]


def test_incomplete_or_changed_scope_never_verifies(tmp_path):
    for change in ["scope", "analysis", "ai"]:
        task = _task(tmp_path)
        after = _report(tmp_path)
        if change == "scope":
            after["analysis_summary"]["comparison_scope"]["scan_path"] = str(
                tmp_path / "other"
            )
        elif change == "analysis":
            after["analysis_errors"] = [{"kind": "worker_crash"}]
        else:
            after["analysis_summary"]["ai_verification"]["state"] = "incomplete"
        receipt = apply_cleanup_edit(
            plan_cleanup_edit(task, tmp_path),
            tmp_path,
            test_cmd=_command("pass"),
            rescan=lambda: after,
        )
        assert receipt["status"] == "incomplete"
        assert receipt["rescan"]["status"] == "incomplete"


def test_comparator_ignores_advice_as_risk_but_preserves_identity_variants(tmp_path):
    advice = {"rule_id": "SKY-Q301", "file": "app.py", "line": 1, "severity": "HIGH"}
    assert (
        compare_cleanup_reports(
            _report(tmp_path), _report(tmp_path, [advice]), project_root=tmp_path
        )["status"]
        == "passed"
    )
    missing = {
        "rule_id": "SKY-L012",
        "file": "app.py",
        "name": "security_check",
        "severity": "HIGH",
    }
    outcome = compare_cleanup_reports(
        _report(tmp_path),
        _report(tmp_path, ai_defects=[missing]),
        project_root=tmp_path,
    )
    assert outcome["status"] == "failed"
    assert outcome["new_findings"] == [missing]


def test_source_anchors_survive_line_shifts_and_distinguish_owners(tmp_path):
    path = tmp_path / "app.py"
    path.write_text("def first():\n    return 42\n\ndef second():\n    return 42\n")
    first = {"file": str(path), "line": 2}
    second = {**first, "line": 5}
    original = source_anchor_digest(first, tmp_path)
    assert original and original != source_anchor_digest(second, tmp_path)
    assert json.loads(source_anchor(first, tmp_path))["symbol"] == "first"
    path.write_text("\n" + path.read_text())
    assert source_anchor_digest({**first, "line": 3}, tmp_path) == original


def test_native_unused_rows_without_catalog_ids_still_use_family_evidence(tmp_path):
    task = _task(tmp_path)
    task["_baseline_report"]["unused_imports"][0].pop("rule_id")
    assert plan_cleanup_edit(task, tmp_path)["rule_id"] == "SKY-U002"
    task["_baseline_report"]["unused_imports"] = []
    with pytest.raises(ValueError, match="originating report"):
        plan_cleanup_edit(task, tmp_path)


def test_identity_cache_is_per_build_and_parses_each_file_once(tmp_path, monkeypatch):
    import skylos.cleanup_identity as identity

    task = _task(tmp_path)
    parse = identity.ast.parse
    calls = []

    def tracked(*args, **kwargs):
        calls.append(args[0])
        return parse(*args, **kwargs)

    monkeypatch.setattr(identity.ast, "parse", tracked)
    cache = {}
    first = source_anchor_digest(task["finding"], tmp_path, cache=cache)
    assert first == source_anchor_digest(task["finding"], tmp_path, cache=cache)
    assert len(calls) == 1
    (tmp_path / "app.py").write_text("import json\n")
    assert source_anchor_digest(task["finding"], tmp_path, cache={}) != first
    assert len(calls) == 2


@pytest.mark.parametrize(
    "section,value",
    [
        ("quality", {}),
        ("danger", [None]),
        ("ai_defects", "not a list"),
        ("publisher_change_findings", [42]),
        ("architecture_metrics", {"advisories": {}}),
        ("architecture_metrics", {"advisories": [{"signals": [None]}]}),
    ],
)
def test_malformed_scanner_evidence_cannot_verify(tmp_path, section, value):
    before = _report(tmp_path)
    after = _report(tmp_path, **{section: value})
    result = compare_cleanup_reports(before, after, project_root=tmp_path)
    assert result["status"] == "incomplete"
    assert any("Malformed" in limitation for limitation in result["limitations"])


def test_medium_defects_and_evidence_changes_are_regressions(tmp_path):
    old = {
        "rule_id": "SKY-L012",
        "file": "app.py",
        "name": "auth",
        "severity": "HIGH",
        "evidence": {"symbol": "first", "line": 2},
    }
    shifted = {**old, "line": 1, "evidence": {"symbol": "first", "line": 1}}
    new = {**old, "evidence": {"symbol": "different", "line": 1}}
    baseline = _report(tmp_path, ai_defects=[old])
    assert (
        compare_cleanup_reports(
            baseline, _report(tmp_path, ai_defects=[shifted]), project_root=tmp_path
        )["status"]
        == "passed"
    )
    assert (
        compare_cleanup_reports(
            baseline, _report(tmp_path, ai_defects=[new]), project_root=tmp_path
        )["status"]
        == "failed"
    )
    defect = {"rule_id": "SKY-L033", "file": "app.py", "severity": "MEDIUM"}
    assert (
        compare_cleanup_reports(
            _report(tmp_path), _report(tmp_path, [defect]), project_root=tmp_path
        )["status"]
        == "failed"
    )


def test_comparator_caller_can_require_its_analyzer_families(tmp_path):
    before = _report(tmp_path)
    after = _report(tmp_path)
    outcome = compare_cleanup_reports(
        before, after, project_root=tmp_path, required_categories=("security",)
    )
    assert outcome["status"] == "incomplete"
    assert "Required analyzer checks were not enabled." in outcome["limitations"]


def test_original_anchor_returning_during_rescan_is_not_verified(tmp_path):
    task = _task(tmp_path)
    edit = plan_cleanup_edit(task, tmp_path)

    def stale_source():
        (tmp_path / "app.py").write_text(edit["_source"])
        return task["_baseline_report"]

    receipt = apply_cleanup_edit(
        edit, tmp_path, test_cmd=_command("pass"), rescan=stale_source
    )
    assert receipt["status"] == "failed"
    assert receipt["rescan"]["original_present"] is True
    assert (tmp_path / "app.py").read_text() == edit["_source"]


def test_multi_import_preview_targets_one_bound_name(tmp_path):
    task = _task(tmp_path, "import math, json\nanswer = 42\n", name="math")
    task["_baseline_report"]["unused_imports"].append(
        {**task["finding"], "name": "json"}
    )
    edit = plan_cleanup_edit(task, tmp_path)
    assert edit["_replacement"] == "import json\nanswer = 42\n"


def test_source_anchors_detect_new_risk_at_different_statement_even_if_totals_match(
    tmp_path,
):
    finding = {
        "rule_id": "SKY-L012",
        "file": "app.py",
        "line": 1,
        "name": "auth",
        "severity": "HIGH",
    }
    before = _report(tmp_path, ai_defects=[finding])
    after = _report(tmp_path, ai_defects=[finding])
    outcome = compare_cleanup_reports(
        before,
        after,
        project_root=tmp_path,
        before_sources={"app.py": "auth(value)\n"},
        after_sources={"app.py": "auth(other_value)\n"},
    )
    assert outcome["status"] == "failed"
    assert outcome["new_findings"] == [finding]
    shifted = _report(tmp_path, ai_defects=[{**finding, "line": 2}])
    outcome = compare_cleanup_reports(
        before,
        shifted,
        project_root=tmp_path,
        before_sources={"app.py": "auth(value)\n"},
        after_sources={"app.py": "\nauth(value)\n"},
    )
    assert outcome["status"] == "passed"
