"""Original offline guard fixtures; no upstream source or target execution."""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from skylos.benchmarks import security_holdouts as holdouts


def _git(root, *args):
    return subprocess.run(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "user.name=Corpus Test",
            "-c",
            "user.email=corpus@example.invalid",
            *args,
        ],
        cwd=root,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "checkouts" / "sample"
    root.mkdir(parents=True)
    source = "class Widget\n  def helper\n    7\n  end\nend\n"
    (root / "widget.rb").write_text(source)
    (root / ".gitignore").write_text("ignored-output\n")
    _git(root, "init", "--quiet")
    _git(root, "add", "widget.rb", ".gitignore")
    _git(root, "commit", "--quiet", "-m", "Original inert corpus source")
    _git(root, "remote", "add", "origin", "https://example.invalid/corpus.git")
    target = {
        "id": "original-ruby",
        "kind": "ruby_dead_code",
        "repo": "https://example.invalid/corpus",
        "ref": _git(root, "rev-parse", "HEAD"),
        "checkout": "sample",
        "scan_root": ".",
        "source_files": [
            {"path": "widget.rb", "sha256": hashlib.sha256(source.encode()).hexdigest()}
        ],
        "expectations": [
            {
                "kind": "ruby_used",
                "file": "widget.rb",
                "symbol": "Widget#helper",
                "line": 2,
            }
        ],
    }
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"version": 1, "label_scope": "open", "targets": [target]})
    )
    return root, target, manifest


def _ruby_report(root):
    return {
        "analysis_errors": [],
        "analysis_summary": {
            "total_files": 1,
            "analysis_error_count": 0,
            "languages": {"Ruby": 1},
        },
        "definitions": {
            "Widget#helper": {
                "name": "Widget#helper",
                "file": str(root / "widget.rb"),
                "line": 2,
                "dead": False,
            }
        },
        "unused_functions": [],
    }


def _tf_target(target):
    target = deepcopy(target)
    target["kind"] = "terraform_policy"
    target["expectations"] = [
        {
            "kind": "terraform_policy",
            "file": "main.tf",
            "resource": "aws_db_instance.primary",
            "rule_id": "SKY-D401",
            "status": "unsafe",
            "line": 4,
        },
        {
            "kind": "terraform_policy",
            "file": "main.tf",
            "resource": "aws_security_group_rule.unresolved",
            "rule_id": "SKY-D400",
            "status": "unknown",
            "line": 12,
        },
        {
            "kind": "terraform_policy",
            "file": "main.tf",
            "resource": "aws_security_group_rule.outbound",
            "rule_id": "SKY-D400",
            "status": "not_applicable",
            "line": 20,
        },
    ]
    return target


def _tf_report(root, target):
    checks = [
        {key: fact[key] for key in ("rule_id", "resource", "file", "line", "status")}
        for fact in target["expectations"]
    ]
    for check in checks:
        check["file"] = str(root / check["file"])
    return {
        "analysis_errors": [],
        "analysis_summary": {
            "total_files": 0,
            "analysis_error_count": 0,
            "configuration_coverage": {
                "terraform": {
                    "status": "complete",
                    "files_discovered": 1,
                    "files_parsed": 1,
                    "resources": 4,
                    "checks": checks,
                    "checks_evaluated": 3,
                    "evaluation_counts": {
                        "unsafe": 1,
                        "safe": 0,
                        "unknown": 1,
                        "not_applicable": 1,
                    },
                    "supported_rules": ["SKY-D400", "SKY-D401"],
                    "evaluation_status": "partial",
                    "unsupported_resource_count": 1,
                    "unsupported_resources": [
                        {
                            "resource": "aws_instance.unlabelled",
                            "file": str(root / "main.tf"),
                            "line": 30,
                        }
                    ],
                    "discovery_errors": [],
                    "unresolved_module_count": 0,
                    "module_calls": [],
                    "modules": 1,
                    "resolution_attempts": 1,
                    "unresolved_resolution_attempts": 1,
                }
            },
        },
        "danger": [{key: value for key, value in checks[0].items() if key != "status"}],
        "assessment": {
            "coverage": {
                "status": "incomplete",
                "incomplete_checks": ["unsupported AWS resources"],
            }
        },
    }


def test_original_clean_pinned_ruby_facts_pass_with_pre_post_hashes(
    project, monkeypatch
):
    root, _, manifest = project
    monkeypatch.setattr(holdouts, "scan_target", lambda *_: _ruby_report(root))
    result = holdouts.run_manifest(manifest, checkout_root=root.parent)
    assert result["failure_count"] == 0
    assert result["selected_fact_outcomes"] == {"ruby_used": 1}
    assert (
        result["targets"][0]["source_hashes_before"]
        == result["targets"][0]["source_hashes_after"]
    )


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "tracked",
        "untracked",
        "ignored",
        "ref",
        "origin",
        "hash",
        "symlink",
        "ancestor_symlink",
        "fifo",
        "assume_unchanged",
        "skip_worktree",
    ],
)
def test_checkout_guards_fail_before_analysis(project, monkeypatch, change, tmp_path):
    root, target, manifest = project
    checkout_root = root.parent
    if change == "missing":
        checkout_root = tmp_path / "absent"
    elif change == "tracked":
        (root / "widget.rb").write_text("changed\n")
    elif change in {"untracked", "ignored"}:
        (
            root / ("untracked-output" if change == "untracked" else "ignored-output")
        ).write_text("extra\n")
    elif change == "ref":
        target["ref"] = "0" * 40
    elif change == "origin":
        _git(root, "remote", "set-url", "origin", "https://example.invalid/wrong")
    elif change == "hash":
        target["source_files"][0]["sha256"] = "0" * 64
    elif change == "symlink":
        (root / "widget.rb").unlink()
        (root / "widget.rb").symlink_to(root / ".gitignore")
    elif change == "fifo":
        (root / "widget.rb").unlink()
        os.mkfifo(root / "widget.rb")
    elif change in {"assume_unchanged", "skip_worktree"}:
        flag = (
            "--assume-unchanged" if change == "assume_unchanged" else "--skip-worktree"
        )
        _git(root, "update-index", flag, "widget.rb")
        (root / "widget.rb").write_text("hidden change\n")
    else:
        checkout_root = tmp_path / "linked"
        checkout_root.symlink_to(root.parent, target_is_directory=True)
    manifest.write_text(
        json.dumps({"version": 1, "label_scope": "open", "targets": [target]})
    )
    calls = []
    monkeypatch.setattr(holdouts, "scan_target", lambda *_: calls.append(True))
    result = holdouts.run_manifest(manifest, checkout_root=checkout_root)
    assert result["failure_count"]
    assert result["selected_fact_outcomes"] == {}
    assert calls == []


def test_post_scan_source_change_cannot_earn_credit(project, monkeypatch):
    root, _, manifest = project

    def scan(*_):
        (root / "widget.rb").write_text("changed during scan\n")
        return _ruby_report(root)

    monkeypatch.setattr(holdouts, "scan_target", scan)
    result = holdouts.run_manifest(manifest, checkout_root=root.parent)
    assert result["failure_count"]
    assert result["selected_fact_outcomes"] == {}


@pytest.mark.parametrize(
    "change",
    [
        "no_definitions",
        "duplicate",
        "wrong_identity",
        "wrong_file",
        "wrong_line",
        "unused",
        "dead",
        "no_ruby",
        "zero_files",
        "parse_error",
        "missing_error_receipt",
        "malformed",
    ],
)
def test_ruby_missing_or_incorrect_positive_evidence_is_not_used_credit(
    project, change
):
    root, target, _ = project
    report = _ruby_report(root)
    definition = report["definitions"]["Widget#helper"]
    if change == "no_definitions":
        report["definitions"] = {}
    elif change == "duplicate":
        report["definitions"]["other-key"] = dict(definition)
    elif change == "wrong_identity":
        definition["name"] = "Unrelated#helper"
    elif change == "wrong_file":
        definition["file"] = str(root / "unrelated.rb")
    elif change == "wrong_line":
        definition["line"] = 9
    elif change == "unused":
        report["unused_functions"] = [dict(definition)]
    elif change == "dead":
        definition["dead"] = True
    elif change == "no_ruby":
        report["analysis_summary"]["languages"] = {"Python": 1}
    elif change == "zero_files":
        report["analysis_summary"]["total_files"] = 0
    elif change == "parse_error":
        report["analysis_errors"] = [{"kind": "parse_error"}]
    elif change == "missing_error_receipt":
        report.pop("analysis_errors")
    else:
        report = []
    result = holdouts.evaluate_target(target, report, root)
    assert result["failures"]
    assert result["outcomes"] == {}


def test_terraform_selected_statuses_pass_while_unsupported_scope_stays_visible(
    project,
):
    root, original, _ = project
    target = _tf_target(original)
    result = holdouts.evaluate_target(target, _tf_report(root, target), root)
    assert result["failures"] == []
    assert result["outcomes"] == {"unsafe": 1, "unknown": 1, "not_applicable": 1}
    assert "safe" not in result["outcomes"]
    assert result["coverage"]["evaluation_status"] == "partial"
    assert result["coverage"]["unsupported_resource_count"] == 1


@pytest.mark.parametrize(
    "change",
    [
        "zero_files",
        "missing_coverage",
        "zero_resources",
        "unparsed",
        "parse_error",
        "no_checks",
        "no_finding",
        "duplicate_finding",
        "wrong_file",
        "wrong_line",
        "unknown_as_safe",
        "na_as_safe",
    ],
)
def test_terraform_nonvacuity_and_status_controls(project, change):
    root, original, _ = project
    target = _tf_target(original)
    report = _tf_report(root, target)
    coverage = report["analysis_summary"]["configuration_coverage"]["terraform"]
    if change == "zero_files":
        coverage["files_discovered"] = coverage["files_parsed"] = 0
    elif change == "missing_coverage":
        report["analysis_summary"].pop("configuration_coverage")
    elif change == "zero_resources":
        coverage["resources"] = 0
    elif change == "unparsed":
        coverage["files_discovered"] = 2
    elif change == "parse_error":
        report["analysis_errors"] = [{"kind": "terraform_parse_error"}]
    elif change == "no_checks":
        coverage["checks"] = []
    elif change == "no_finding":
        report["danger"] = []
    elif change == "duplicate_finding":
        report["danger"] *= 2
    elif change == "wrong_file":
        coverage["checks"][0]["file"] = str(root / "other.tf")
    elif change == "wrong_line":
        report["danger"][0]["line"] = 999
    elif change == "unknown_as_safe":
        coverage["checks"][1]["status"] = "safe"
    else:
        coverage["checks"][2]["status"] = "safe"
    result = holdouts.evaluate_target(target, report, root)
    assert result["failures"]
    assert result["outcomes"] == {}


def test_unreviewed_facts_are_counts_not_false_positives(project):
    root, original, _ = project
    target = _tf_target(original)
    report = _tf_report(root, target)
    extra = {
        "rule_id": "SKY-D400",
        "resource": "aws_security_group.extra",
        "file": str(root / "other.tf"),
        "line": 1,
        "status": "unsafe",
    }
    coverage = report["analysis_summary"]["configuration_coverage"]["terraform"]
    coverage["checks"].append(extra)
    coverage["checks_evaluated"] += 1
    coverage["evaluation_counts"]["unsafe"] += 1
    coverage["unsupported_resources"] = []
    coverage["unsupported_resource_count"] = 0
    report["danger"].append(dict(extra))
    result = holdouts.evaluate_target(target, report, root)
    assert result["failures"] == []
    assert result["unreviewed_findings"] == result["unreviewed_checks"] == 1
    assert "false_positives" not in result


def test_static_scan_disables_services_and_custom_rules_and_restores_environment(
    project, monkeypatch
):
    root, target, _ = project
    monkeypatch.setenv("SKYLOS_CUSTOM_RULES", '[{"untrusted": true}]')
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "inert-test-value")
    original = dict(os.environ)

    def analyze(path, **options):
        assert path == str(root)
        assert os.environ["SKYLOS_CUSTOM_RULES"] == "[]"
        assert "AWS_SECRET_ACCESS_KEY" not in os.environ
        assert options["custom_rules_data"] == []
        for key in (
            "enable_danger",
            "enable_secrets",
            "enable_quality",
            "enable_ai_defects",
            "enable_sca",
            "enable_dependency_hallucinations",
            "trace_file",
            "grep_cache",
        ):
            assert options[key] is False
        return json.dumps(_ruby_report(root))

    monkeypatch.setattr(holdouts, "analyze", analyze)
    assert holdouts.scan_target(target, root)["definitions"]
    assert dict(os.environ) == original


@pytest.mark.parametrize(
    "change",
    [
        "moving_ref",
        "empty_facts",
        "unhashed_fact",
        "escape",
        "duplicate",
        "closed_labels",
    ],
)
def test_manifest_rejects_unfrozen_or_vacuous_labels(project, change):
    _, target, manifest = project
    data = {"version": 1, "label_scope": "open", "targets": [target]}
    if change == "moving_ref":
        target["ref"] = "main"
    elif change == "empty_facts":
        target["expectations"] = []
    elif change == "unhashed_fact":
        target["expectations"][0]["file"] = "other.rb"
    elif change == "escape":
        target["checkout"] = "../outside"
    elif change == "duplicate":
        target["expectations"] *= 2
    else:
        data["label_scope"] = "closed"
    manifest.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        holdouts.load_manifest(manifest)


@pytest.mark.parametrize(
    "change",
    [
        "missing_line",
        "shifted_line",
        "float_line",
        "bool_line",
        "missing_name",
        "empty_name",
        "wrong_name_type",
        "missing_file",
        "outside_file",
        "malformed_full_name",
        "canonical_full_name",
    ],
)
def test_review_ruby_unused_identity_or_contradiction_cannot_earn_used_credit(
    project, change
):
    root, target, _ = project
    report = _ruby_report(root)
    unused = dict(report["definitions"]["Widget#helper"])
    if change == "missing_line":
        unused.pop("line")
    elif change == "shifted_line":
        unused["line"] += 1
    elif change == "float_line":
        unused["line"] = float(unused["line"])
    elif change == "bool_line":
        unused["line"] = True
    elif change == "missing_name":
        unused.pop("name")
    elif change == "empty_name":
        unused["name"] = ""
    elif change == "wrong_name_type":
        unused["name"] = 123
    elif change == "missing_file":
        unused.pop("file")
    elif change == "outside_file":
        unused["file"] = str(root.parent / "outside.rb")
    elif change == "malformed_full_name":
        unused["full_name"] = []
    else:
        unused["name"] = "helper"
        unused["full_name"] = "Widget#helper"
        unused["line"] += 1
    report["unused_functions"].append(unused)
    result = holdouts.evaluate_target(target, report, root)
    assert result["failures"]
    assert result["outcomes"] == {}


@pytest.mark.parametrize(
    "field,value", [("line", 2.0), ("line", True), ("name", ""), ("file", "")]
)
def test_review_ruby_definition_identity_is_strict(project, field, value):
    root, target, _ = project
    report = _ruby_report(root)
    report["definitions"]["Widget#helper"][field] = value
    result = holdouts.evaluate_target(target, report, root)
    assert result["failures"]
    assert result["outcomes"] == {}


@pytest.mark.parametrize(
    "change",
    [
        "bool_error_count",
        "bool_total_files",
        "bad_check_rule_type",
        "float_error_count",
        "float_check_count",
        "bool_file_count",
        "float_resources",
        "float_check_line",
        "float_finding_line",
        "bool_check_line",
        "incomplete_extra_check",
        "unsupported_check_rule",
        "missing_supported_rules",
        "inconsistent_status_counts",
        "float_status_count",
        "float_unsupported_count",
        "inconsistent_unsupported_count",
        "float_module_count",
        "inconsistent_module_count",
        "wrong_evaluation_status",
        "malformed_extra_finding",
    ],
)
def test_review_terraform_identity_counts_and_coverage_are_strict(project, change):
    root, original, _ = project
    target = _tf_target(original)
    report = _tf_report(root, target)
    summary = report["analysis_summary"]
    coverage = summary["configuration_coverage"]["terraform"]
    if change == "bool_error_count":
        summary["analysis_error_count"] = False
    elif change == "bool_total_files":
        summary["total_files"] = False
    elif change == "bad_check_rule_type":
        coverage["checks"][0]["rule_id"] = []
    elif change == "float_error_count":
        summary["analysis_error_count"] = 0.0
    elif change == "float_check_count":
        coverage["checks_evaluated"] = float(coverage["checks_evaluated"])
    elif change == "bool_file_count":
        coverage["files_discovered"] = True
    elif change == "float_resources":
        coverage["resources"] = float(coverage["resources"])
    elif change == "float_check_line":
        coverage["checks"][0]["line"] = float(coverage["checks"][0]["line"])
    elif change == "float_finding_line":
        report["danger"][0]["line"] = float(report["danger"][0]["line"])
    elif change == "bool_check_line":
        coverage["checks"][0]["line"] = True
    elif change == "incomplete_extra_check":
        coverage["checks"].append({"status": "safe"})
        coverage["checks_evaluated"] += 1
        coverage["evaluation_counts"]["safe"] += 1
    elif change == "unsupported_check_rule":
        coverage["checks"][1]["rule_id"] = "SKY-INVALID"
    elif change == "missing_supported_rules":
        coverage.pop("supported_rules")
    elif change == "inconsistent_status_counts":
        coverage["evaluation_counts"]["safe"] = 1
    elif change == "float_status_count":
        coverage["evaluation_counts"]["safe"] = 0.0
    elif change == "float_unsupported_count":
        coverage["unsupported_resource_count"] = 1.0
    elif change == "inconsistent_unsupported_count":
        coverage["unsupported_resource_count"] = 0
    elif change == "float_module_count":
        coverage["unresolved_module_count"] = 0.0
    elif change == "inconsistent_module_count":
        coverage["unresolved_module_count"] = 1
    elif change == "wrong_evaluation_status":
        coverage["evaluation_status"] = "complete"
    else:
        report["danger"].append({"rule_id": "SKY-D400"})
    result = holdouts.evaluate_target(target, report, root)
    assert result["failures"]
    assert result["outcomes"] == {}


@pytest.mark.parametrize("during_scan", [False, True])
def test_review_full_tracked_context_cannot_hide_behind_git_stat_cache(
    project, monkeypatch, during_scan
):
    root, target, manifest = project
    sibling = root / "context.rb"
    sibling.write_bytes(b"VALUE = 1\n")
    # Deliberately old before indexing, so Git's racy-index check cannot rescue
    # a status-only guard. The changed sibling is outside labelled source_files.
    os.utime(sibling, (1_600_000_000, 1_600_000_000))
    _git(root, "add", "context.rb")
    _git(root, "commit", "--quiet", "-m", "Original unlabelled context")
    target["ref"] = _git(root, "rev-parse", "HEAD")
    _git(root, "config", "core.trustctime", "false")
    _git(root, "config", "core.checkstat", "minimal")
    manifest.write_text(
        json.dumps({"version": 1, "label_scope": "open", "targets": [target]})
    )
    original = sibling.stat()

    def change():
        sibling.write_bytes(b"VALUE = 2\n")
        os.utime(sibling, ns=(original.st_atime_ns, original.st_mtime_ns))
        assert _git(root, "status", "--porcelain=v1") == ""

    def scan(*_):
        if during_scan:
            change()
        return _ruby_report(root)

    monkeypatch.setattr(holdouts, "scan_target", scan)
    if not during_scan:
        change()
    result = holdouts.run_manifest(manifest, checkout_root=root.parent)
    assert result["failure_count"]
    assert result["selected_fact_outcomes"] == {}


def test_holdout_cli_bootstraps_checkout_without_pythonpath(tmp_path):
    script = Path(__file__).resolve().parents[1] / "scripts/security_holdouts.py"
    environment = {
        key: value for key, value in os.environ.items() if key != "PYTHONPATH"
    }
    result = subprocess.run(
        [sys.executable, "-I", str(script), "--help"],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert "--checkout-root" in result.stdout
