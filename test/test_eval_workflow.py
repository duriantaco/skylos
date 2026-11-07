import hashlib
import json
import subprocess
import sys

import pytest

from skylos.benchmarks import eval_workflow as workflow


def _fixture(tmp_path):
    root = tmp_path / "data"
    case = root / "fixture"
    case.mkdir(parents=True)
    (case / "app.py").write_text("print('fixture is only analyzed')\n")
    manifest = root / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "cases": [
                    {
                        "id": "safe",
                        "path": "fixture",
                        "taxonomy": ["precision_guard"],
                        "source": {
                            "repo": "https://github.com/example/project",
                            "license": "MIT",
                        },
                        "expect": {"present": {}, "absent": {"danger": ["SKY-D216"]}},
                    }
                ],
            }
        )
    )
    return manifest


def _dataset(tmp_path):
    manifest = _fixture(tmp_path)
    dataset = workflow._selected_dataset(manifest, ["safe"])
    dataset["suite"] = "security"
    return manifest, dataset


def _raw(**updates):
    return {
        "analysis_summary": {"total_files": 1, "analysis_error_count": 0},
        "analysis_errors": [],
        **updates,
    }


def _worker_files(output, raw, *, case_id="safe", summary_updates=None):
    summary = {
        "cases": [
            {
                "id": case_id,
                "scored": True,
                "analysis_status": "complete",
                "analysis_issues": [],
                "failures": [],
            }
        ],
        "skipped_case_count": 0,
        "case_count": 1,
        "failure_count": 0,
    }
    summary.update(summary_updates or {})
    workflow._write(output / "summary.json", summary)
    workflow._write(output / "cases/0/actual.raw.json", raw)


@pytest.mark.parametrize("ids", [[], ["safe", "safe"], ["typo"]])
def test_invalid_selection_cannot_produce_empty_pass(tmp_path, ids):
    with pytest.raises(ValueError):
        workflow._selected_dataset(_fixture(tmp_path), ids)


def test_fixture_snapshot_is_frozen_and_label_changes_have_distinct_identity(tmp_path):
    manifest, dataset = _dataset(tmp_path)
    frozen = workflow._freeze_dataset(manifest, dataset, tmp_path / "frozen")
    old = frozen.read_text()
    original = json.loads(manifest.read_text())
    original["cases"][0]["expect"]["absent"]["danger"] = ["SKY-D211"]
    manifest.write_text(json.dumps(original))
    assert workflow._digest(
        workflow._selected_dataset(manifest, ["safe"])
    ) != workflow._digest({k: v for k, v in dataset.items() if k != "suite"})
    assert frozen.read_text() == old
    copied = frozen.parent / json.loads(old)["cases"][0]["path"] / "app.py"
    assert copied.read_text() == "print('fixture is only analyzed')\n"


def test_fixture_link_cannot_read_outside_dataset(tmp_path):
    manifest = _fixture(tmp_path)
    private = tmp_path / "private.txt"
    private.write_text("not a fixture")
    (manifest.parent / "fixture/link.py").symlink_to(private)
    with pytest.raises(ValueError, match="symlink"):
        workflow._selected_dataset(manifest, ["safe"])


def test_raw_incomplete_analysis_overrides_claimed_passing_summary(tmp_path):
    _, dataset = _dataset(tmp_path)
    output = tmp_path / "output"
    _worker_files(output, _raw(analysis_errors=[{"kind": "syntax_error"}]))
    cases, errors = workflow._case_reports(dataset, output)
    assert not errors
    assert cases[0]["status"] == "incomplete"
    assert cases[0]["analysis_issues"]


def test_unlabelled_security_findings_remain_unresolved(tmp_path):
    _, dataset = _dataset(tmp_path)
    output = tmp_path / "output"
    _worker_files(
        output,
        _raw(
            danger=[
                {
                    "rule_id": "SKY-D211",
                    "file": "/temporary/snapshot/app.py",
                    "line": 9,
                }
            ],
            evidence={"trace": ["keep full source evidence"]},
        ),
    )
    cases, errors = workflow._case_reports(dataset, output)
    assert not errors
    assert cases[0]["unresolved_findings"] == [
        {
            "category": "danger",
            "rule_id": "SKY-D211",
            "file": "app.py",
            "line": 9,
        }
    ]
    assert json.loads((output / "cases/0/actual.raw.json").read_text())["evidence"]
    report = {
        "cases": cases,
        "case_ids": ["safe"],
        "phase": "baseline",
        "suite": "security",
        "runtime_errors": [],
        "elapsed_seconds": 0.1,
    }
    assert workflow._run_summary(report, output)[1] == 1


@pytest.mark.parametrize(
    "updates",
    [
        {"cases": []},
        {"cases": [{"id": "other", "failures": []}]},
        {"cases": [{"id": "safe"}, {"id": "safe"}]},
        {"skipped_case_count": 1},
    ],
)
def test_missing_duplicate_or_skipped_cases_cannot_pass(tmp_path, updates):
    _, dataset = _dataset(tmp_path)
    output = tmp_path / "output"
    _worker_files(output, _raw(), summary_updates=updates)
    cases, errors = workflow._case_reports(dataset, output)
    assert cases == []
    assert errors


def test_normalization_preserves_distinct_owners_and_relative_directories():
    entry = {"case": {}, "files": {"one/app.py": "a", "two/app.py": "b"}}
    findings, issues = workflow._findings(
        {
            "unused_functions": [
                {
                    "file": "/tmp/first/one/app.py",
                    "full_name": "Primary.process",
                    "line": 3,
                },
                {
                    "file": "/tmp/first/two/app.py",
                    "full_name": "Secondary.process",
                    "line": 3,
                },
            ]
        },
        "dead-code",
        entry,
    )
    assert not issues
    assert {finding["file"] for finding in findings} == {"one/app.py", "two/app.py"}
    assert {finding["full_name"] for finding in findings} == {
        "Primary.process",
        "Secondary.process",
    }


@pytest.mark.parametrize("record", [{}, {"file": "app.py"}, {"name": "unused"}])
def test_malformed_dead_code_finding_cannot_disappear_into_safe_result(record):
    findings, issues = workflow._findings(
        {"unused_functions": [record]},
        "dead-code",
        {"case": {}, "files": {"app.py": "x"}},
    )
    assert not findings
    assert issues


def test_ungraded_file_string_cannot_disappear_into_safe_result():
    findings, issues = workflow._findings(
        {"unused_files": ["extra.py"]},
        "dead-code",
        {"case": {}, "files": {"extra.py": "x"}},
    )
    assert not findings
    assert issues


def test_second_security_location_requires_review_even_when_rule_is_labelled():
    case = {"expect": {"present": {"danger": ["SKY-D216"]}, "absent": {}}}
    findings = [
        {"category": "danger", "rule_id": "SKY-D216", "file": "app.py", "line": line}
        for line in (3, 9)
    ]
    assert workflow._unresolved("security", case, findings[:1], {}) == []
    assert workflow._unresolved("security", case, findings, {}) == findings


def test_worker_does_not_inherit_external_rule_config_or_engine_injection(monkeypatch):
    monkeypatch.setenv("SKYLOS_CUSTOM_RULES", "/outside/rules.py")
    monkeypatch.setenv("SKYLOS_CONFIG_FILE", "/outside/skylos.toml")
    monkeypatch.setenv("SKYLOS_GO_ENGINE", "/outside/binary")
    env = workflow._worker_environment(workflow.ROOT)
    assert env["SKYLOS_CUSTOM_RULES"] == "[]"
    assert "SKYLOS_CONFIG_FILE" not in env and "SKYLOS_GO_ENGINE" not in env
    assert env["SKYLOS_NO_UPLOAD"] == "1" and env["SKYLOS_NO_TELEMETRY"] == "1"


def test_saved_artifact_modification_prevents_receipt_reuse(tmp_path):
    payload = tmp_path / "actual.raw.json"
    payload.write_text("{}")
    workflow._save_receipt(
        tmp_path / "receipt.json",
        {
            "artifacts": {
                "actual.raw.json": hashlib.sha256(payload.read_bytes()).hexdigest()
            },
        },
    )
    assert workflow.load_receipt(tmp_path)
    payload.write_text('{"changed":true}')
    with pytest.raises(ValueError, match="changed"):
        workflow.load_receipt(tmp_path)


def test_artifact_escape_is_rejected(tmp_path):
    workflow._save_receipt(
        tmp_path / "receipt.json", {"artifacts": {"../outside": "x"}}
    )
    with pytest.raises(ValueError, match="escapes"):
        workflow.load_receipt(tmp_path)


def test_receipt_edit_without_matching_checksum_is_rejected(tmp_path):
    workflow._save_receipt(
        tmp_path / "receipt.json", {"artifacts": {"actual.raw.json": "a"}}
    )
    (tmp_path / "receipt.json").write_text('{"cases": []}')
    with pytest.raises(ValueError, match="receipt checksum"):
        workflow.load_receipt(tmp_path)


@pytest.mark.parametrize("worker_exit,changed", [(0, True), (1, False)])
def test_source_edit_or_inconsistent_worker_exit_prevents_success(
    tmp_path, monkeypatch, worker_exit, changed
):
    manifest = _fixture(tmp_path)
    before = {"snapshot_sha256": "a", "revision": "initial", "files": {}}
    after = {**before, "snapshot_sha256": "b"} if changed else before
    identities = iter([before, after])
    monkeypatch.setattr(workflow, "source_identity", lambda repo: next(identities))
    monkeypatch.setattr(
        workflow, "environment_identity", lambda: {"sha256": "environment"}
    )
    monkeypatch.setattr(workflow, "_harness_identity", lambda *args: "harness")
    monkeypatch.setattr(
        workflow, "write_source_snapshot", lambda r, p, i: p.write_bytes(b"snapshot")
    )
    output = tmp_path / "run"

    def fake_worker(*args, **kwargs):
        _worker_files(output, _raw())
        return subprocess.CompletedProcess([], worker_exit)

    monkeypatch.setattr(workflow.subprocess, "run", fake_worker)
    report = workflow.run_evaluation(
        suite="security",
        manifest=manifest,
        case_ids=["safe"],
        output=output,
        phase="baseline",
    )
    assert report["source_unchanged"] is (not changed)
    assert workflow._run_summary(report, output)[1] == 1
    assert ("source changed" if changed else "worker exit status") in report[
        "runtime_errors"
    ][0]
    assert workflow.load_receipt(output)["runtime_errors"]


def test_cli_real_static_security_pair_retains_native_results(tmp_path):
    output = tmp_path / "baseline"
    command = [
        sys.executable,
        "-B",
        str(workflow.ROOT / "scripts/eval_check.py"),
        "baseline",
        "--suite",
        "security",
        "--case",
        "ssrf-tainted-host",
        "--case",
        "ssrf-fixed-host-path",
        "--output",
        str(output),
    ]
    result = subprocess.run(
        command, cwd=workflow.ROOT, text=True, capture_output=True, timeout=120
    )
    assert result.returncode == 0, result.stdout + result.stderr
    receipt = workflow.load_receipt(output)
    assert receipt["source_unchanged"] is True
    assert receipt["case_ids"] == ["ssrf-tainted-host", "ssrf-fixed-host-path"]
    assert all(case["status"] == "passed" for case in receipt["cases"])
    assert all(not case["unresolved_findings"] for case in receipt["cases"])
    positive = json.loads((output / "cases/0/actual.raw.json").read_text())
    negative = json.loads((output / "cases/1/actual.raw.json").read_text())
    assert not positive.get("analysis_errors") and not negative.get("analysis_errors")
    assert any(f["rule_id"] == "SKY-D216" for f in positive["danger"])
    assert not any(f["rule_id"] == "SKY-D216" for f in negative.get("danger", []))
    assert (output / "source.tar.gz").is_file()
