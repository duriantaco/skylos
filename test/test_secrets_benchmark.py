"""Independent expected answers and honest completeness for secrets shape evals."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from skylos.benchmarks import secrets as benchmark
from test.fixture_paths import write_fixture


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "benchmarks/secrets/manifest.json"


def _case(case_id="classic-keyed"):
    return next(
        case for case in benchmark.load_manifest(MANIFEST) if case["id"] == case_id
    )


def _source(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    write_fixture(
        source, "skylos/analyzer.py", "# source identity only; never executed\n"
    )
    return source


def _finding(*, provider="github", name="app.py", line=1):
    return {
        "file": name,
        "line": line,
        "provider": provider,
        "rule_id": "SKY-S101",
        "col": 13,
        "end_col": 53,
    }


def test_reviewed_manifest_has_frozen_positive_safe_and_scope_contracts():
    cases = benchmark.load_manifest(MANIFEST)
    assert len(cases) == 20
    assert sum(case["expect"]["detected"] for case in cases) == 13
    assert sum(not case["expect"]["detected"] for case in cases) == 7
    assert {case["id"] for case in cases if case["track"] == "capability"} == {
        "finegrain-keyed",
        "finegrain-unkeyed",
        "base64-once",
        "base64-twice",
        "json-unicode",
        "html-numeric",
        "python-test-scope",
        "readme-scope",
        "text-scope",
        "keyfile-scope",
    }
    finegrain = benchmark.fixture_content("finegrain-keyed").decode().split('"')[1]
    head, account, payload = finegrain.split("_")[-3:]
    assert head == "pat" and len(account) == 22 and len(payload) == 59


def test_cross_language_oracle_is_separate_and_balanced():
    manifest = ROOT / "benchmarks/secrets/cross_language_manifest.json"
    cases = benchmark.load_manifest(manifest)
    positives = [case for case in cases if case["expect"]["detected"]]
    negatives = [case for case in cases if not case["expect"]["detected"]]
    assert len(cases) == 16 and len(positives) == len(negatives) == 8
    assert {Path(case["file"]).suffix for case in positives} == {
        ".ts",
        ".tsx",
        ".js",
        ".mjs",
        ".cjs",
    }
    assert {case["id"] for case in positives if case["file"].startswith("tests/")} == {
        "ts-tests-credential",
        "tsx-tests-credential",
        "js-tests-credential",
    }
    assert all(
        case["expect"] == {"detected": True, "provider": "github", "line": 1}
        for case in positives
    )
    assert all(case["expect"] == {"detected": False} for case in negatives)
    assert {case["file"] for case in positives} == {case["file"] for case in negatives}
    assert len(benchmark.load_manifest(MANIFEST)) == 20


def test_generated_inputs_are_identical_for_both_scanners(tmp_path):
    case = _case("base64-twice")
    first = benchmark.materialize(case, tmp_path / "skylos")
    second = benchmark.materialize(case, tmp_path / "trufflehog")
    assert first == second
    assert set(first) == {"benchmark_anchor.py", "app.py"}
    assert (tmp_path / "skylos/app.py").read_bytes() == (
        tmp_path / "trufflehog/app.py"
    ).read_bytes()


def test_positive_cases_have_distinct_material_to_avoid_tool_deduplication():
    positives = [
        case for case in benchmark.load_manifest(MANIFEST) if case["expect"]["detected"]
    ]
    material = {
        benchmark.fixture_content(case["recipe"], seed=case["id"]) for case in positives
    }
    assert len(material) == len(positives) == 13


@pytest.mark.parametrize("path", ["../escape.py", "/outside.py", "a\\escape.py", ""])
def test_unsafe_fixture_paths_are_rejected_before_materialization(tmp_path, path):
    case = _case()
    case["file"] = path
    manifest = write_fixture(
        tmp_path, "manifest.json", json.dumps({"version": 1, "cases": [case]})
    )
    with pytest.raises(ValueError, match="relative path"):
        benchmark.load_manifest(manifest)
    assert not (tmp_path / "escape.py").exists()


def test_case_selection_never_silently_ignores_unknown_or_empty_scope():
    with pytest.raises(ValueError, match="unknown selected"):
        benchmark.load_manifest(MANIFEST, selected_cases={"not-a-case"})
    with pytest.raises(ValueError, match="empty"):
        benchmark.load_manifest(
            MANIFEST, selected_cases={"classic-keyed"}, track="capability"
        )


def test_duplicate_case_ids_and_implicit_expectations_are_rejected(tmp_path):
    case = _case()
    manifest = write_fixture(
        tmp_path, "manifest.json", json.dumps({"version": 1, "cases": [case, case]})
    )
    with pytest.raises(ValueError, match="duplicate"):
        benchmark.load_manifest(manifest)
    del case["expect"]["detected"]
    write_fixture(
        tmp_path,
        "manifest.json",
        json.dumps({"version": 1, "cases": [case]}),
        overwrite=True,
    )
    with pytest.raises(ValueError, match="explicit boolean"):
        benchmark.load_manifest(manifest)


def test_generic_detection_is_not_misreported_as_a_provider_recall_miss():
    report = benchmark.grade(
        _case("finegrain-keyed"), [_finding(provider="generic")], []
    )
    assert report["detected"] and report["presence_passed"]
    assert not report["provider_passed"]
    assert report["classification_status"] == "missing_expected_provider"
    assert report["status"] == "failed"


def test_duplicates_and_two_rules_for_one_case_are_not_two_detected_secrets():
    reports = [_finding(), _finding(), _finding(provider="generic")]
    report = benchmark.grade(_case(), reports, [])
    assert report["detected"] and report["status"] == "passed"
    assert report["raw_finding_count"] == 3
    assert report["unique_finding_locations"] == 1
    assert report["duplicate_identity_count"] == 1
    assert report["extra_findings_same_case"] == 2


def test_error_on_a_quiet_safe_case_is_incomplete_not_a_pass():
    report = benchmark.grade(
        _case("env-reference"), [], ["scanner evidence unavailable"]
    )
    assert report["status"] == "incomplete"
    assert not report["detected"]


def test_findings_in_benign_anchor_are_not_credited_to_the_expected_secret():
    report = benchmark.grade(_case(), [_finding(name="benchmark_anchor.py")], [])
    assert report["status"] == "failed"
    assert not report["detected"]
    assert report["unexpected_locations"]


def test_finding_on_wrong_line_does_not_receive_secret_detection_credit():
    report = benchmark.grade(_case(), [_finding(line=2)], [])
    assert not report["detected"] and not report["presence_passed"]
    assert report["status"] == "failed" and report["unexpected_locations"]


def test_false_alarm_on_reviewed_safe_fixture_fails():
    report = benchmark.grade(_case("prose-label"), [_finding(provider="generic")], [])
    assert report["status"] == "failed" and not report["presence_passed"]


def test_th_adapter_uses_filesystem_metadata_without_exposing_token_material(tmp_path):
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    raw = [
        {
            "DetectorName": "Github",
            "DetectorType": 7,
            "Verified": False,
            "Raw": "synthetic runtime-only material",
            "SourceMetadata": {
                "Data": {"Filesystem": {"file": str(fixture / "app.py"), "line": 1}}
            },
        }
    ]
    records = benchmark.normalize(raw, scanner="trufflehog", fixture=fixture)
    assert records[0]["provider"] == "github" and records[0]["file"] == "app.py"
    assert "Raw" not in records[
        0
    ] and "synthetic runtime-only material" not in json.dumps(records)
    raw[0]["SourceMetadata"] = None
    with pytest.raises(ValueError, match="invalid location"):
        benchmark.normalize(raw, scanner="trufflehog", fixture=fixture)


def test_report_keeps_expected_inputs_and_runtime_failures(tmp_path, monkeypatch):
    source = _source(tmp_path)
    monkeypatch.setattr(
        benchmark,
        "_run_scanner",
        lambda *args: ([], ["timed out"], {"elapsed_seconds": 1.0}),
    )
    output = tmp_path / "report"
    summary = benchmark.run_manifest(
        MANIFEST, output=output, source=source, selected_cases={"env-reference"}
    )
    assert not summary["passed"] and summary["incomplete_count"] == 1
    assert summary["missed_positive_cases"] == 0
    assert json.loads((output / "env-reference/expected.json").read_text())[
        "expect"
    ] == {"detected": False}
    assert json.loads((output / "env-reference/inputs.json").read_text())
    assert (output / "summary.json").is_file()
    with pytest.raises(FileExistsError):
        benchmark.run_manifest(MANIFEST, output=output, source=source)


def test_source_changes_are_not_reported_as_a_stable_pass(tmp_path, monkeypatch):
    source = _source(tmp_path)

    def mutate(*args):
        write_fixture(
            source, "skylos/analyzer.py", "# changed during execution\n", overwrite=True
        )
        return [], [], {"elapsed_seconds": 0.0}

    monkeypatch.setattr(benchmark, "_run_scanner", mutate)
    summary = benchmark.run_manifest(
        MANIFEST,
        output=tmp_path / "report",
        source=source,
        selected_cases={"env-reference"},
    )
    assert not summary["passed"]
    assert "analyzer source changed during the run" in summary["errors"]


def test_completeness_grader_changes_invalidate_a_quiet_run(tmp_path, monkeypatch):
    source = _source(tmp_path)
    harness = tmp_path / "harness"
    harness.mkdir()
    write_fixture(harness, "scripts/secrets_benchmark.py", "# trusted entry\n")
    write_fixture(harness, "skylos/benchmarks/_analysis_validation.py", "# original\n")
    monkeypatch.setattr(benchmark, "ROOT", harness)

    def mutate(*args):
        write_fixture(
            harness,
            "skylos/benchmarks/_analysis_validation.py",
            "# changed\n",
            overwrite=True,
        )
        return [], [], {"elapsed_seconds": 0.0}

    monkeypatch.setattr(benchmark, "_run_scanner", mutate)
    summary = benchmark.run_manifest(
        MANIFEST,
        output=tmp_path / "report",
        source=source,
        selected_cases={"env-reference"},
    )
    assert not summary["passed"]
    assert "harness or expected manifest changed during the run" in summary["errors"]


def test_safe_case_noise_in_anchor_still_counts_as_a_false_alarm(tmp_path, monkeypatch):
    source = _source(tmp_path)
    monkeypatch.setattr(
        benchmark,
        "_run_scanner",
        lambda *args: (
            [_finding(name="benchmark_anchor.py")],
            [],
            {"elapsed_seconds": 0.0},
        ),
    )
    summary = benchmark.run_manifest(
        MANIFEST,
        output=tmp_path / "report",
        source=source,
        selected_cases={"env-reference"},
    )
    assert summary["unexpected_finding_cases"] == 1
    assert not summary["passed"]


def test_worker_environment_clears_all_git_local_overrides(monkeypatch):
    names = subprocess.run(
        ["git", "rev-parse", "--local-env-vars"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    assert set(names) <= benchmark._GIT_LOCAL
    for name in (
        *names,
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "SKYLOS_CUSTOM_RULES",
    ):
        monkeypatch.setenv(name, "unrelated-source")
    env = benchmark._worker_environment()
    assert not set(names) & set(env)
    assert "GIT_CONFIG_KEY_0" not in env and "GIT_CONFIG_VALUE_0" not in env
    assert env["SKYLOS_CUSTOM_RULES"] == "[]"


def test_real_native_worker_loads_analyzer_from_source_without_new_benchmark(tmp_path):
    source = tmp_path / "legacy-source"
    source.mkdir()
    shutil.copytree(
        ROOT / "skylos",
        source / "skylos",
        ignore=shutil.ignore_patterns(
            "__pycache__", "*.pyc", "skylos-go", "skylos-go.exe"
        ),
    )
    (source / "skylos/benchmarks/secrets.py").unlink()
    summary = benchmark.run_manifest(
        MANIFEST,
        output=tmp_path / "report",
        source=source,
        selected_cases={"classic-keyed", "env-reference"},
    )
    assert summary["passed"], summary
    for case in summary["cases"]:
        assert Path(case["execution"]["analyzer_path"]).is_relative_to(source)
        assert case["execution"]["native_analysis_summary"]["total_files"] > 0


def test_th_command_disables_updates_and_verification_and_keeps_unverified(
    tmp_path, monkeypatch
):
    binary = write_fixture(
        tmp_path, "trufflehog", "# never executed; mocked subprocess\n"
    )
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        if command[-1] == "--version":
            return subprocess.CompletedProcess(command, 0, "trufflehog 3.99.8\n", "")
        assert "--no-verification" in command and "--no-update" in command
        assert "--results=verified,unverified,unknown" in command
        assert kwargs["env"]["SKYLOS_NO_UPLOAD"] == "1"
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(benchmark.subprocess, "run", fake_run)
    summary = benchmark.run_manifest(
        MANIFEST,
        output=tmp_path / "report",
        scanner="trufflehog",
        trufflehog=binary,
        selected_cases={"env-reference"},
    )
    assert summary["passed"]
    assert len(calls) == 2
    assert "--no-update" in calls[0]
    assert summary["tool"]["detectors"] == "default built-ins"


@pytest.mark.parametrize(
    "failure", ["zero-exit-error-log", "nonzero-exit", "malformed-stdout"]
)
def test_th_scan_failures_never_turn_a_quiet_case_into_a_pass(
    tmp_path, monkeypatch, failure
):
    fixture = tmp_path / "fixture"
    benchmark.materialize(_case("env-reference"), fixture)
    directory = tmp_path / "report"
    directory.mkdir()

    def fake_run(command, **kwargs):
        assert "--fail-on-scan-errors" in command
        if failure == "zero-exit-error-log":
            kwargs["stderr"].write(
                json.dumps({"level": "error", "msg": "read failed"}) + "\n"
            )
        if failure == "malformed-stdout":
            kwargs["stdout"].write("not valid JSON\n")
        return subprocess.CompletedProcess(
            command, 1 if failure == "nonzero-exit" else 0
        )

    monkeypatch.setattr(benchmark.subprocess, "run", fake_run)
    findings, errors, _ = benchmark._run_scanner(
        "trufflehog", fixture, directory, ROOT, tmp_path / "trufflehog"
    )
    assert errors
    assert (
        benchmark.grade(_case("env-reference"), findings, errors)["status"]
        == "incomplete"
    )
