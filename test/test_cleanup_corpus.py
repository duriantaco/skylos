"""The corpus evaluator must not turn incidental findings into accuracy claims."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import os

import pytest

from skylos.benchmarks.cleanup_corpus import (
    _blocked_operation,
    _contained,
    evaluate_case,
    load_cases,
)


MANIFEST = (
    Path(__file__).resolve().parents[1] / "benchmarks/cleanup/corpus/manifest.json"
)


def _case(variant="problematic", *, language="python", rule_ids=None):
    return {
        "id": "example",
        "pair_id": "pair",
        "pattern": "mutable-default",
        "variant": variant,
        "language": language,
        "targets": [
            {
                "file": "app.py",
                "start_line": 3,
                "end_line": 4,
                "rule_ids": ["SKY-L001"] if rule_ids is None else rule_ids,
            }
        ],
    }


def _observation(findings=(), *, language="Python"):
    return {
        "exit_code": 0,
        "queue_status": "ready",
        "limitations": [],
        "analysis_errors": [],
        "analysis_summary": {"total_files": 1, "languages": {language: 1}},
        "findings": list(findings),
        "source_unchanged": True,
        "blocked_events": [],
        "default_queue": [],
        "all_advice_queue": list(findings),
    }


@pytest.mark.parametrize(
    "finding",
    [
        {"rule_id": "SKY-L007", "file": "app.py", "line": 3},
        {"rule_id": "SKY-L001", "file": "other.py", "line": 3},
        {"rule_id": "SKY-L001", "file": "app.py", "line": 20},
        {"rule_id": "SKY-L001", "file": "app.py", "line": True},
    ],
)
def test_unrelated_rule_file_or_line_cannot_count_as_a_catch(finding):
    result = evaluate_case(_case(), _observation([finding]))
    assert result["targets"][0]["outcome"] == "missed"


def test_detection_and_queue_visibility_are_separate():
    finding = {"rule_id": "SKY-L001", "file": "app.py", "line": 3}
    result = evaluate_case(_case(), _observation([finding]))
    target = result["targets"][0]
    assert target["outcome"] == "detected"
    assert target["default_visible"] is False
    assert target["all_advice_visible"] is True
    assert (
        evaluate_case(_case("control"), _observation([finding]))["targets"][0][
            "outcome"
        ]
        == "false_positive"
    )
    assert (
        evaluate_case(_case("control"), _observation())["targets"][0]["outcome"]
        == "clean_control"
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"queue_status": "incomplete"},
        {"exit_code": 2},
        {"analysis_summary": {"total_files": 0}},
        {"analysis_errors": [{"file": "app.py", "message": "parse failed"}]},
        {"source_unchanged": False},
        {"blocked_events": [{"event": "socket.connect"}]},
        {"limitations": ["API coverage incomplete"]},
    ],
)
def test_incomplete_or_unsafe_scans_never_count_as_success(changes):
    observed = _observation()
    observed.update(changes)
    result = evaluate_case(_case("control"), observed)
    assert result["analysis_status"] == "incomplete"
    assert result["targets"][0]["outcome"] == "incomplete"


@pytest.mark.parametrize("variant", ["problematic", "control"])
def test_unmapped_patterns_are_neither_misses_nor_passing_controls(variant):
    result = evaluate_case(_case(variant, rule_ids=[]), _observation())
    assert result["targets"][0]["outcome"] == "unmapped"


def test_javascript_coverage_requires_its_actual_engine_label():
    result = evaluate_case(
        _case(language="javascript"), _observation(language="JavaScript")
    )
    assert result["analysis_status"] == "complete"


def test_checked_in_corpus_has_pinned_pairs_and_no_claimed_test_smell_mapping():
    _, cases = load_cases(MANIFEST)
    assert len(cases) == 16
    assert len({case["pair_id"] for case in cases}) == 8
    unmapped = [
        case for case in cases if not any(t["rule_ids"] for t in case["targets"])
    ]
    assert len(unmapped) == 8
    assert all(
        case["source"]["kind"] == "independently-authored-reproduction"
        for case in cases
    )


def test_initial_receipt_is_bound_to_the_measured_sources():
    report = json.loads((MANIFEST.parent / "baseline.json").read_text(encoding="utf-8"))
    _, cases = load_cases(MANIFEST)
    declared = {case["id"]: case for case in cases}
    assert report["repair_evaluated"] is False
    assert report["target_code_executed"] is False
    for case in report["cases"]:
        metadata = json.dumps(
            declared[case["id"]], sort_keys=True, separators=(",", ":")
        )
        assert (
            hashlib.sha256(metadata.encode()).hexdigest()
            == case["case_metadata_sha256"]
        )
        directory = _contained(MANIFEST.parent, case["path"])
        for name, digest in case["source_sha256"].items():
            assert (
                hashlib.sha256(_contained(directory, name).read_bytes()).hexdigest()
                == digest
            )
        assert case["source_sha256"] == case["observation"]["source_sha256"]
        assert case["observation"]["source_unchanged"] is True
        assert case["observation"]["blocked_events"] == []


def test_manifest_refuses_partial_pairs_and_unknown_rule_ids(tmp_path):
    root = tmp_path / "case"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    case = _case()
    case.update(
        path="case",
        rationale="Example",
        source={
            "url": "https://example.org/pattern",
            "revision": "v1",
            "license": "MIT",
            "kind": "reproduction",
        },
    )
    case["targets"][0].update(start_line=1, end_line=1)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"schema_version": 1, "cases": [case]}), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="one problematic case and one control"):
        load_cases(manifest)
    control = deepcopy(case)
    control.update(id="control", variant="control")
    control["targets"][0]["rule_ids"] = ["SKY-NOT-A-RULE"]
    manifest.write_text(
        json.dumps({"schema_version": 1, "cases": [case, control]}), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="unknown rule id"):
        load_cases(manifest)


def test_paths_cannot_escape_or_follow_symlinks(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("data", encoding="utf-8")
    (root / "link").symlink_to(outside)
    for value in ("../outside", str(outside), "link"):
        with pytest.raises(ValueError):
            _contained(root, value)


def test_corpus_rejects_special_files_before_reading_them(tmp_path):
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO is unavailable")
    from skylos.benchmarks.cleanup_corpus import _regular_tree

    os.mkfifo(tmp_path / "app.py")
    assert _regular_tree(tmp_path) is False


def test_worker_blocks_target_imports_network_and_non_readonly_processes(tmp_path):
    compiled = compile("value = 1", str(tmp_path / "app.py"), "exec")
    assert (
        _blocked_operation("exec", (compiled,), tmp_path) == "corpus source execution"
    )
    assert _blocked_operation("socket.connect", (), tmp_path) == "network"
    assert (
        _blocked_operation(
            "subprocess.Popen", ("python", ["python", "app.py"]), tmp_path
        )
        == "non-Git subprocess"
    )
    assert (
        _blocked_operation(
            "subprocess.Popen", ("git", ["git", "reset", "--hard"]), tmp_path
        )
        == "unexpected Git operation"
    )
    assert (
        _blocked_operation(
            "subprocess.Popen",
            ("git", ["git", "-C", str(tmp_path), "rev-parse", "HEAD"]),
            tmp_path,
        )
        is None
    )
    from skylos.core.git_safety import read_only_git_command

    safe = read_only_git_command(["-C", str(tmp_path), "rev-parse", "HEAD"])
    assert _blocked_operation("subprocess.Popen", ("git", safe), tmp_path) is None
    unsafe = read_only_git_command(["reset", "--hard"])
    assert (
        _blocked_operation("subprocess.Popen", ("git", unsafe), tmp_path)
        == "unexpected Git operation"
    )
    config = read_only_git_command(
        ["config", "--includes", "--null", "--name-only", "--get-regexp", "^filter\\."]
    )
    assert _blocked_operation("subprocess.Popen", ("git", config), tmp_path) is None
    write = read_only_git_command(["config", "core.hooksPath", "/tmp/hooks"])
    assert (
        _blocked_operation("subprocess.Popen", ("git", write), tmp_path)
        == "unexpected Git operation"
    )
