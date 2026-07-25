from __future__ import annotations

import json
import os
from pathlib import Path
import stat

import pytest

import scripts.deep_audit_logic_benchmark as benchmark_script


def _summary(*, error: str = "") -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": "pass",
        "pass_count": 1,
        "case_count": 1,
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
        "false_clean_count": 0,
        "wrong_target_count": 0,
        "incomplete_count": 0,
        "abstention_count": 0,
        "cases": [
            {
                "id": "model-controlled-case",
                "label": "vulnerable",
                "passed": True,
                "failures": [],
                "actual": {
                    "status": "complete",
                    "finding_count": 1,
                    "tool_calls": 2,
                    "turns": 3,
                    "total_tokens": 4,
                    "finding_targets": [
                        {
                            "rule_ids": ["SKY-AUDIT-LOGIC"],
                            "categories": ["authorization_scope"],
                            "symbols": ["handler"],
                            "primary_files": ["app.py"],
                            "evidence_files": ["app.py"],
                        }
                    ],
                    "finding_claims": [
                        {
                            "message": "MODEL MESSAGE MUST NOT PERSIST",
                            "invariant": "MODEL INVARIANT MUST NOT PERSIST",
                            "trigger": "MODEL TRIGGER MUST NOT PERSIST",
                            "actual_behavior": "SOURCE-LIKE MODEL PROSE",
                            "impact": "MODEL IMPACT MUST NOT PERSIST",
                            "evidence": [
                                {
                                    "file": "app.py",
                                    "line": 1,
                                    "end_line": 2,
                                    "role": "MODEL EVIDENCE ROLE MUST NOT PERSIST",
                                }
                            ],
                        }
                    ],
                    "error": error,
                },
            }
        ],
    }


def test_default_report_omits_model_prose_without_mutating_summary() -> None:
    summary = _summary()

    report = benchmark_script._prepare_report(
        summary,
        include_model_prose=False,
    )

    actual = report["cases"][0]["actual"]
    assert "finding_claims" not in actual
    assert actual["finding_targets"][0]["primary_files"] == ["app.py"]
    assert report["report_content"] == "projections_only"
    serialized = json.dumps(report)
    for model_prose in (
        "MODEL MESSAGE MUST NOT PERSIST",
        "MODEL INVARIANT MUST NOT PERSIST",
        "MODEL TRIGGER MUST NOT PERSIST",
        "SOURCE-LIKE MODEL PROSE",
        "MODEL EVIDENCE ROLE MUST NOT PERSIST",
    ):
        assert model_prose not in serialized
    assert "finding_claims" in summary["cases"][0]["actual"]


def test_model_prose_requires_explicit_opt_in() -> None:
    report = benchmark_script._prepare_report(
        _summary(),
        include_model_prose=True,
    )

    actual = report["cases"][0]["actual"]
    assert actual["finding_claims"][0]["message"] == ("MODEL MESSAGE MUST NOT PERSIST")
    assert report["report_content"] == "model_prose_included"


def test_report_errors_are_redacted_single_line_and_bounded() -> None:
    raw_error = (
        "\x1b[31mrequest failed\x1b[0m\n"
        "Authorization: Bearer abcdefghijklmnop\t"
        "OPENAI_API_KEY=top-secret sk-abcdefghijklmnopqrstuvwxyz " + ("x" * 2_000)
    )

    report = benchmark_script._prepare_report(
        _summary(error=raw_error),
        include_model_prose=False,
    )

    persisted = report["cases"][0]["actual"]["error"]
    assert len(persisted) == benchmark_script.MAX_PERSISTED_ERROR_CHARS
    assert "\n" not in persisted
    assert "\x1b" not in persisted
    assert "abcdefghijklmnop" not in persisted
    assert "top-secret" not in persisted
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in persisted
    assert persisted.endswith("...[truncated]")


def test_private_atomic_writer_rejects_preplanted_output_symlink(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.json"
    target.write_text("unchanged", encoding="utf-8")
    output = tmp_path / "report.json"
    output.symlink_to(target)

    with pytest.raises(
        benchmark_script.BenchmarkReportOutputError,
        match="symbolic-link",
    ):
        benchmark_script._write_private_atomic_json(output, {"status": "pass"})

    assert output.is_symlink()
    assert target.read_text(encoding="utf-8") == "unchanged"


def test_private_atomic_writer_rejects_symlink_parent(tmp_path: Path) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(
        benchmark_script.BenchmarkReportOutputError,
        match="unsafe report parent component",
    ):
        benchmark_script._write_private_atomic_json(
            linked_parent / "report.json",
            {"status": "pass"},
        )

    assert not (real_parent / "report.json").exists()


def test_private_atomic_writer_creates_private_file_and_parents(
    tmp_path: Path,
) -> None:
    output = tmp_path / "new" / "nested" / "report.json"

    benchmark_script._write_private_atomic_json(output, {"status": "pass"})

    assert json.loads(output.read_text(encoding="utf-8")) == {"status": "pass"}
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert stat.S_IMODE(output.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(output.parent.parent.stat().st_mode) == 0o700


def test_private_atomic_writer_replaces_regular_file_with_private_mode(
    tmp_path: Path,
) -> None:
    output = tmp_path / "report.json"
    output.write_text("old", encoding="utf-8")
    output.chmod(0o644)

    benchmark_script._write_private_atomic_json(output, {"status": "new"})

    assert json.loads(output.read_text(encoding="utf-8")) == {"status": "new"}
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_private_atomic_writer_leaves_no_partial_file_on_replace_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "report.json"
    output.write_text("original", encoding="utf-8")

    def fail_replace(*args, **kwargs) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr(benchmark_script.os, "replace", fail_replace)

    with pytest.raises(
        benchmark_script.BenchmarkReportOutputError,
        match="could not safely write",
    ):
        benchmark_script._write_private_atomic_json(output, {"status": "new"})

    assert output.read_text(encoding="utf-8") == "original"
    assert list(tmp_path.iterdir()) == [output]


def test_main_persists_projection_only_report_by_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "report.json"
    monkeypatch.setattr(
        benchmark_script,
        "resolve_llm_runtime",
        lambda **_kwargs: ("openai", "KEY", None, False),
    )
    monkeypatch.setattr(
        benchmark_script,
        "run_manifest",
        lambda *args, **kwargs: _summary(),
    )
    monkeypatch.setattr(
        "sys.argv",
        ["deep_audit_logic_benchmark.py", "--output", os.fspath(output), "--json"],
    )

    assert benchmark_script.main() == 0

    persisted = json.loads(output.read_text(encoding="utf-8"))
    assert persisted["report_content"] == "projections_only"
    assert "finding_claims" not in persisted["cases"][0]["actual"]
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
