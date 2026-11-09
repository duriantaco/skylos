from __future__ import annotations

import io
import json
import os
from unittest.mock import patch

import pytest

from skylos.commands import cleanup_cmd


def _read_report(root, report):
    output = io.StringIO()
    with patch("skylos.cleanup.build_cleanup_plan") as planner:
        planner.return_value = {
            "status": "clear",
            "tasks": [],
            "advisories": [],
            "counts": {},
        }
        code = cleanup_cmd.run_cleanup_command(
            [str(root), "--from-report", str(report), "--format", "json"],
            stdout=output,
            analyze_func=lambda *_a, **_kw: pytest.fail(
                "saved input must remain offline"
            ),
        )
    return code, json.loads(output.getvalue()), planner.call_count


def test_operator_can_read_a_regular_report_outside_source_root(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    report = tmp_path / "chosen-report.json"
    original = b'{"quality": []}\n'
    report.write_bytes(original)

    code, result, planned = _read_report(root, report)

    assert code == 0
    assert result["source"] == "saved_report"
    assert planned == 1
    assert report.read_bytes() == original
    assert not (root / ".skylos").exists()


def test_symlinked_report_is_refused_before_parsing(tmp_path):
    report = tmp_path / "original.json"
    original = b'{"quality": []}\n'
    report.write_bytes(original)
    link = tmp_path / "linked-report.json"
    link.symlink_to(report)

    code, result, planned = _read_report(tmp_path, link)

    assert code == 2
    assert result["status"] == "incomplete"
    assert planned == 0
    assert report.read_bytes() == original


def test_oversized_report_is_refused_before_parsing(tmp_path, monkeypatch):
    report = tmp_path / "large.json"
    report.write_text('{"quality": []}' + " " * 128, encoding="utf-8")
    monkeypatch.setattr(cleanup_cmd, "MAX_SAVED_REPORT_BYTES", 128, raising=False)

    code, result, planned = _read_report(tmp_path, report)

    assert code == 2
    assert result["status"] == "incomplete"
    assert planned == 0


def test_named_pipe_is_refused_without_waiting_for_a_writer(tmp_path):
    if not hasattr(os, "mkfifo"):
        pytest.skip("named pipes are unavailable")
    report = tmp_path / "pipe.json"
    os.mkfifo(report)

    # Failure to use the bounded nonblocking reader must fail this test before
    # opening the pipe, rather than hanging the test process.
    with patch.object(
        type(report), "read_text", side_effect=AssertionError("unbounded report read")
    ):
        code, result, planned = _read_report(tmp_path, report)

    assert code == 2
    assert result["status"] == "incomplete"
    assert planned == 0
    assert "unbounded report read" not in " ".join(result["limitations"])
