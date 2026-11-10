"""New static test-quality findings reach the actual default cleanup flow."""

from hashlib import sha256
import io
import json
import os
from pathlib import Path
import shutil

import pytest

from skylos.cleanup_execution import plan_cleanup_edit
from skylos.commands.cleanup_cmd import run_cleanup_command


CORPUS = Path(__file__).resolve().parents[1] / "corpus"
CASES = [
    case
    for case in json.loads((CORPUS / "manifest.json").read_text())["cases"]
    if case["id"].startswith("test-quality-")
]


def _project(tmp_path, monkeypatch, case):
    project = tmp_path / "project"
    shutil.copytree(CORPUS / case["path"], project)
    operator = tmp_path / "operator.toml"
    operator.write_text("[tool.skylos]\n")
    policy = tmp_path / "policy" / "config.yaml"
    policy.parent.mkdir()
    policy.write_text("{}\n")
    for name in list(os.environ):
        if name.startswith("SKYLOS_"):
            monkeypatch.delenv(name)
    monkeypatch.setenv("SKYLOS_CONFIG_FILE", str(operator))
    monkeypatch.setenv("SKYLOS_SYNCED_POLICY_FILE", str(policy))
    monkeypatch.setenv("SKYLOS_CUSTOM_RULES", "[]")
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    return project


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_native_cleanup_shows_test_quality_evidence_without_editing_source(
    tmp_path, monkeypatch, case
):
    project = _project(tmp_path, monkeypatch, case)
    source = project / "test_case.py"
    original = source.read_bytes()
    output = io.StringIO()
    code = run_cleanup_command(
        [str(project), "--format", "json", "--context", "--no-state", "--top", "1000"],
        stdout=output,
    )
    report = json.loads(output.getvalue())
    assert code == 0, report
    assert report["status"] in {"ready", "clear"}
    mode = "present" if "present" in case["expect"] else "absent"
    target = case["expect"][mode]["quality"][0]
    matched = [row for row in report["tasks"] if row["rule_id"] == target["rule_id"]]
    if mode == "present":
        assert len(matched) == 1, report
        task = matched[0]
        assert task["line"] == target["start_line"]
        assert task["file"] == "test_case.py"
        assert task["finding_type"] == "review"
        assert task["evidence"]["pattern"]
        assert task["evidence"]["test"]
        assert task["message"] and task["action"]
        assert task["source_sha256"] == sha256(original).hexdigest()
        assert report["context"]["files"], report
        with pytest.raises(ValueError, match="no deterministic cleanup edit"):
            plan_cleanup_edit(task, project)
    else:
        assert matched == [], report
    assert source.read_bytes() == original
    assert not (project / ".skylos").exists()


@pytest.mark.parametrize(
    "case",
    [case for case in CASES if "present" in case["expect"]],
    ids=lambda case: case["id"],
)
def test_test_quality_task_identity_survives_source_line_shifts(
    tmp_path, monkeypatch, case
):
    project = _project(tmp_path, monkeypatch, case)
    rule = case["expect"]["present"]["quality"][0]["rule_id"]

    def task():
        output = io.StringIO()
        code = run_cleanup_command(
            [str(project), "--format", "json", "--no-state", "--top", "1000"],
            stdout=output,
        )
        report = json.loads(output.getvalue())
        assert code == 0, report
        return next(row for row in report["tasks"] if row["rule_id"] == rule)

    before = task()
    source = project / "test_case.py"
    source.write_bytes(b"\n" + source.read_bytes())
    after = task()
    assert before["source_anchor"] and after["source_anchor"]
    assert after["line"] == before["line"] + 1
    assert after["id"] == before["id"]
    assert after["source_sha256"] != before["source_sha256"]
