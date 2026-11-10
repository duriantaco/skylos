import io
import json

import pytest

from skylos.commands.cleanup_cmd import run_cleanup_command


def _raw(root):
    return {
        "analysis_errors": [],
        "analysis_summary": {
            "total_files": 1,
            "grade_categories": ["quality", "ai_defects", "dead_code"],
            "ai_verification": {"state": "complete"},
            "comparison_scope": {"scan_path": str(root)},
        },
        "unused_imports": [
            {
                "name": name,
                "file": str(root / "app.py"),
                "line": line,
                "confidence": 100,
            }
            for line, name in enumerate(("math", "statistics"), 1)
        ],
    }


def _run(root, *args):
    output = io.StringIO()
    code = run_cleanup_command(
        [str(root), *args, "--format", "json"],
        stdout=output,
        analyze_func=lambda *_a, **_kw: _raw(root),
    )
    result = json.loads(output.getvalue())
    assert code == 0, result
    return result


def test_create_reorder_complete_and_list_local_plan(tmp_path):
    source = "import math\nimport statistics\nvalue = 3\n"
    (tmp_path / "app.py").write_text(source)
    tasks = _run(tmp_path)["tasks"]
    ids = [task["id"] for task in tasks]
    created = _run(
        tmp_path,
        "--create-plan",
        "imports",
        "--plan-task",
        ids[0],
        "--plan-task",
        ids[1],
        "--prerequisite",
        "Review callers",
        "--acceptance-check",
        "pytest -q",
    )
    assert [step["task_id"] for step in created["plan"]["steps"]] == ids
    assert created["plan"]["acceptance_checks"] == ["pytest -q"]
    assert created["plan"]["execution_authorized"] is False
    moved = _run(
        tmp_path, "--plan", "imports", "--move-task", ids[1], "--before", ids[0]
    )
    assert moved["plan"]["steps"][0]["task_id"] == ids[1]
    completed = _run(tmp_path, "--plan", "imports", "--complete-task", ids[1])
    assert completed["plan"]["completed_steps"] == 1
    assert completed["plan"]["steps"][0]["verification_status"] == "unverified"
    listed = _run(tmp_path, "--plans")
    assert listed["plans"][0]["name"] == "imports"
    assert (tmp_path / "app.py").read_text() == source


def test_model_review_is_saved_and_promoted_explicitly_as_advice(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("import math\nimport statistics\nvalue = 3\n")

    class Model:
        _cleanup_provider = "fixture"

        def complete(self, *_args, **_kwargs):
            return json.dumps(
                {
                    "advice": [
                        {
                            "file": "app.py",
                            "line": 1,
                            "summary": "Review imports",
                            "evidence": "The selected import has no local reference",
                            "suggestion": "Check effects before removing",
                            "confidence": "medium",
                        }
                    ]
                }
            )

    monkeypatch.setattr(
        "skylos.commands.cleanup_cmd._review_adapter", lambda _args: Model()
    )
    reviewed = _run(tmp_path, "--review", "--top", "1")
    assert reviewed["context_review"]["status"] == "reviewed"
    saved = _run(tmp_path, "--reviews")["stored_reviews"]
    assert len(saved) == 1
    assert saved[0]["provenance"]["provider"] == "fixture"
    assert saved[0]["refresh_status"] == "current"
    task = reviewed["tasks"][0]["id"]
    _run(tmp_path, "--create-plan", "reviewed", "--plan-task", task)
    promoted = _run(tmp_path, "--plan", "reviewed", "--promote-review", saved[0]["id"])
    assert promoted["plan"]["steps"][-1]["kind"] == "review_advice"
    assert promoted["plan"]["steps"][-1]["verification_status"] == "unverified"
    (tmp_path / "app.py").write_text("import math\nimport statistics\nvalue = 4\n")
    stale = _run(tmp_path, "--reviews")["stored_reviews"][0]
    assert stale["refresh_status"] == "stale"


def test_apply_checks_security_and_secrets_in_both_scans(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("import math\nimport statistics\nvalue = 3\n")
    task = _run(tmp_path)["tasks"][0]["id"]
    calls = []

    def scan(*_args, **kwargs):
        calls.append(kwargs)
        result = _raw(tmp_path)
        result["unused_imports"] = [
            row for row in result["unused_imports"] if row["name"] in source.read_text()
        ]
        result["analysis_summary"]["grade_categories"] += ["security", "secrets"]
        return result

    output = io.StringIO()
    code = run_cleanup_command(
        [str(tmp_path), "--task", task, "--apply", "--format", "json"],
        stdout=output,
        analyze_func=scan,
    )
    report = json.loads(output.getvalue())
    assert code == 0, report
    assert len(calls) == 2
    assert all(call["enable_danger"] and call["enable_secrets"] for call in calls)
    assert all(call["enable_sca"] is False for call in calls)
    assert report["execution"]["rescan"]["checked_categories"] == [
        "ai_defects",
        "dead_code",
        "quality",
        "secrets",
        "security",
    ]
    assert report["execution"]["status"] == "applied_unverified"


def test_human_context_points_to_the_reported_source_line(tmp_path):
    (tmp_path / "app.py").write_text("import math\nimport statistics\nvalue = 3\n")
    output = io.StringIO()
    code = run_cleanup_command(
        [str(tmp_path), "--context", "--top", "1"],
        stdout=output,
        analyze_func=lambda *_a, **_kw: _raw(tmp_path),
    )
    text = output.getvalue()
    assert code == 0
    assert "Source context (bounded" in text
    assert "app.py:1" in text
    assert "1 > import math" in text
    assert "SKY-U002" in text


@pytest.mark.parametrize(
    "args",
    [
        ["--create-plan", "x"],
        ["--plan-task", "id"],
        ["--before", "id"],
        ["--move-task", "id", "--before", "other"],
        ["--complete-task", "id"],
        ["--promote-review", "id"],
        ["--note", "done"],
        ["--plan", "x", "--no-state"],
        ["--plans", "--reviews"],
        ["--reviews", "--review"],
        ["--plan", "x", "--task", "id"],
        ["--create-plan", "x", "--plan-task", "id", "--from-report", "r.json"],
        ["--junit-report", "junit.xml"],
    ],
)
def test_invalid_workspace_actions_fail_before_scanning(args):
    with pytest.raises(SystemExit) as error:
        run_cleanup_command(
            args, analyze_func=lambda *_a, **_kw: pytest.fail("must not scan")
        )
    assert error.value.code == 2
