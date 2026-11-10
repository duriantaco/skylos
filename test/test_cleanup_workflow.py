from copy import deepcopy
import io
import json
import shlex
import sys

import pytest

from skylos.cleanup import build_cleanup_plan
from skylos.cleanup_context import build_cleanup_context, review_cleanup_context
from skylos.cleanup_state import update_cleanup_state, load_cleanup_state
from skylos.commands.cleanup_cmd import run_cleanup_command


def raw(root, *, present=True):
    return {
        "analysis_errors": [],
        "analysis_summary": {
            "total_files": 1,
            "grade_categories": ["quality", "ai_defects", "dead_code"],
            "ai_verification": {"state": "complete"},
            "comparison_scope": {
                "repository_root": str(root),
                "scan_path": str(root),
                "targets": [str(root)],
            },
        },
        "unused_imports": [
            {"name": "math", "file": str(root / "app.py"), "line": 1, "confidence": 100}
        ]
        if present
        else [],
        "quality": [],
        "ai_defects": [],
    }


def run(args, analyze):
    out = io.StringIO()
    code = run_cleanup_command(
        [*args, "--format", "json"], stdout=out, analyze_func=analyze
    )
    return code, json.loads(out.getvalue())


def test_task_identity_survives_blank_lines_but_apply_source_hash_changes(tmp_path):
    file = tmp_path / "app.py"
    file.write_text("import math\n")
    first = build_cleanup_plan(raw(tmp_path), project_root=tmp_path)["tasks"][0]
    file.write_text("\n\nimport math\n")
    report = raw(tmp_path)
    report["unused_imports"][0]["line"] = 3
    second = build_cleanup_plan(report, project_root=tmp_path)["tasks"][0]
    assert first["id"] == second["id"]
    assert first["source_sha256"] != second["source_sha256"]


def test_scope_and_incomplete_scans_cannot_resolve_missing_tasks(tmp_path):
    (tmp_path / "app.py").write_text("import math\n")
    plan = build_cleanup_plan(raw(tmp_path), project_root=tmp_path)
    scope = {"target": str(tmp_path), "config_digest": "a"}
    first = update_cleanup_state(tmp_path, scope, plan)
    task_id = next(iter(first["tasks"]))
    update_cleanup_state(
        tmp_path,
        {**scope, "target": str(tmp_path / "other")},
        {"status": "clear", "tasks": [], "advisories": []},
    )
    incomplete = update_cleanup_state(
        tmp_path, scope, {"status": "incomplete", "tasks": [], "advisories": []}
    )
    assert incomplete["tasks"][task_id]["status"] == "open"
    absent = update_cleanup_state(
        tmp_path, scope, {"status": "clear", "tasks": [], "advisories": []}
    )
    assert absent["tasks"][task_id]["status"] == "not_reported"
    reopened = update_cleanup_state(tmp_path, scope, plan)
    assert reopened["tasks"][task_id]["status"] == "open"
    assert reopened["tasks"][task_id]["history"][-1]["status"] == "reopened"


def test_defer_restore_and_history_are_local_without_changing_raw_findings(tmp_path):
    (tmp_path / "app.py").write_text("import math\n")
    original = raw(tmp_path)
    code, plan = run([str(tmp_path)], lambda *_a, **_kw: deepcopy(original))
    assert code == 0
    task_id = plan["tasks"][0]["id"]
    code, deferred = run(
        [
            str(tmp_path),
            "--defer",
            task_id[:16],
            "--reason",
            "Public plugin dependency under review",
        ],
        lambda *_a, **_kw: deepcopy(original),
    )
    assert code == 0 and deferred["tasks"] == []
    assert deferred["counts"]["deferred_tasks"] == 1
    code, restored = run(
        [str(tmp_path), "--restore", task_id], lambda *_a, **_kw: deepcopy(original)
    )
    assert restored["tasks"][0]["state"] == "open"
    code, history = run(
        [str(tmp_path), "--history"],
        lambda *_a, **_kw: pytest.fail("history must not scan"),
    )
    assert code == 0 and history["status"] == "history"
    assert len(history["history"]["scopes"]) == 1
    assert original == raw(tmp_path)


def test_preview_then_apply_rescans_and_skipped_tests_stay_unverified(tmp_path):
    file = tmp_path / "app.py"
    file.write_text("import math\nvalue = 3\n")

    def scanner(*_a, **_kw):
        return raw(tmp_path, present="import math" in file.read_text())

    _, plan = run([str(tmp_path)], scanner)
    task_id = plan["tasks"][0]["id"]
    code, preview = run([str(tmp_path), "--task", task_id], scanner)
    assert code == 0 and "-import math" in preview["edit"]["patch"]
    assert file.read_text() == "import math\nvalue = 3\n"
    assert not any(key.startswith("_") for key in preview["edit"])
    code, applied = run([str(tmp_path), "--task", task_id, "--apply"], scanner)
    assert code == 0, applied
    assert applied["execution"]["status"] == "applied_unverified"
    assert applied["execution"]["tests"]["status"] == "skipped"
    assert file.read_text() == "value = 3\n"
    assert "_baseline_report" not in json.dumps(applied)


def test_authorized_passing_tests_and_same_scope_rescan_produce_verified_receipt(
    tmp_path,
):
    file = tmp_path / "app.py"
    file.write_text("import math\nvalue = 3\n")

    def scanner(*_a, **_kw):
        return raw(tmp_path, present="import math" in file.read_text())

    _, plan = run([str(tmp_path)], scanner)
    (tmp_path / "test_app.py").write_text(
        "import app\n\ndef test_value():\n    assert app.value == 3\n"
    )
    cmd = shlex.join([sys.executable, "-m", "pytest", "-q", "test_app.py"])
    code, applied = run(
        [str(tmp_path), "--task", plan["tasks"][0]["id"], "--apply", "--test-cmd", cmd],
        scanner,
    )
    assert code == 0, applied
    assert applied["execution"]["status"] == "verified"
    assert applied["execution"]["tests"]["status"] == "passed"
    assert applied["execution"]["rescan"]["status"] == "passed"


def test_failing_authorized_check_rolls_back_and_returns_failure(tmp_path):
    file = tmp_path / "app.py"
    original = "import math\nvalue = 3\n"
    file.write_text(original)

    def scanner(*_a, **_kw):
        return raw(tmp_path, present="import math" in file.read_text())

    _, plan = run([str(tmp_path)], scanner)
    cmd = shlex.join([sys.executable, "-c", "raise SystemExit(1)"])
    code, report = run(
        [str(tmp_path), "--task", plan["tasks"][0]["id"], "--apply", "--test-cmd", cmd],
        scanner,
    )
    assert code == 1, report
    assert report["execution"]["status"] == "failed"
    assert file.read_text() == original


def test_local_review_decisions_are_applied_to_cleanup(tmp_path, monkeypatch):
    from skylos.core import review_decisions

    (tmp_path / "app.py").write_text("import math\n")
    calls = []

    def apply(result, root):
        calls.append(root)
        result["unused_imports"] = []
        return result

    monkeypatch.setattr(review_decisions, "apply_trusted_review_decisions", apply)
    code, plan = run([str(tmp_path)], lambda *_a, **_kw: raw(tmp_path))
    assert code == 0 and plan["tasks"] == []
    assert calls == [tmp_path]


def test_context_includes_candidate_callers_and_model_cannot_invent_files(tmp_path):
    (tmp_path / "app.py").write_text("def process():\n    return 1\n")
    (tmp_path / "caller.py").write_text("from app import process\nresult = process()\n")
    task = {
        "id": "task",
        "file": "app.py",
        "line": 1,
        "name": "process",
        "rule_id": "SKY-U001",
    }
    context = build_cleanup_context([task], tmp_path)
    assert any(row["file"] == "caller.py" for row in context["candidate_callers"])
    assert context["caller_resolution"].startswith("Candidate")

    class Model:
        def complete(self, *_args, **_kwargs):
            return json.dumps(
                {
                    "advice": [
                        {
                            "file": "missing.py",
                            "line": 1,
                            "summary": "a",
                            "evidence": "b",
                            "suggestion": "c",
                            "confidence": "high",
                        }
                    ]
                }
            )

    assert review_cleanup_context(context, [task], Model())["status"] == "incomplete"


def test_malformed_or_symlink_state_is_not_replaced(tmp_path):
    path = tmp_path / ".skylos/cache/cleanup.json"
    path.parent.mkdir(parents=True)
    path.write_text("{")
    with pytest.raises(ValueError, match="malformed"):
        load_cleanup_state(tmp_path)
    assert path.read_text() == "{"


def test_display_limit_never_marks_other_tasks_resolved(tmp_path):
    (tmp_path / "app.py").write_text("import math\nimport statistics\nvalue = 3\n")
    report = raw(tmp_path)
    report["unused_imports"].append(
        {
            "name": "statistics",
            "file": str(tmp_path / "app.py"),
            "line": 2,
            "confidence": 100,
        }
    )
    for _ in range(2):
        code, plan = run(
            [str(tmp_path), "--top", "1"], lambda *_a, **_kw: deepcopy(report)
        )
        assert code == 0 and len(plan["tasks"]) == 1
        assert len(plan["state"]["tasks"]) == 2
        assert {row["status"] for row in plan["state"]["tasks"].values()} == {"open"}


def test_actual_analyzer_patch_roundtrip(tmp_path):
    file = tmp_path / "app.py"
    file.write_text("import math\nprint('ready')\n")
    output = io.StringIO()
    code = run_cleanup_command([str(tmp_path), "--format", "json"], stdout=output)
    plan = json.loads(output.getvalue())
    assert code == 0, plan
    task = next(task for task in plan["tasks"] if task["rule_id"] == "SKY-U002")
    output = io.StringIO()
    code = run_cleanup_command(
        [str(tmp_path), "--task", task["id"], "--apply", "--format", "json"],
        stdout=output,
    )
    receipt = json.loads(output.getvalue())
    assert code == 0, receipt
    assert receipt["execution"]["status"] == "applied_unverified"
    assert receipt["execution"]["rescan"]["status"] == "passed"
    assert file.read_text() == "print('ready')\n"


def test_policy_changed_by_authorized_check_cannot_verify_a_fix(tmp_path, monkeypatch):
    file = tmp_path / "app.py"
    file.write_text("import math\nvalue = 3\n")

    def scanner(*_a, **_kw):
        return raw(tmp_path, present="import math" in file.read_text())

    _, plan = run([str(tmp_path)], scanner)

    def changed_policy(*_args, **_kwargs):
        (tmp_path / "pyproject.toml").write_text(
            '[tool.skylos]\nignore = ["SKY-U002"]\n'
        )
        return {
            "status": "passed",
            "returncode": 0,
            "observed": True,
            "evidence": "pytest_junit",
            "count": 1,
        }

    monkeypatch.setattr("skylos.cleanup_checks.run_cleanup_tests", changed_policy)
    code, report = run(
        [
            str(tmp_path),
            "--task",
            plan["tasks"][0]["id"],
            "--apply",
            "--test-cmd",
            "pytest",
        ],
        scanner,
    )
    assert code == 2
    assert report["execution"]["status"] == "incomplete"
    assert "configuration changed" in report["execution"]["rescan"]["error"]


def test_model_context_uses_scan_exclusions(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("import math\n")
    (tmp_path / "private").mkdir()
    (tmp_path / "private/caller.py").write_text("math()\nprivate_marker = 'excluded'\n")
    (tmp_path / "pyproject.toml").write_text('[tool.skylos]\nexclude = ["private"]\n')
    code, report = run([str(tmp_path), "--context"], lambda *_a, **_kw: raw(tmp_path))
    assert code == 0
    assert "private/caller.py" not in json.dumps(report["context"])


def test_history_failure_after_apply_preserves_execution_receipt(tmp_path, monkeypatch):
    import skylos.cleanup_state as state

    (tmp_path / "app.py").write_text("import math\nvalue = 3\n")

    def scanner(*_a, **_kw):
        return raw(tmp_path, present="import math" in (tmp_path / "app.py").read_text())

    _, plan = run([str(tmp_path)], scanner)
    real = state.update_cleanup_state

    def failed_history(*args, **kwargs):
        if kwargs.get("receipt"):
            raise ValueError("disk unavailable")
        return real(*args, **kwargs)

    monkeypatch.setattr(state, "update_cleanup_state", failed_history)
    code, report = run(
        [str(tmp_path), "--task", plan["tasks"][0]["id"], "--apply"], scanner
    )
    assert code == 2
    assert report["execution"]["status"] == "applied_unverified"
    assert report["tasks"]
    assert "receipt retained" in report["limitations"][0]


@pytest.mark.parametrize(
    "args",
    [
        ["--apply"],
        ["--test-cmd", "pytest"],
        ["--defer", "id"],
        ["--review", "--task", "id"],
        ["--from-report", "r.json", "--task", "id"],
    ],
)
def test_execution_requires_explicit_valid_live_action(args):
    with pytest.raises(SystemExit) as error:
        run_cleanup_command(args)
    assert error.value.code == 2


def _review_queue(root):
    (root / "app.py").write_text("import math\ndeferred_marker = 'separate work'\n")
    (root / "open.py").write_text("import json\nopen_marker = 'current work'\n")
    report = raw(root)
    report["unused_imports"].append(
        {
            "name": "json",
            "file": str(root / "open.py"),
            "line": 1,
            "confidence": 100,
        }
    )

    def scanner(*_args, **_kwargs):
        return deepcopy(report)

    _, plan = run([str(root)], scanner)
    tasks = {task["file"]: task["id"] for task in plan["tasks"]}
    code, _ = run(
        [str(root), "--defer", tasks["app.py"], "--reason", "Separate review"], scanner
    )
    assert code == 0
    return scanner, tasks


@pytest.mark.parametrize("flag", ["--context", "--review"])
def test_context_and_model_review_exclude_deferred_tasks(tmp_path, monkeypatch, flag):
    import skylos.cleanup_context as context_module
    import skylos.commands.cleanup_cmd as command

    scanner, tasks = _review_queue(tmp_path)
    selected = []
    prompts = []
    original_context = context_module.build_cleanup_context

    def context_for_open_tasks(items, *args, **kwargs):
        selected.extend(task["id"] for task in items)
        return original_context(items, *args, **kwargs)

    class Model:
        def complete(self, _system, prompt, **_kwargs):
            prompts.append(json.loads(prompt))
            return '{"advice": []}'

    monkeypatch.setattr(context_module, "build_cleanup_context", context_for_open_tasks)
    monkeypatch.setattr(command, "_review_adapter", lambda _args: Model())
    code, report = run([str(tmp_path), flag], scanner)

    assert code == 0
    assert selected == [tasks["open.py"]]
    assert {row["file"] for row in report["context"]["files"]} == {"open.py"}
    assert "deferred_marker" not in json.dumps(report["context"])
    if flag == "--review":
        assert len(prompts) == 1
        assert [task["id"] for task in prompts[0]["tasks"]] == [tasks["open.py"]]
        assert "deferred_marker" not in json.dumps(prompts[0])
    else:
        assert prompts == []


def test_all_deferred_review_skips_context_and_model_initialization(
    tmp_path, monkeypatch
):
    import skylos.cleanup_context as context_module
    import skylos.commands.cleanup_cmd as command

    scanner, tasks = _review_queue(tmp_path)
    code, _ = run(
        [str(tmp_path), "--defer", tasks["open.py"], "--reason", "Later"], scanner
    )
    assert code == 0
    calls = []

    def forbidden(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("deferred work must not initialize context or a model")

    monkeypatch.setattr(context_module, "build_cleanup_context", forbidden)
    monkeypatch.setattr(command, "_review_adapter", forbidden)
    code, report = run([str(tmp_path), "--review"], scanner)

    assert code == 0
    assert calls == []
    assert report["tasks"] == []
    assert report["context_review"]["status"] == "skipped"
    assert report["context_review"]["advice"] == []


def test_explicit_task_preview_still_accepts_deferred_task(tmp_path):
    scanner, tasks = _review_queue(tmp_path)
    original = (tmp_path / "app.py").read_bytes()
    code, report = run([str(tmp_path), "--task", tasks["app.py"]], scanner)
    assert code == 0
    assert report["edit"]["task_id"] == tasks["app.py"]
    assert "-import math" in report["edit"]["patch"]
    assert (tmp_path / "app.py").read_bytes() == original
