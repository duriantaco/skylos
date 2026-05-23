import json
import os
import sys
from unittest.mock import Mock, patch

import pytest

import skylos.cli as cli
from skylos.debt.advisor import (
    DebtAdvisor,
    _parse_json_object,
    _safe_excerpt,
    _user_prompt,
    augment_hotspots_with_advisories,
)
from skylos.debt.baseline import (
    _read_text_no_follow,
    _write_text_no_follow,
    append_history,
    compare_to_baseline,
    load_baseline,
    load_history,
    save_baseline,
)
from skylos.debt.engine import (
    build_debt_snapshot,
    collect_debt_signals,
    run_debt_analysis,
)
from skylos.debt.policy import _parse_policy, load_policy
from skylos.debt.report import (
    format_debt_history_json,
    format_debt_history_table,
    format_debt_table,
)
from skylos.debt.result import (
    DebtAdvisory,
    DebtHotspot,
    DebtScore,
    DebtSignal,
    DebtSnapshot,
)
from skylos.debt.scoring import build_hotspots


def _hardlink_or_skip(source, target):
    try:
        os.link(source, target)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")


SAMPLE_RESULT = {
    "analysis_summary": {"total_files": 3, "total_loc": 500},
    "quality": [
        {
            "rule_id": "SKY-Q301",
            "severity": "HIGH",
            "file": "/repo/app/services.py",
            "line": 20,
            "name": "process_order",
            "message": "Cyclomatic complexity is 18 (threshold: 10)",
            "value": 18,
            "threshold": 10,
        },
        {
            "rule_id": "SKY-Q804",
            "severity": "HIGH",
            "file": "/repo/app/core.py",
            "line": 1,
            "name": "app.core",
            "message": "Dependency inversion violation",
        },
    ],
    "unused_functions": [
        {
            "name": "legacy_worker",
            "file": "/repo/app/legacy.py",
            "line": 8,
            "confidence": 92,
        }
    ],
    "unused_imports": [],
    "unused_variables": [],
    "unused_classes": [],
    "unused_parameters": [],
}


def _snapshot(project: str) -> DebtSnapshot:
    signal = DebtSignal(
        fingerprint="complexity:SKY-Q301:app/services.py:20:process_order",
        dimension="complexity",
        rule_id="SKY-Q301",
        severity="HIGH",
        file="app/services.py",
        line=20,
        subject="process_order",
        message="Cyclomatic complexity is 18 (threshold: 10)",
        points=14.0,
    )
    hotspot = DebtHotspot(
        fingerprint="hotspot:app/services.py",
        file="app/services.py",
        score=14.0,
        signal_count=1,
        dimension_count=1,
        primary_dimension="complexity",
        signals=[signal],
    )
    score = DebtScore(
        total_points=14.0,
        normalizer=2.0,
        score_pct=93,
        risk_rating="LOW",
        hotspot_count=1,
        signal_count=1,
    )
    return DebtSnapshot(
        version="1.0",
        timestamp="2026-03-28T00:00:00+00:00",
        project=project,
        files_scanned=3,
        total_loc=500,
        score=score,
        hotspots=[hotspot],
        summary={},
    )


def test_collect_debt_signals_maps_dimensions_and_dead_code():
    result = {
        **SAMPLE_RESULT,
        "unused_parameters": [
            {
                "name": "unused_context",
                "file": "/repo/app/services.py",
                "line": 21,
                "confidence": 80,
            }
        ],
    }
    signals = collect_debt_signals(
        result,
        project_root=cli.Path("/repo"),
    )

    dimensions = {(signal.rule_id, signal.dimension) for signal in signals}
    assert ("SKY-Q301", "complexity") in dimensions
    assert ("SKY-Q804", "architecture") in dimensions
    assert ("SKY-U001", "dead_code") in dimensions
    assert ("SKY-U006", "dead_code") in dimensions


def test_collect_debt_signals_skips_paths_outside_project_root(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("def outside():\n    return True\n", encoding="utf-8")
    result = {
        "analysis_summary": {"total_files": 1, "total_loc": 2},
        "quality": [
            {
                "rule_id": "SKY-Q301",
                "severity": "HIGH",
                "file": str(outside),
                "line": 1,
                "name": "outside",
                "message": "Outside-root finding",
            }
        ],
        "unused_functions": [],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
    }

    assert collect_debt_signals(result, project_root=root) == []

    link = root / "leak.py"
    try:
        link.symlink_to(outside)
    except OSError:
        return

    result["quality"][0]["file"] = str(link)
    assert collect_debt_signals(result, project_root=root) == []


def test_god_file_signal_becomes_modularity_debt_hotspot():
    result = {
        "analysis_summary": {"total_files": 1, "total_loc": 700},
        "quality": [
            {
                "rule_id": "SKY-Q502",
                "severity": "HIGH",
                "file": "/repo/app/api.py",
                "line": 1,
                "name": "app.api",
                "message": "File 'api.py' is a god file candidate",
                "value": 700,
                "threshold": 500,
            }
        ],
        "unused_functions": [],
        "unused_imports": [],
        "unused_variables": [],
        "unused_classes": [],
        "unused_parameters": [],
    }

    snapshot = build_debt_snapshot(result, project_root="/repo")

    assert snapshot.summary["dimensions"]["modularity"] == 1
    assert len(snapshot.hotspots) == 1
    hotspot = snapshot.hotspots[0]
    assert hotspot.file == "app/api.py"
    assert hotspot.primary_dimension == "modularity"
    assert hotspot.signals[0].rule_id == "SKY-Q502"
    assert hotspot.signals[0].dimension == "modularity"


def test_collect_debt_signals_filters_to_changed_files():
    signals = collect_debt_signals(
        SAMPLE_RESULT,
        project_root=cli.Path("/repo"),
        changed_files=["/repo/app/services.py"],
    )

    assert len(signals) == 1
    assert signals[0].file == "app/services.py"
    assert signals[0].dimension == "complexity"


def test_collect_debt_signals_ignores_invalid_changed_files(tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text("def outside():\n    return True\n", encoding="utf-8")

    signals = collect_debt_signals(
        SAMPLE_RESULT,
        project_root=cli.Path("/repo"),
        changed_files=[outside],
    )

    assert signals == []


def test_run_debt_analysis_builds_snapshot():
    with patch(
        "skylos.debt.engine.run_analyze", return_value=json.dumps(SAMPLE_RESULT)
    ):
        snapshot = run_debt_analysis("/repo")

    assert snapshot.files_scanned == 3
    assert snapshot.total_loc == 500
    assert snapshot.score.hotspot_count == len(snapshot.hotspots)
    assert snapshot.summary["dimensions"]["complexity"] == 1
    assert snapshot.summary["score_breakdown"]["dimensions"][0]["dimension"] == (
        "complexity"
    )
    assert snapshot.summary["score_breakdown"]["top_rules"][0]["rule_id"] == "SKY-Q301"
    assert snapshot.summary["score_model"]["included_sources"] == [
        "quality",
        "dead_code",
    ]


def test_run_debt_analysis_changed_mode_keeps_project_score_and_filters_hotspots():
    with patch(
        "skylos.debt.engine.run_analyze", return_value=json.dumps(SAMPLE_RESULT)
    ):
        full_snapshot = run_debt_analysis("/repo")
        changed_snapshot = run_debt_analysis(
            "/repo",
            changed_files=["/repo/app/services.py"],
        )

    assert full_snapshot.score.score_pct == changed_snapshot.score.score_pct
    assert full_snapshot.score.total_points == changed_snapshot.score.total_points
    assert changed_snapshot.score.hotspot_count == 3
    assert len(changed_snapshot.hotspots) == 1
    assert changed_snapshot.hotspots[0].file == "app/services.py"
    assert changed_snapshot.summary["scope"]["score"] == "project"
    assert changed_snapshot.summary["scope"]["hotspots"] == "changed"


def test_build_debt_snapshot_reuses_static_result():
    snapshot = build_debt_snapshot(SAMPLE_RESULT, project_root="/repo")

    assert snapshot.files_scanned == 3
    assert snapshot.total_loc == 500
    assert snapshot.score.hotspot_count == len(snapshot.hotspots)
    assert snapshot.summary["dimensions"]["complexity"] == 1
    assert snapshot.summary["score_breakdown"]["signal_points"] == 41.15
    assert snapshot.summary["score_model"]["signal_formula"] == (
        "severity_weight * dimension_weight * magnitude"
    )


def test_build_hotspots_changed_files_raise_priority_not_structural_score():
    signals = collect_debt_signals(
        SAMPLE_RESULT,
        project_root=cli.Path("/repo"),
    )

    unchanged_hotspots = build_hotspots(signals)
    changed_hotspots = build_hotspots(
        signals,
        changed_files={"app/services.py"},
    )

    by_file = {hotspot.file: hotspot for hotspot in unchanged_hotspots}
    changed_by_file = {hotspot.file: hotspot for hotspot in changed_hotspots}

    assert changed_by_file["app/services.py"].score == by_file["app/services.py"].score
    assert (
        changed_by_file["app/services.py"].priority_score
        > by_file["app/services.py"].priority_score
    )


def test_compare_to_baseline_marks_worsened_unchanged_and_resolved():
    snapshot = _snapshot("/repo")
    baseline = {
        "hotspots": [
            {"fingerprint": "hotspot:app/services.py", "score": 10.0},
            {"fingerprint": "hotspot:app/old.py", "score": 8.0},
        ]
    }

    counts = compare_to_baseline(snapshot, baseline)

    assert snapshot.hotspots[0].baseline_status == "worsened"
    assert counts["worsened"] == 1
    assert counts["resolved"] == 1


def test_compare_to_baseline_changed_scope_does_not_count_unseen_resolved():
    snapshot = _snapshot("/repo")
    snapshot.summary["scope"] = {"score": "project", "hotspots": "changed"}
    baseline = {
        "hotspots": [
            {"fingerprint": "hotspot:app/services.py", "score": 10.0},
            {"fingerprint": "hotspot:app/old.py", "score": 8.0},
        ]
    }

    counts = compare_to_baseline(snapshot, baseline)

    assert snapshot.hotspots[0].baseline_status == "worsened"
    assert counts["worsened"] == 1
    assert counts["resolved"] == 0


def test_save_baseline_normalizes_changed_scope_to_project(tmp_path):
    snapshot = _snapshot(str(tmp_path))
    snapshot.all_hotspots = list(snapshot.hotspots)
    snapshot.summary["scope"] = {"score": "project", "hotspots": "changed"}
    snapshot.summary["project_hotspot_count"] = 1
    snapshot.summary["visible_hotspot_count"] = 1
    snapshot.summary["baseline"] = {"resolved": 0}

    path = save_baseline(tmp_path, snapshot)
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["summary"]["scope"]["hotspots"] == "project"
    assert "baseline" not in payload["summary"]


def test_safe_file_write_rejects_hardlink_without_truncating(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("do-not-clobber\n", encoding="utf-8")
    hardlink = tmp_path / "hardlink.txt"
    _hardlink_or_skip(outside, hardlink)

    with pytest.raises(ValueError, match="hard-linked"):
        _write_text_no_follow(hardlink, "replacement\n", label="test")

    assert outside.read_text(encoding="utf-8") == "do-not-clobber\n"


def test_safe_file_append_rejects_hardlink_without_appending(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("do-not-append\n", encoding="utf-8")
    hardlink = tmp_path / "hardlink.txt"
    _hardlink_or_skip(outside, hardlink)

    with pytest.raises(ValueError, match="hard-linked"):
        _write_text_no_follow(hardlink, "extra\n", label="test", append=True)

    assert outside.read_text(encoding="utf-8") == "do-not-append\n"


def test_safe_file_write_rejects_symlink_without_clobbering(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("do-not-clobber\n", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(ValueError, match="symlink"):
        _write_text_no_follow(link, "replacement\n", label="test")

    assert outside.read_text(encoding="utf-8") == "do-not-clobber\n"


def test_safe_file_append_rejects_symlink_without_appending(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("do-not-append\n", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(ValueError, match="symlink"):
        _write_text_no_follow(link, "extra\n", label="test", append=True)

    assert outside.read_text(encoding="utf-8") == "do-not-append\n"


def test_safe_file_read_rejects_invalid_utf8(tmp_path):
    path = tmp_path / "bad.txt"
    path.write_bytes(b"\xff\xfe")

    with pytest.raises(ValueError, match="valid UTF-8"):
        _read_text_no_follow(path, label="test", max_bytes=10)


def test_safe_file_read_rejects_oversized_file(tmp_path):
    path = tmp_path / "large.txt"
    path.write_text("12345", encoding="utf-8")

    with pytest.raises(ValueError, match="too large"):
        _read_text_no_follow(path, label="test", max_bytes=4)


def test_load_baseline_rejects_oversized_baseline_file(tmp_path, monkeypatch):
    baseline_dir = tmp_path / ".skylos"
    baseline_dir.mkdir()
    (baseline_dir / "debt_baseline.json").write_text(
        json.dumps({"hotspots": []}) + "\n",
        encoding="utf-8",
    )
    from skylos.debt import baseline

    monkeypatch.setattr(baseline, "BASELINE_MAX_BYTES", 4)

    with pytest.raises(ValueError, match="too large"):
        load_baseline(tmp_path)


def test_load_baseline_rejects_invalid_utf8(tmp_path):
    baseline_dir = tmp_path / ".skylos"
    baseline_dir.mkdir()
    (baseline_dir / "debt_baseline.json").write_bytes(b"\xff\xfe")

    with pytest.raises(ValueError, match="valid UTF-8"):
        load_baseline(tmp_path)


def test_load_baseline_rejects_symlinked_baseline_file(tmp_path):
    baseline_dir = tmp_path / ".skylos"
    baseline_dir.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text(
        json.dumps({"token": "secret-outside-value"}) + "\n",
        encoding="utf-8",
    )
    baseline_path = baseline_dir / "debt_baseline.json"
    try:
        baseline_path.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(ValueError, match="symlink"):
        load_baseline(tmp_path)


def test_load_baseline_rejects_hardlinked_baseline_file(tmp_path):
    baseline_dir = tmp_path / ".skylos"
    baseline_dir.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text(
        json.dumps({"token": "secret-outside-value"}) + "\n",
        encoding="utf-8",
    )
    _hardlink_or_skip(outside, baseline_dir / "debt_baseline.json")

    with pytest.raises(ValueError, match="hard-linked"):
        load_baseline(tmp_path)


def test_save_baseline_rejects_symlinked_baseline_file(tmp_path):
    snapshot = _snapshot(str(tmp_path))
    baseline_dir = tmp_path / ".skylos"
    baseline_dir.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("do-not-clobber\n", encoding="utf-8")
    baseline_path = baseline_dir / "debt_baseline.json"
    try:
        baseline_path.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(ValueError, match="symlink"):
        save_baseline(tmp_path, snapshot)

    assert outside.read_text(encoding="utf-8") == "do-not-clobber\n"


def test_save_baseline_rejects_hardlinked_baseline_file(tmp_path):
    snapshot = _snapshot(str(tmp_path))
    baseline_dir = tmp_path / ".skylos"
    baseline_dir.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("do-not-clobber\n", encoding="utf-8")
    _hardlink_or_skip(outside, baseline_dir / "debt_baseline.json")

    with pytest.raises(ValueError, match="hard-linked"):
        save_baseline(tmp_path, snapshot)

    assert outside.read_text(encoding="utf-8") == "do-not-clobber\n"


def test_save_baseline_rejects_parent_symlink(tmp_path):
    snapshot = _snapshot(str(tmp_path))
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    link = tmp_path / ".skylos"
    try:
        link.symlink_to(outside_dir, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(ValueError, match="parent directory must not be a symlink"):
        save_baseline(tmp_path, snapshot)

    assert not (outside_dir / "debt_baseline.json").exists()


def test_load_baseline_rejects_baseline_resolved_outside_project(tmp_path):
    project = tmp_path / "repo"
    project.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    (outside_dir / "debt_baseline.json").write_text(
        json.dumps({"token": "secret-outside-value"}) + "\n",
        encoding="utf-8",
    )
    try:
        (project / ".skylos").symlink_to(outside_dir, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(ValueError, match="parent directory must not be a symlink"):
        load_baseline(project)


def test_compare_to_baseline_ignores_malformed_hotspot_entries():
    snapshot = _snapshot("/repo")
    baseline = {
        "hotspots": [
            "not-a-dict",
            {"fingerprint": "hotspot:app/services.py", "score": "bad-score"},
            {"fingerprint": "hotspot:app/old.py", "score": 8.0},
        ]
    }

    counts = compare_to_baseline(snapshot, baseline)

    assert snapshot.hotspots[0].baseline_status == "new"
    assert counts["new"] == 1
    assert counts["resolved"] == 1


def test_load_history_reads_saved_jsonl_entries(tmp_path):
    snapshot = _snapshot(str(tmp_path))

    append_history(tmp_path, snapshot)
    entries = load_history(tmp_path)

    assert len(entries) == 1
    assert entries[0]["timestamp"] == "2026-03-28T00:00:00+00:00"
    assert entries[0]["score"]["score_pct"] == 93
    assert entries[0]["hotspots"][0]["file"] == "app/services.py"
    assert entries[0]["hotspots"][0]["score"] == 14.0


def test_load_history_returns_empty_for_missing_history(tmp_path):
    assert load_history(tmp_path) == []


def test_load_history_rejects_symlinked_history_file(tmp_path):
    history_dir = tmp_path / ".skylos"
    history_dir.mkdir()
    outside = tmp_path / "outside.jsonl"
    outside.write_text(
        json.dumps({"token": "secret-outside-value"}) + "\n",
        encoding="utf-8",
    )
    history_path = history_dir / "debt_history.jsonl"
    try:
        history_path.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(ValueError, match="symlink"):
        load_history(tmp_path)


def test_append_history_rejects_symlinked_history_file(tmp_path):
    snapshot = _snapshot(str(tmp_path))
    history_dir = tmp_path / ".skylos"
    history_dir.mkdir()
    outside = tmp_path / "outside.jsonl"
    outside.write_text("do-not-append\n", encoding="utf-8")
    history_path = history_dir / "debt_history.jsonl"
    try:
        history_path.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(ValueError, match="symlink"):
        append_history(tmp_path, snapshot)

    assert outside.read_text(encoding="utf-8") == "do-not-append\n"


def test_append_history_rejects_hardlinked_history_file(tmp_path):
    snapshot = _snapshot(str(tmp_path))
    history_dir = tmp_path / ".skylos"
    history_dir.mkdir()
    outside = tmp_path / "outside.jsonl"
    outside.write_text("do-not-append\n", encoding="utf-8")
    _hardlink_or_skip(outside, history_dir / "debt_history.jsonl")

    with pytest.raises(ValueError, match="hard-linked"):
        append_history(tmp_path, snapshot)

    assert outside.read_text(encoding="utf-8") == "do-not-append\n"


def test_append_history_rejects_parent_symlink(tmp_path):
    snapshot = _snapshot(str(tmp_path))
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    link = tmp_path / ".skylos"
    try:
        link.symlink_to(outside_dir, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(ValueError, match="parent directory must not be a symlink"):
        append_history(tmp_path, snapshot)

    assert not (outside_dir / "debt_history.jsonl").exists()


def test_load_history_rejects_history_resolved_outside_project(tmp_path):
    project = tmp_path / "repo"
    project.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    (outside_dir / "debt_history.jsonl").write_text(
        json.dumps({"token": "secret-outside-value"}) + "\n",
        encoding="utf-8",
    )
    history_dir = project / ".skylos"
    try:
        history_dir.symlink_to(outside_dir, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(ValueError, match="parent directory must not be a symlink"):
        load_history(project)


def test_load_history_rejects_oversized_history_file(tmp_path, monkeypatch):
    history_dir = tmp_path / ".skylos"
    history_dir.mkdir()
    (history_dir / "debt_history.jsonl").write_text(
        json.dumps({"score": {"score_pct": 93}}) + "\n",
        encoding="utf-8",
    )
    from skylos.debt import baseline

    monkeypatch.setattr(baseline, "HISTORY_MAX_BYTES", 4)

    with pytest.raises(ValueError, match="too large"):
        load_history(tmp_path)


def test_parse_policy_accepts_gate_and_report():
    policy = _parse_policy(
        {
            "gate": {"min_score": 80, "fail_on_status": "new_or_worsened"},
            "report": {"top": 15},
        }
    )

    assert policy.gate_min_score == 80
    assert policy.gate_fail_on_status == "new_or_worsened"
    assert policy.report_top == 15


def test_parse_policy_rejects_invalid_status():
    with pytest.raises(ValueError):
        _parse_policy({"gate": {"fail_on_status": "boom"}})


def test_load_policy_discovers_from_start_path(tmp_path):
    project = tmp_path / "repo"
    src = project / "src"
    src.mkdir(parents=True)
    (project / "skylos-debt.yaml").write_text(
        "report:\n  top: 3\n",
        encoding="utf-8",
    )

    policy = load_policy(start_path=src)

    assert policy is not None
    assert policy.report_top == 3


def test_load_policy_rejects_symlinked_policy_file(tmp_path):
    outside = tmp_path / "outside.yaml"
    outside.write_text("report:\n  top: 3\n", encoding="utf-8")
    policy_path = tmp_path / "skylos-debt.yaml"
    try:
        policy_path.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(ValueError, match="symlink"):
        load_policy(policy_path)


def test_load_policy_rejects_hardlinked_policy_file(tmp_path):
    outside = tmp_path / "outside.yaml"
    outside.write_text("report:\n  top: 3\n", encoding="utf-8")
    policy_path = tmp_path / "skylos-debt.yaml"
    _hardlink_or_skip(outside, policy_path)

    with pytest.raises(ValueError, match="hard-linked"):
        load_policy(policy_path)


def test_load_policy_rejects_oversized_policy_file(tmp_path, monkeypatch):
    policy_path = tmp_path / "skylos-debt.yaml"
    policy_path.write_text("report:\n  top: 3\n", encoding="utf-8")
    from skylos.debt import policy as debt_policy

    monkeypatch.setattr(debt_policy, "POLICY_MAX_BYTES", 4)

    with pytest.raises(ValueError, match="too large"):
        load_policy(policy_path)


def test_load_policy_rejects_invalid_utf8(tmp_path):
    policy_path = tmp_path / "skylos-debt.yaml"
    policy_path.write_bytes(b"\xff\xfe")

    with pytest.raises(ValueError, match="valid UTF-8"):
        load_policy(policy_path)


def test_augment_hotspots_with_advisories_sets_advisory(tmp_path):
    services = tmp_path / "app" / "services.py"
    services.parent.mkdir(parents=True)
    services.write_text(
        "def process_order(order):\n"
        "    if order:\n"
        "        return order\n"
        "    return None\n",
        encoding="utf-8",
    )
    snapshot = _snapshot(str(tmp_path))

    with patch("skylos.debt.advisor.LiteLLMAdapter") as mock_adapter_cls:
        mock_adapter_cls.return_value.complete.return_value = json.dumps(
            {
                "summary": "The hotspot concentrates branching logic in one service function.",
                "root_cause": "Control flow and responsibility are mixed in the same routine.",
                "refactor_steps": [
                    "Extract validation into a helper.",
                    "Split decision branches into named functions.",
                ],
                "remediation_notes": ["Keep behavior covered with regression tests."],
                "confidence": "medium",
            }
        )

        advised = augment_hotspots_with_advisories(
            snapshot.hotspots,
            project_root=tmp_path,
            model="gpt-4.1",
            api_key="test-key",
        )

    assert advised == 1
    assert snapshot.hotspots[0].advisory is not None
    assert (
        snapshot.hotspots[0].advisory.summary
        == "The hotspot concentrates branching logic in one service function."
    )
    assert snapshot.hotspots[0].advisory.refactor_steps[0].startswith("Extract")


def test_safe_excerpt_returns_context_and_missing_file_is_empty(tmp_path):
    services = tmp_path / "app.py"
    services.write_text(
        "line 1\nline 2\nline 3\nline 4\nline 5\n",
        encoding="utf-8",
    )

    excerpt = _safe_excerpt(services, 3, radius=1)

    assert excerpt == "2: line 2\n3: line 3\n4: line 4"
    assert _safe_excerpt(tmp_path / "missing.py", 3) == ""


def test_parse_json_object_handles_plain_fenced_and_invalid_payloads():
    assert _parse_json_object('{"summary":"ok"}') == {"summary": "ok"}
    assert _parse_json_object('```json\n{"summary":"ok"}\n```') == {"summary": "ok"}
    assert _parse_json_object("not json") is None
    assert _parse_json_object("") is None


def test_user_prompt_includes_signals_architecture_and_excerpt(tmp_path):
    services = tmp_path / "app" / "services.py"
    services.parent.mkdir(parents=True)
    services.write_text(
        "\n".join(f"line {idx}" for idx in range(1, 31)) + "\n",
        encoding="utf-8",
    )
    snapshot = _snapshot(str(tmp_path))

    prompt = _user_prompt(
        snapshot.hotspots[0],
        project_root=tmp_path,
        architecture_metrics={
            "system_metrics": {
                "mean_distance": 1.2,
                "architecture_fitness": 0.8,
                "dip_violations": 3,
            }
        },
    )

    assert "Hotspot:" in prompt
    assert "- [SKY-Q301] Cyclomatic complexity is 18 (threshold: 10)" in prompt
    assert "Architecture context:" in prompt
    assert "- mean_distance=1.2" in prompt
    assert "[app/services.py:20]" in prompt


def test_debt_advisor_skips_outside_root_signal_excerpts(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("OUTSIDE_DEBT_CANARY = True\n", encoding="utf-8")
    signal = DebtSignal(
        fingerprint="complexity:SKY-Q301:outside.py:1:outside",
        dimension="complexity",
        rule_id="SKY-Q301",
        severity="HIGH",
        file=str(outside),
        line=1,
        subject="outside",
        message="Outside-root debt signal",
        points=14.0,
    )
    hotspot = DebtHotspot(
        fingerprint="hotspot:outside.py",
        file=str(outside),
        score=14.0,
        signal_count=1,
        dimension_count=1,
        primary_dimension="complexity",
        signals=[signal],
    )
    advisor = _stub_debt_advisor(
        json.dumps(
            {
                "summary": "Summary.",
                "root_cause": "Root cause.",
                "refactor_steps": [],
                "remediation_notes": [],
                "confidence": "medium",
            }
        )
    )

    advisory = advisor.summarize_hotspot(hotspot, project_root=root)
    user_prompt = advisor.adapter.complete.call_args.args[1]

    assert advisory is not None
    assert "OUTSIDE_DEBT_CANARY" not in user_prompt
    assert "No code excerpts available." in user_prompt

    link = root / "leak.py"
    try:
        link.symlink_to(outside)
    except OSError:
        return

    signal.file = "leak.py"
    hotspot.file = "leak.py"
    advisor.summarize_hotspot(hotspot, project_root=root)
    user_prompt = advisor.adapter.complete.call_args.args[1]
    assert "OUTSIDE_DEBT_CANARY" not in user_prompt
    assert "No code excerpts available." in user_prompt


def _stub_debt_advisor(payload: str, *, model: str = "gpt-4.1") -> DebtAdvisor:
    advisor = DebtAdvisor.__new__(DebtAdvisor)
    advisor.model = model
    advisor.adapter = Mock(complete=Mock(return_value=payload))
    return advisor


def test_debt_advisor_summarize_hotspot_normalizes_payload(tmp_path):
    services = tmp_path / "app" / "services.py"
    services.parent.mkdir(parents=True)
    services.write_text(
        "def process_order(order):\n"
        "    if order:\n"
        "        return order\n"
        "    return None\n",
        encoding="utf-8",
    )
    snapshot = _snapshot(str(tmp_path))
    advisor = _stub_debt_advisor(
        json.dumps(
            {
                "summary": "The hotspot concentrates branching logic.",
                "root_cause": "Control flow and responsibility are mixed.",
                "refactor_steps": ["Extract validation.", "", "Split branches."],
                "remediation_notes": ["Keep regression coverage.", ""],
                "confidence": "BOGUS",
            }
        )
    )

    advisory = advisor.summarize_hotspot(snapshot.hotspots[0], project_root=tmp_path)

    assert advisory is not None
    assert advisory.confidence == "medium"
    assert advisory.refactor_steps == ["Extract validation.", "Split branches."]
    assert advisory.remediation_notes == ["Keep regression coverage."]


def test_debt_advisor_summarize_hotspot_returns_none_for_incomplete_payload(tmp_path):
    services = tmp_path / "app" / "services.py"
    services.parent.mkdir(parents=True)
    services.write_text(
        "def process_order(order):\n"
        "    if order:\n"
        "        return order\n"
        "    return None\n",
        encoding="utf-8",
    )
    snapshot = _snapshot(str(tmp_path))
    advisor = _stub_debt_advisor(
        json.dumps(
            {
                "summary": "",
                "root_cause": "Control flow and responsibility are mixed.",
                "refactor_steps": [],
                "remediation_notes": [],
                "confidence": "low",
            }
        )
    )

    advisory = advisor.summarize_hotspot(snapshot.hotspots[0], project_root=tmp_path)

    assert advisory is None


def test_format_debt_table_renders_changed_scope_empty_state_and_baseline():
    snapshot = _snapshot("/repo")
    snapshot.hotspots = []
    snapshot.summary["scope"] = {"score": "project", "hotspots": "changed"}
    snapshot.summary["project_hotspot_count"] = 3
    snapshot.summary["baseline"] = {
        "new": 1,
        "worsened": 2,
        "improved": 0,
        "unchanged": 4,
        "resolved": 1,
    }

    rendered = format_debt_table(snapshot)

    assert "Skylos Technical Debt Report" in rendered
    assert "Hotspots: 0 shown (3 project total)" in rendered
    assert "View: changed files only" in rendered
    assert (
        "Baseline: 1 new | 2 worsened | 0 improved | 4 unchanged | 1 resolved"
        in rendered
    )
    assert "No debt hotspots found in changed files." in rendered


def test_format_debt_table_renders_hotspot_advisory_and_delta():
    snapshot = _snapshot("/repo")
    hotspot = snapshot.hotspots[0]
    hotspot.priority_score = 16.5
    hotspot.baseline_status = "worsened"
    hotspot.score_delta = 1.25
    hotspot.advisory = DebtAdvisory(
        summary="Split summary and detail formatting into helpers.",
        root_cause="One function owns several output branches.",
        refactor_steps=[
            "Extract summary line builders.",
            "Move hotspot rendering into a helper.",
            "Keep advisory formatting isolated.",
        ],
    )

    rendered = format_debt_table(snapshot)

    assert (
        "1. app/services.py | score=14.00 | priority=16.50 | "
        "signals=1 | dimensions=complexity | worsened (+1.25)"
    ) in rendered
    assert (
        "why: primary=complexity, strongest=HIGH, breadth_bonus=0.00, "
        "priority_bonus=2.50"
    ) in rendered
    assert (
        "SKY-Q301 | HIGH | complexity | app/services.py:20 | "
        "Cyclomatic complexity is 18 (threshold: 10) (points=14.00)"
    ) in rendered
    assert "advisor: Split summary and detail formatting into helpers." in rendered
    assert "step: Extract summary line builders." in rendered
    assert "step: Move hotspot rendering into a helper." in rendered
    assert "step: Keep advisory formatting isolated." not in rendered


def test_format_debt_table_orders_by_priority_and_applies_top_limit():
    snapshot = _snapshot("/repo")
    hotspot = snapshot.hotspots[0]
    hotspot.priority_score = 10.0

    second_signal = DebtSignal(
        fingerprint="maintainability:SKY-L027:app/core.py:8:app.core",
        dimension="maintainability",
        rule_id="SKY-L027",
        severity="MEDIUM",
        file="app/core.py",
        line=8,
        subject="app.core",
        message="String literal repeated 5 times (threshold: 3)",
        points=9.0,
    )
    second_hotspot = DebtHotspot(
        fingerprint="hotspot:app/core.py",
        file="app/core.py",
        score=9.0,
        signal_count=1,
        dimension_count=1,
        primary_dimension="maintainability",
        priority_score=18.0,
        signals=[second_signal],
    )
    snapshot.hotspots.append(second_hotspot)

    rendered = format_debt_table(snapshot, top=1)

    assert "1. app/core.py | score=9.00 | priority=18.00" in rendered
    assert "app/services.py" not in rendered


def test_format_debt_table_explains_score_breakdown_and_model():
    snapshot = build_debt_snapshot(SAMPLE_RESULT, project_root="/repo")

    rendered = format_debt_table(snapshot)

    assert "Score Breakdown:" in rendered
    assert "complexity: 21.60 pts" in rendered
    assert "Top rules: SKY-Q301 21.60 pts" in rendered
    assert "How Score Is Calculated:" in rendered
    assert "severity weight * dimension weight * magnitude" in rendered
    assert "included sources: quality, dead_code" in rendered
    assert (
        "SKY-Q301 | HIGH | complexity | app/services.py:20 | "
        "Cyclomatic complexity is 18 (threshold: 10) "
        "(metric=18 threshold=10 points=21.60)"
    ) in rendered


def test_format_debt_history_table_renders_deltas_and_limit():
    entries = [
        {
            "timestamp": "2026-03-28T00:00:00+00:00",
            "score": {
                "score_pct": 93,
                "risk_rating": "LOW",
                "hotspot_count": 1,
                "signal_count": 1,
            },
        },
        {
            "timestamp": "2026-03-29T00:00:00+00:00",
            "score": {
                "score_pct": 90,
                "risk_rating": "MODERATE",
                "hotspot_count": 2,
                "signal_count": 4,
            },
            "hotspots": [
                {
                    "file": "app/core.py",
                    "score": 18.0,
                    "signal_count": 3,
                    "primary_dimension": "complexity",
                }
            ],
        },
    ]

    rendered = format_debt_history_table(entries)
    limited = format_debt_history_table(entries, limit=1)

    assert "Skylos Debt History" in rendered
    assert "Entries: 2 shown (2 total)" in rendered
    assert "2026-03-29T00:00:00+00:00" in rendered
    assert "-3" in rendered
    assert "Entries: 1 shown (2 total)" in limited
    assert "-3" in limited
    assert "Latest Top Hotspots:" in limited
    assert "app/core.py | score=18.00 | signals=3 | complexity" in limited
    assert "2026-03-28T00:00:00+00:00" not in limited


def test_format_debt_history_table_handles_old_entries_without_hotspots():
    entries = [{"timestamp": "2026-03-28T00:00:00+00:00", "score": {}}]

    rendered = format_debt_history_table(entries)

    assert "Latest Top Hotspots:" in rendered
    assert "Not recorded in saved history." in rendered


def test_format_debt_history_json_wraps_entries():
    entries = [{"timestamp": "2026-03-28T00:00:00+00:00", "score": {}}]

    payload = json.loads(format_debt_history_json(entries))

    assert payload == {"history": entries}


def test_cli_debt_json_outputs_snapshot_and_exits_zero(tmp_path, monkeypatch):
    snapshot = _snapshot(str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["skylos", "debt", str(tmp_path), "--json"])

    with (
        patch("skylos.debt.run_debt_analysis", return_value=snapshot),
        patch("builtins.print") as mock_print,
        patch("skylos.cli.Console", return_value=Mock()),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    payload = json.loads(mock_print.call_args.args[0])
    assert payload["score"]["score_pct"] == 93
    assert payload["hotspots"][0]["file"] == "app/services.py"


def test_cli_debt_json_upload_uses_quiet_mode(tmp_path, monkeypatch):
    snapshot = _snapshot(str(tmp_path))
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "debt", str(tmp_path), "--json", "--upload"],
    )

    with (
        patch("skylos.debt.run_debt_analysis", return_value=snapshot),
        patch(
            "skylos.api.upload_debt_report", return_value={"success": True}
        ) as mock_upload,
        patch("builtins.print") as mock_print,
        patch("skylos.cli.Console", return_value=Mock()),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    mock_upload.assert_called_once_with(snapshot, quiet=True)
    payload = json.loads(mock_print.call_args.args[0])
    assert payload["score"]["score_pct"] == 93


def test_cli_debt_with_agent_includes_advisory_in_json(tmp_path, monkeypatch):
    snapshot = _snapshot(str(tmp_path))
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "debt", str(tmp_path), "--json", "--with-agent"],
    )

    def _augment(hotspots, **kwargs):
        hotspots[0].advisory = DebtAdvisory(
            summary="Start by isolating the branching service logic.",
            root_cause="The function owns too many decision paths.",
            refactor_steps=["Extract branch handlers."],
            remediation_notes=["Add regression tests first."],
            confidence="medium",
            model="gpt-4.1",
        )
        return 1

    with (
        patch("skylos.debt.run_debt_analysis", return_value=snapshot),
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "test-key", None, False),
        ),
        patch(
            "skylos.debt.augment_hotspots_with_advisories",
            side_effect=_augment,
        ),
        patch("builtins.print") as mock_print,
        patch("skylos.cli.Console", return_value=Mock()),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    payload = json.loads(mock_print.call_args.args[0])
    assert payload["summary"]["agent"]["advised_hotspots"] == 1
    assert (
        payload["hotspots"][0]["advisory"]["summary"]
        == "Start by isolating the branching service logic."
    )


def test_cli_debt_fail_on_status_uses_baseline_comparison(tmp_path, monkeypatch):
    snapshot = _snapshot(str(tmp_path))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "skylos",
            "debt",
            str(tmp_path),
            "--baseline",
            "--fail-on-status",
            "new",
        ],
    )

    def _mark_new(current_snapshot, baseline):
        current_snapshot.hotspots[0].baseline_status = "new"
        current_snapshot.summary["baseline"] = {"new": 1}
        return {"new": 1}

    with (
        patch("skylos.debt.run_debt_analysis", return_value=snapshot),
        patch("skylos.debt.load_baseline", return_value={"hotspots": []}),
        patch("skylos.debt.compare_to_baseline", side_effect=_mark_new),
        patch("skylos.cli.Console", return_value=Mock()),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 1


def test_cli_debt_baseline_reports_invalid_baseline_json(tmp_path, monkeypatch):
    snapshot = _snapshot(str(tmp_path))
    baseline_dir = tmp_path / ".skylos"
    baseline_dir.mkdir()
    (baseline_dir / "debt_baseline.json").write_text(
        "{not-json",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "debt", str(tmp_path), "--baseline"],
    )
    mock_console = Mock()

    with (
        patch("skylos.debt.run_debt_analysis", return_value=snapshot),
        patch("skylos.cli.Console", return_value=mock_console),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 1
    message = mock_console.print.call_args.args[0]
    assert "Error reading debt baseline" in message
    assert "invalid JSON" in message


def test_cli_debt_baseline_symlink_error_does_not_leak_file_content(
    tmp_path,
    monkeypatch,
):
    snapshot = _snapshot(str(tmp_path))
    baseline_dir = tmp_path / ".skylos"
    baseline_dir.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text(
        json.dumps({"token": "secret-outside-value"}) + "\n",
        encoding="utf-8",
    )
    try:
        (baseline_dir / "debt_baseline.json").symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "debt", str(tmp_path), "--baseline"],
    )
    mock_console = Mock()

    with (
        patch("skylos.debt.run_debt_analysis", return_value=snapshot),
        patch("skylos.cli.Console", return_value=mock_console),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 1
    message = mock_console.print.call_args.args[0]
    assert "Error reading debt baseline" in message
    assert "symlink" in message
    assert "secret-outside-value" not in message


def test_cli_debt_json_min_score_includes_gate_failure(tmp_path, monkeypatch):
    snapshot = _snapshot(str(tmp_path))
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "debt", str(tmp_path), "--json", "--min-score", "95"],
    )

    with (
        patch("skylos.debt.run_debt_analysis", return_value=snapshot),
        patch("builtins.print") as mock_print,
        patch("skylos.cli.Console", return_value=Mock()),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 1
    payload = json.loads(mock_print.call_args.args[0])
    assert payload["summary"]["gate"]["passed"] is False
    assert payload["summary"]["gate"]["failures"] == [
        "score 93% is below min_score 95%"
    ]


def test_cli_debt_uses_project_policy_for_report_top(tmp_path, monkeypatch):
    snapshot = _snapshot(str(tmp_path))
    (tmp_path / "skylos-debt.yaml").write_text(
        "report:\n  top: 1\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["skylos", "debt", str(tmp_path)])

    with (
        patch("skylos.debt.run_debt_analysis", return_value=snapshot),
        patch("skylos.debt.format_debt_table", return_value="ok") as mock_table,
        patch("skylos.cli.Console", return_value=Mock()),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    assert mock_table.call_args.kwargs["top"] == 1


def test_cli_debt_top_flag_overrides_policy_report_top(tmp_path, monkeypatch):
    snapshot = _snapshot(str(tmp_path))
    (tmp_path / "skylos-debt.yaml").write_text(
        "report:\n  top: 1\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["skylos", "debt", str(tmp_path), "--top", "2"])

    with (
        patch("skylos.debt.run_debt_analysis", return_value=snapshot),
        patch("skylos.debt.format_debt_table", return_value="ok") as mock_table,
        patch("skylos.cli.Console", return_value=Mock()),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    assert mock_table.call_args.kwargs["top"] == 2


def test_cli_debt_save_baseline_requires_project_root_scan(tmp_path, monkeypatch):
    project = tmp_path / "repo"
    target = project / "src"
    target.mkdir(parents=True)
    snapshot = _snapshot(str(project))
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "debt", str(target), "--save-baseline"],
    )
    mock_console = Mock()

    with (
        patch("skylos.debt.run_debt_analysis", return_value=snapshot),
        patch("skylos.debt.save_baseline") as mock_save,
        patch("skylos.cli.Console", return_value=mock_console),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 1
    mock_save.assert_not_called()
    message = mock_console.print.call_args.args[0]
    assert "--save-baseline only supports project-root scans" in message


def test_cli_debt_history_requires_project_root_scan(tmp_path, monkeypatch):
    project = tmp_path / "repo"
    target = project / "src"
    target.mkdir(parents=True)
    snapshot = _snapshot(str(project))
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "debt", str(target), "--history"],
    )
    mock_console = Mock()

    with (
        patch("skylos.debt.run_debt_analysis", return_value=snapshot),
        patch("skylos.debt.append_history") as mock_history,
        patch("skylos.cli.Console", return_value=mock_console),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 1
    mock_history.assert_not_called()
    message = mock_console.print.call_args.args[0]
    assert "--history only supports project-root scans" in message


def test_cli_debt_show_history_reads_history_without_scanning(tmp_path, monkeypatch):
    history_dir = tmp_path / ".skylos"
    history_dir.mkdir()
    (history_dir / "debt_history.jsonl").write_text(
        json.dumps(
            {
                "timestamp": "2026-03-28T00:00:00+00:00",
                "score": {
                    "score_pct": 93,
                    "risk_rating": "LOW",
                    "hotspot_count": 1,
                    "signal_count": 1,
                },
            }
        )
        + "\n"
        + json.dumps(
            {
                "timestamp": "2026-03-29T00:00:00+00:00",
                "score": {
                    "score_pct": 90,
                    "risk_rating": "MODERATE",
                    "hotspot_count": 2,
                    "signal_count": 4,
                },
                "hotspots": [
                    {
                        "file": "app/core.py",
                        "score": 18.0,
                        "signal_count": 3,
                        "primary_dimension": "complexity",
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "debt", str(tmp_path), "--show-history", "--history-limit", "1"],
    )
    mock_console = Mock()

    with (
        patch("skylos.debt.run_debt_analysis") as mock_scan,
        patch("skylos.cli.Console", return_value=mock_console),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    mock_scan.assert_not_called()
    output = mock_console.print.call_args.args[0]
    assert "Skylos Debt History" in output
    assert "Entries: 1 shown (2 total)" in output
    assert "2026-03-29T00:00:00+00:00" in output
    assert "app/core.py | score=18.00 | signals=3 | complexity" in output
    assert "2026-03-28T00:00:00+00:00" not in output


def test_cli_debt_show_history_json_outputs_saved_entries(tmp_path, monkeypatch):
    history_dir = tmp_path / ".skylos"
    history_dir.mkdir()
    (history_dir / "debt_history.jsonl").write_text(
        json.dumps(
            {
                "timestamp": "2026-03-28T00:00:00+00:00",
                "score": {"score_pct": 93},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "debt", str(tmp_path), "--show-history", "--json"],
    )

    with (
        patch("skylos.debt.run_debt_analysis") as mock_scan,
        patch("builtins.print") as mock_print,
        patch("skylos.cli.Console", return_value=Mock()),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 0
    mock_scan.assert_not_called()
    payload = json.loads(mock_print.call_args.args[0])
    assert payload["history"][0]["score"]["score_pct"] == 93


def test_cli_debt_show_history_json_rejects_symlink_history(
    tmp_path, monkeypatch
):
    history_dir = tmp_path / ".skylos"
    history_dir.mkdir()
    outside = tmp_path / "outside.jsonl"
    outside.write_text(
        json.dumps({"token": "secret-outside-value"}) + "\n",
        encoding="utf-8",
    )
    history_path = history_dir / "debt_history.jsonl"
    try:
        history_path.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", "debt", str(tmp_path), "--show-history", "--json"],
    )
    mock_console = Mock()

    with (
        patch("skylos.debt.run_debt_analysis") as mock_scan,
        patch("builtins.print") as mock_print,
        patch("skylos.cli.Console", return_value=mock_console),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()

    assert exc.value.code == 1
    mock_scan.assert_not_called()
    mock_print.assert_not_called()
    message = mock_console.print.call_args.args[0]
    assert "Error reading debt history" in message
    assert "symlink" in message
    assert "secret-outside-value" not in message
