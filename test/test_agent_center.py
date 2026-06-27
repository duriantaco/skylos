import shutil
import subprocess
import json
from unittest.mock import patch

import pytest

from skylos.agents.center import (
    _save_grep_cache,
    clear_action_triage,
    build_headline,
    build_ranked_actions,
    detect_changed_files,
    load_agent_state,
    normalize_findings,
    refresh_agent_state,
    rebuild_agent_state_from_existing,
    relative_path,
    save_agent_state,
    snapshot_file_signatures,
    parse_utc_timestamp,
    update_action_triage,
    watch_project,
)


def test_detect_changed_files_includes_new_changed_and_removed_files():
    previous = {
        "src/a.py": {"mtime_ns": 1, "size": 10},
        "src/b.py": {"mtime_ns": 2, "size": 20},
    }
    current = {
        "src/a.py": {"mtime_ns": 1, "size": 10},
        "src/c.py": {"mtime_ns": 3, "size": 30},
        "src/b.py": {"mtime_ns": 9, "size": 20},
    }

    changed = detect_changed_files(previous, current)

    assert changed == ["src/b.py", "src/c.py"]


def test_snapshot_file_signatures_skips_gitignored_files(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git is required for this test")

    project = tmp_path / "repo"
    project.mkdir()
    ignored_dir = project / "customenv"
    kept_dir = project / "src"
    ignored_dir.mkdir(parents=True)
    kept_dir.mkdir(parents=True)
    (project / ".gitignore").write_text("customenv/\n", encoding="utf-8")
    (ignored_dir / "ghost.py").write_text("x = 1\n", encoding="utf-8")
    (kept_dir / "keep.py").write_text("x = 1\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=project, check=True)

    signatures = snapshot_file_signatures(project)

    assert "src/keep.py" in signatures
    assert "customenv/ghost.py" not in signatures


def test_build_ranked_actions_prioritizes_new_critical_changed_security():
    findings = [
        {
            "fingerprint": "security:1",
            "rule_id": "SKY-D999",
            "category": "security",
            "severity": "CRITICAL",
            "message": "SQL injection path",
            "file": "src/auth.py",
            "absolute_file": "/tmp/src/auth.py",
            "line": 14,
            "confidence": 95,
            "is_new_vs_baseline": True,
            "is_new_since_last_scan": True,
            "is_in_changed_file": True,
        },
        {
            "fingerprint": "dead:1",
            "rule_id": "SKY-U002",
            "category": "dead_code",
            "severity": "INFO",
            "message": "Unused import: os",
            "file": "src/helpers.py",
            "absolute_file": "/tmp/src/helpers.py",
            "line": 2,
            "confidence": 40,
            "is_new_vs_baseline": False,
            "is_new_since_last_scan": False,
            "is_in_changed_file": False,
        },
    ]

    actions = build_ranked_actions(findings, changed_files=["src/auth.py"])

    assert actions[0]["file"] == "src/auth.py"
    assert actions[0]["severity"] == "CRITICAL"
    assert actions[0]["action_type"] == "inspect_now"
    assert actions[0]["score"] > actions[1]["score"]


def test_build_ranked_actions_prioritizes_debt_hotspots_over_plain_quality():
    findings = [
        {
            "fingerprint": "quality:1",
            "rule_id": "SKY-Q302",
            "category": "quality",
            "severity": "MEDIUM",
            "message": "Deep nesting",
            "file": "src/auth.py",
            "absolute_file": "/tmp/src/auth.py",
            "line": 14,
        },
        {
            "fingerprint": "hotspot:src/payments.py",
            "rule_id": "SKY-DEBT",
            "category": "debt",
            "severity": "MEDIUM",
            "message": "Technical debt hotspot: architecture (4 signal(s), score 28.00).",
            "file": "src/payments.py",
            "absolute_file": "/tmp/src/payments.py",
            "line": 21,
            "hotspot_score": 28.0,
            "signal_count": 4,
            "primary_dimension": "architecture",
            "baseline_status": "worsened",
        },
    ]

    actions = build_ranked_actions(findings, changed_files=[])

    assert actions[0]["category"] == "debt"
    assert actions[0]["action_type"] == "plan_refactor"
    assert actions[0]["score"] > actions[1]["score"]


def test_build_ranked_actions_preserves_debt_priority_order():
    findings = [
        {
            "fingerprint": "hotspot:src/a.py",
            "rule_id": "SKY-DEBT",
            "category": "debt",
            "severity": "MEDIUM",
            "message": "Debt hotspot A",
            "file": "src/a.py",
            "absolute_file": "/tmp/src/a.py",
            "line": 10,
            "hotspot_score": 35.0,
            "priority_score": 41.0,
        },
        {
            "fingerprint": "hotspot:src/b.py",
            "rule_id": "SKY-DEBT",
            "category": "debt",
            "severity": "MEDIUM",
            "message": "Debt hotspot B",
            "file": "src/b.py",
            "absolute_file": "/tmp/src/b.py",
            "line": 10,
            "hotspot_score": 35.0,
            "priority_score": 80.0,
        },
    ]

    actions = build_ranked_actions(findings, changed_files=[])

    assert actions[0]["file"] == "src/b.py"
    assert actions[0]["priority_score"] > actions[1]["priority_score"]


def test_build_ranked_actions_keeps_critical_security_ahead_of_debt_hotspot():
    findings = [
        {
            "fingerprint": "hotspot:src/debt.py",
            "rule_id": "SKY-DEBT",
            "category": "debt",
            "severity": "HIGH",
            "message": "Debt hotspot",
            "file": "src/debt.py",
            "absolute_file": "/tmp/src/debt.py",
            "line": 20,
            "priority_score": 44.0,
            "hotspot_score": 38.0,
        },
        {
            "fingerprint": "security:1",
            "rule_id": "SKY-D999",
            "category": "security",
            "severity": "CRITICAL",
            "message": "Critical injection path",
            "file": "src/auth.py",
            "absolute_file": "/tmp/src/auth.py",
            "line": 10,
        },
    ]

    actions = build_ranked_actions(findings, changed_files=[])

    assert actions[0]["category"] == "security"


def test_build_ranked_actions_debt_ignores_new_since_last_scan_bonus():
    findings = [
        {
            "fingerprint": "hotspot:src/debt.py",
            "rule_id": "SKY-DEBT",
            "category": "debt",
            "severity": "HIGH",
            "message": "Debt hotspot",
            "file": "src/debt.py",
            "absolute_file": "/tmp/src/debt.py",
            "line": 20,
            "priority_score": 44.0,
            "hotspot_score": 38.0,
            "is_new_since_last_scan": True,
        },
        {
            "fingerprint": "security:1",
            "rule_id": "SKY-D999",
            "category": "security",
            "severity": "CRITICAL",
            "message": "Critical injection path",
            "file": "src/auth.py",
            "absolute_file": "/tmp/src/auth.py",
            "line": 10,
        },
    ]

    actions = build_ranked_actions(findings, changed_files=[])

    assert actions[0]["category"] == "security"


def test_build_headline_prefers_urgent_changed_code():
    headline = build_headline(
        critical=1,
        high=1,
        new_total=2,
        changed_total=2,
        baseline_present=True,
        total=10,
    )

    assert headline == "2 urgent finding(s) need attention in changed code"


def test_normalize_findings_includes_debt_hotspots(tmp_path):
    project_root = tmp_path / "repo"
    src = project_root / "src"
    src.mkdir(parents=True)
    target = src / "auth.py"
    target.write_text("def login():\n    return True\n", encoding="utf-8")

    result = {
        "quality": [
            {
                "rule_id": "SKY-Q301",
                "severity": "WARN",
                "message": "High cyclomatic complexity",
                "file": str(target),
                "line": 1,
            }
        ]
    }

    findings = normalize_findings(result, project_root)

    debt = [finding for finding in findings if finding["category"] == "debt"]
    assert len(debt) == 1
    assert debt[0]["rule_id"] == "SKY-DEBT"
    assert debt[0]["primary_dimension"] == "complexity"
    assert debt[0]["baseline_status"] == "untracked"


def test_normalize_findings_includes_ai_defects(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()
    target = project_root / "app.py"
    target.write_text("def handler():\n    return validate_token()\n", encoding="utf-8")

    result = {
        "ai_defects": [
            {
                "rule_id": "SKY-L012",
                "severity": "CRITICAL",
                "message": "Call to 'validate_token()' but this function is never defined.",
                "file": str(target),
                "line": 2,
            }
        ]
    }

    findings = normalize_findings(result, project_root)

    assert len(findings) == 1
    assert findings[0]["category"] == "ai_defects"
    assert findings[0]["rule_id"] == "SKY-L012"


def test_normalize_findings_applies_debt_baseline(tmp_path):
    project_root = tmp_path / "repo"
    src = project_root / "src"
    state_dir = project_root / ".skylos"
    src.mkdir(parents=True)
    state_dir.mkdir(parents=True)
    target = src / "auth.py"
    target.write_text("def login():\n    return True\n", encoding="utf-8")
    (state_dir / "debt_baseline.json").write_text(
        json.dumps(
            {
                "hotspots": [
                    {
                        "fingerprint": "hotspot:src/auth.py",
                        "score": 2.0,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = {
        "quality": [
            {
                "rule_id": "SKY-Q301",
                "severity": "WARN",
                "message": "High cyclomatic complexity",
                "file": str(target),
                "line": 1,
                "value": 14,
                "threshold": 10,
            }
        ]
    }

    findings = normalize_findings(result, project_root)

    debt = [finding for finding in findings if finding["category"] == "debt"]
    assert len(debt) == 1
    assert debt[0]["baseline_status"] == "worsened"


def test_refresh_agent_state_with_only_debt_baseline_does_not_mark_quality_new(
    tmp_path,
):
    project_root = tmp_path / "repo"
    src = project_root / "src"
    state_dir = project_root / ".skylos"
    src.mkdir(parents=True)
    state_dir.mkdir(parents=True)
    target = src / "auth.py"
    target.write_text("def login():\n    return True\n", encoding="utf-8")
    (state_dir / "debt_baseline.json").write_text(
        json.dumps(
            {
                "hotspots": [
                    {
                        "fingerprint": "hotspot:src/auth.py",
                        "score": 2.0,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = {
        "quality": [
            {
                "rule_id": "SKY-Q301",
                "severity": "WARN",
                "message": "High cyclomatic complexity",
                "file": str(target),
                "line": 1,
                "value": 14,
                "threshold": 10,
            }
        ]
    }

    with patch(
        "skylos.agents.center.run_analyze", return_value=json.dumps(result)
    ) as run_analyze:
        state, updated = refresh_agent_state(project_root, force=True)

    assert run_analyze.call_args.kwargs["enable_ai_defects"] is True
    assert updated is True
    quality = [
        finding for finding in state["findings"] if finding["category"] == "quality"
    ]
    debt = [finding for finding in state["findings"] if finding["category"] == "debt"]
    assert quality[0]["is_new_vs_baseline"] is False
    assert debt[0]["is_new_vs_baseline"] is False
    assert state["summary"]["new_findings"] == 0


def test_refresh_agent_state_rebuilds_when_only_triage_normalization_changes(
    tmp_path,
):
    project_root = tmp_path / "repo"
    src = project_root / "src"
    src.mkdir(parents=True)
    target = src / "auth.py"
    target.write_text("def login():\n    return True\n", encoding="utf-8")

    signatures = snapshot_file_signatures(project_root)
    state = rebuild_agent_state_from_existing(
        {
            "project_root": str(project_root),
            "file_signatures": signatures,
            "changed_files": [],
            "baseline_present": False,
            "findings": [
                {
                    "fingerprint": "security:1",
                    "rule_id": "SKY-D999",
                    "category": "security",
                    "severity": "HIGH",
                    "message": "Shell injection path",
                    "file": "src/auth.py",
                    "absolute_file": str(target),
                    "line": 9,
                    "confidence": 91,
                    "is_new_vs_baseline": True,
                    "is_new_since_last_scan": True,
                    "is_in_changed_file": True,
                },
            ],
        }
    )
    state["triage"] = {
        "security:1": {
            "status": "snoozed",
            "updated_at": "2026-03-16T00:00:00+00:00",
            "snoozed_until": "2000-03-16T00:00:00+00:00",
        }
    }
    save_agent_state(project_root, state)

    with patch(
        "skylos.agents.center.run_analyze",
        side_effect=AssertionError("run_analyze should not be called"),
    ) as run_analyze_mock:
        rebuilt, updated = refresh_agent_state(project_root)

    assert updated is True
    assert rebuilt["triage"] == {}
    assert rebuilt["actions"][0]["id"] == "security:1"
    assert load_agent_state(project_root) == rebuilt
    run_analyze_mock.assert_not_called()


def test_agent_state_round_trip(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()
    state = {
        "summary": {"headline": "1 urgent finding"},
        "actions": [{"id": "a1", "title": "Review HIGH SKY-D201"}],
    }

    save_agent_state(project_root, state)
    loaded = load_agent_state(project_root)

    assert loaded == state


def test_load_agent_state_returns_none_for_invalid_json(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()
    state_dir = project_root / ".skylos"
    state_dir.mkdir()
    (state_dir / "agent_state.json").write_text("{not-json", encoding="utf-8")

    assert load_agent_state(project_root) is None


def test_save_grep_cache_does_not_swallow_unexpected_errors(tmp_path):
    class BrokenCache:
        def save(self, _project_root):
            raise RuntimeError("cache write failed")

    with pytest.raises(RuntimeError):
        _save_grep_cache(BrokenCache(), tmp_path)


def test_relative_path_falls_back_for_outside_path(tmp_path):
    project_root = tmp_path / "repo"
    outside = tmp_path / "outside.py"

    assert relative_path(str(outside), project_root).endswith("outside.py")


def test_parse_utc_timestamp_returns_none_for_invalid_value():
    assert parse_utc_timestamp("not-a-date") is None


def test_rebuild_agent_state_filters_dismissed_and_snoozed_actions():
    state = {
        "project_root": "/tmp/repo",
        "file_signatures": {"src/auth.py": {"mtime_ns": 1, "size": 10}},
        "changed_files": ["src/auth.py"],
        "baseline_present": True,
        "findings": [
            {
                "fingerprint": "security:1",
                "rule_id": "SKY-D999",
                "category": "security",
                "severity": "CRITICAL",
                "message": "SQL injection path",
                "file": "src/auth.py",
                "absolute_file": "/tmp/repo/src/auth.py",
                "line": 14,
                "confidence": 95,
                "is_new_vs_baseline": True,
                "is_new_since_last_scan": True,
                "is_in_changed_file": True,
            },
            {
                "fingerprint": "dead:1",
                "rule_id": "SKY-U002",
                "category": "dead_code",
                "severity": "INFO",
                "message": "Unused import: os",
                "file": "src/helpers.py",
                "absolute_file": "/tmp/repo/src/helpers.py",
                "line": 2,
                "confidence": 40,
                "is_new_vs_baseline": False,
                "is_new_since_last_scan": False,
                "is_in_changed_file": False,
            },
        ],
        "triage": {
            "security:1": {
                "status": "dismissed",
                "updated_at": "2026-03-16T00:00:00+00:00",
            },
            "dead:1": {
                "status": "snoozed",
                "updated_at": "2026-03-16T00:00:00+00:00",
                "snoozed_until": "2099-03-16T00:00:00+00:00",
            },
        },
    }

    rebuilt = rebuild_agent_state_from_existing(state)

    assert rebuilt["actions"] == []
    assert rebuilt["summary"]["dismissed"] == 1
    assert rebuilt["summary"]["snoozed"] == 1


def test_update_and_clear_action_triage_round_trip(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()
    state = {
        "project_root": str(project_root),
        "file_signatures": {"src/auth.py": {"mtime_ns": 1, "size": 10}},
        "changed_files": ["src/auth.py"],
        "baseline_present": False,
        "findings": [
            {
                "fingerprint": "security:1",
                "rule_id": "SKY-D999",
                "category": "security",
                "severity": "HIGH",
                "message": "Shell injection path",
                "file": "src/auth.py",
                "absolute_file": str(project_root / "src" / "auth.py"),
                "line": 9,
                "confidence": 91,
                "is_new_vs_baseline": True,
                "is_new_since_last_scan": True,
                "is_in_changed_file": True,
            },
        ],
    }
    save_agent_state(project_root, rebuild_agent_state_from_existing(state))

    dismissed = update_action_triage(project_root, "security:1", status="dismissed")
    assert dismissed["actions"] == []
    assert dismissed["triage"]["security:1"]["status"] == "dismissed"

    restored = clear_action_triage(project_root, "security:1")
    assert restored["actions"][0]["id"] == "security:1"
    assert restored["triage"] == {}


def test_watch_project_tracks_lifecycle_events_and_cache_saves(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()

    state1 = {"findings": [{"fingerprint": "a"}], "summary": {"headline": "one"}}
    state2 = {
        "findings": [{"fingerprint": "a"}, {"fingerprint": "b"}],
        "summary": {"headline": "two"},
    }
    state3 = {"findings": [{"fingerprint": "b"}], "summary": {"headline": "three"}}
    sequence = [(state1, True), (state2, True), (state3, True)]
    call_index = {"i": 0}

    def fake_refresh(*args, **kwargs):
        idx = call_index["i"]
        call_index["i"] += 1
        return sequence[idx]

    class FakeCache:
        def __init__(self):
            self.loaded: list[str] = []
            self.saved: list[str] = []

        def load(self, value: str) -> None:
            self.loaded.append(value)

        def save(self, value: str) -> None:
            self.saved.append(value)

    fake_cache = FakeCache()

    with (
        patch("skylos.agents.center.refresh_agent_state", side_effect=fake_refresh),
        patch(
            "skylos.core.grep_cache.GrepCache",
            return_value=fake_cache,
        ),
        patch("time.sleep", return_value=None),
    ):
        result = watch_project(project_root, cycles=3, interval=0)

    assert result == {
        "findings": [{"fingerprint": "b"}],
        "summary": {"headline": "three"},
        "_events": [
            {
                "type": "finding_resolved",
                "count": 1,
                "iteration": 2,
            }
        ],
    }
    assert fake_cache.loaded == [str(project_root.resolve())]
    assert fake_cache.saved == [str(project_root.resolve())] * 3
    assert call_index["i"] == 3
