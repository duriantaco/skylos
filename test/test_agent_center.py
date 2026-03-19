from skylos.agent_center import (
    clear_action_triage,
    build_headline,
    build_ranked_actions,
    detect_changed_files,
    load_agent_state,
    rebuild_agent_state_from_existing,
    save_agent_state,
    update_action_triage,
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
