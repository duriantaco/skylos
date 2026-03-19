from skylos.agent_center import rebuild_agent_state_from_existing, save_agent_state
from skylos.agent_service import AgentServiceController


def test_agent_service_controller_serves_command_center_and_triage_updates(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()

    state = rebuild_agent_state_from_existing(
        {
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
    )
    save_agent_state(project_root, state)

    controller = AgentServiceController(str(project_root))

    health = controller.health()
    assert health["ok"] is True
    assert health["has_state"] is True

    payload = controller.get_command_center()
    assert payload["items"][0]["id"] == "security:1"
    assert payload["triaged_count"] == 0

    dismissed = controller.dismiss("security:1")
    assert dismissed["triage"]["security:1"]["status"] == "dismissed"
    assert dismissed["actions"] == []

    restored = controller.restore("security:1")
    assert restored["triage"] == {}
    assert restored["actions"][0]["id"] == "security:1"


def test_agent_service_controller_tracks_snoozed_actions(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()

    state = rebuild_agent_state_from_existing(
        {
            "project_root": str(project_root),
            "file_signatures": {"src/helpers.py": {"mtime_ns": 1, "size": 10}},
            "changed_files": [],
            "baseline_present": False,
            "findings": [
                {
                    "fingerprint": "dead:1",
                    "rule_id": "SKY-U002",
                    "category": "dead_code",
                    "severity": "INFO",
                    "message": "Unused import: os",
                    "file": "src/helpers.py",
                    "absolute_file": str(project_root / "src" / "helpers.py"),
                    "line": 2,
                    "confidence": 40,
                    "is_new_vs_baseline": False,
                    "is_new_since_last_scan": False,
                    "is_in_changed_file": False,
                },
            ],
        }
    )
    save_agent_state(project_root, state)

    controller = AgentServiceController(str(project_root))
    snoozed = controller.snooze("dead:1", hours=4)

    assert snoozed["triage"]["dead:1"]["status"] == "snoozed"
    assert snoozed["actions"] == []

    payload = controller.get_command_center()
    assert payload["triaged_count"] == 1
    assert payload["items"] == []
