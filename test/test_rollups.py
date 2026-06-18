from pathlib import Path

from skylos.reporting.rollups import build_directory_rollups


def test_build_directory_rollups_groups_findings_by_relative_parent(tmp_path):
    src = tmp_path / "src" / "api" / "views.py"
    worker = tmp_path / "src" / "jobs" / "worker.py"
    source_file = tmp_path / "main.py"
    result = {
        "quality": [
            {
                "rule_id": "SKY-C304",
                "severity": "MEDIUM",
                "file": str(src),
                "line": 10,
            },
            {
                "rule_id": "SKY-Q301",
                "severity": "HIGH",
                "file": str(src),
                "line": 20,
            },
        ],
        "unused_functions": [
            {"name": "old_handler", "file": str(src), "line": 30},
            {"name": "stale_job", "file": str(worker), "line": 5},
            {"name": "unused_main", "file": str(source_file), "line": 1},
        ],
        "danger": [
            {
                "rule_id": "SKY-D211",
                "severity": "CRITICAL",
                "file": str(worker),
                "line": 12,
            }
        ],
    }

    rollups = build_directory_rollups(result, tmp_path)

    assert rollups[0]["path"] == "src/api"
    assert rollups[0]["total"] == 3
    assert rollups[0]["files"] == 1
    assert rollups[0]["quality"] == 2
    assert rollups[0]["dead_code"] == 1
    assert rollups[0]["rules"] == {
        "SKY-C304": 1,
        "SKY-Q301": 1,
        "unused-functions": 1,
    }
    assert rollups[1]["path"] == "src/jobs"
    assert rollups[1]["security"] == 1
    assert rollups[1]["dead_code"] == 1
    assert rollups[2]["path"] == "."
    assert rollups[2]["dead_code"] == 1
