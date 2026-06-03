from __future__ import annotations

import json

import pytest

from skylos.verify_change import (
    build_verify_change_response,
    parse_line_range,
    verify_change_stdin_payload,
    verify_change_path,
)


def test_build_verify_change_response_filters_to_ai_findings(tmp_path):
    app = tmp_path / "app.py"
    app.write_text("def handler(token):\n    return validate_token(token)\n")
    result = {
        "quality": [
            {
                "rule_id": "SKY-L012",
                "vibe_category": "hallucinated_reference",
                "ai_likelihood": "high",
                "severity": "CRITICAL",
                "file": str(app),
                "line": 2,
                "col": 11,
                "message": "Call to validate_token() is never defined.",
            },
            {
                "rule_id": "SKY-Q302",
                "severity": "LOW",
                "file": str(app),
                "line": 1,
                "message": "Generic quality finding",
            },
        ],
    }

    payload = build_verify_change_response(result, project_root=tmp_path)

    assert payload["schema_version"] == 1
    assert payload["tool"] == "verify_change"
    assert payload["status"] == "fail"
    assert payload["summary"] == "1 AI-code issue found"
    assert len(payload["findings"]) == 1
    finding = payload["findings"][0]
    assert finding["rule_id"] == "SKY-L012"
    assert finding["vibe_category"] == "hallucinated_reference"
    assert finding["ai_likelihood"] == "high"
    assert finding["confidence"] == 90
    assert finding["range"]["file"] == "app.py"
    assert finding["range"]["start_line"] == 2
    assert finding["suggested_fix"]


def test_build_verify_change_response_applies_rule_defaults(tmp_path):
    app = tmp_path / "app.py"
    app.write_text("requests.get(url, verify=False)\n")
    result = {
        "quality": [
            {
                "rule_id": "SKY-L011",
                "severity": "HIGH",
                "file": str(app),
                "line": 1,
                "message": "TLS verification disabled.",
            }
        ]
    }

    payload = build_verify_change_response(result, project_root=tmp_path)

    finding = payload["findings"][0]
    assert finding["vibe_category"] == "disabled_security_control"
    assert finding["ai_likelihood"] == "medium"
    assert finding["confidence"] == 70


def test_build_verify_change_response_filters_target_file_and_range(tmp_path):
    app = tmp_path / "app.py"
    other = tmp_path / "other.py"
    app.write_text("def a():\n    return validate_token(token)\n")
    other.write_text("def b():\n    return require_admin(user)\n")
    result = {
        "quality": [
            {
                "rule_id": "SKY-L012",
                "vibe_category": "hallucinated_reference",
                "ai_likelihood": "high",
                "file": str(app),
                "line": 2,
                "message": "app phantom",
            },
            {
                "rule_id": "SKY-L012",
                "vibe_category": "hallucinated_reference",
                "ai_likelihood": "high",
                "file": str(other),
                "line": 2,
                "message": "other phantom",
            },
        ]
    }

    payload = build_verify_change_response(
        result,
        project_root=tmp_path,
        target_file="app.py",
        line_range="2:2",
    )

    assert [f["message"] for f in payload["findings"]] == ["app phantom"]
    assert payload["target"]["file"] == "app.py"
    assert payload["target"]["range"] == {"start_line": 2, "end_line": 2}


def test_parse_line_range_validation():
    assert parse_line_range("4:9") == (4, 9)
    assert parse_line_range("4-9") == (4, 9)
    assert parse_line_range("4") == (4, 4)
    with pytest.raises(ValueError):
        parse_line_range("9:4")


def test_verify_change_path_runs_existing_vibe_rules(tmp_path):
    app = tmp_path / "app.py"
    app.write_text("def handler(token):\n    return validate_token(token)\n")

    payload = verify_change_path(app, line_range="2:2")

    assert payload["status"] == "fail"
    assert any(f["rule_id"] == "SKY-L012" for f in payload["findings"])
    assert all(f["range"]["start_line"] == 2 for f in payload["findings"])


def test_verify_change_path_accepts_injected_analyzer_result(tmp_path):
    app = tmp_path / "app.py"
    app.write_text("def handler():\n    pass\n")

    def fake_analyze(*_args, **_kwargs):
        return json.dumps(
            {
                "quality": [
                    {
                        "rule_id": "SKY-L026",
                        "vibe_category": "incomplete_generation",
                        "ai_likelihood": "medium",
                        "file": str(app),
                        "line": 2,
                        "message": "Generated stub left behind.",
                    }
                ]
            }
        )

    payload = verify_change_path(app, analyze_func=fake_analyze)

    assert payload["status"] == "fail"
    assert payload["findings"][0]["vibe_category"] == "incomplete_generation"


def test_verify_change_stdin_payload_uses_manifest_file_for_schema():
    payload = verify_change_stdin_payload(
        {
            "path": "/repo",
            "file": "src/app.py",
            "range": "2:2",
            "code": "def handler(token):\n    return validate_token(token)\n",
        }
    )

    assert payload["status"] == "fail"
    assert payload["target"]["path"] == "/repo"
    assert payload["target"]["file"] == "src/app.py"
    assert payload["target"]["range"] == {"start_line": 2, "end_line": 2}
    assert any(f["range"]["file"] == "src/app.py" for f in payload["findings"])


def test_verify_change_stdin_payload_rejects_absolute_manifest_file():
    with pytest.raises(ValueError):
        verify_change_stdin_payload({"file": "/tmp/app.py", "code": "pass\n"})
