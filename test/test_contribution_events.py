from __future__ import annotations

from skylos.core.contribution_events import (
    build_structural_event,
    load_local_events,
    record_structural_event,
)
from skylos.core.contribution_settings import ContributionSettings


def _enabled_settings() -> ContributionSettings:
    return ContributionSettings(
        collect_local_signals=True,
        contribute_public_corpus=False,
        structural_signatures_only=True,
        include_source=False,
    )


def _finding() -> dict:
    return {
        "fingerprint": "vibe:1",
        "rule_id": "SKY-L012",
        "category": "quality",
        "severity": "MEDIUM",
        "vibe_category": "hallucinated_reference",
        "ai_likelihood": "high",
        "message": "validate_token is never defined",
        "file": "src/auth.py",
        "absolute_file": "/private/project/src/auth.py",
        "line": 27,
        "code": "validate_token(request)",
        "source": "validate_token(request)",
    }


def test_record_structural_event_is_off_by_default(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()

    recorded = record_structural_event(
        project_root,
        _finding(),
        event_type="dismiss",
    )
    payload = load_local_events(project_root)

    assert recorded is False
    assert payload == {"schema_version": 1, "events": []}


def test_record_structural_event_stores_privacy_clean_signature(tmp_path):
    project_root = tmp_path / "repo"
    project_root.mkdir()

    recorded = record_structural_event(
        project_root,
        _finding(),
        event_type="dismiss",
        settings=_enabled_settings(),
    )
    payload = load_local_events(project_root)

    assert recorded is True
    assert len(payload["events"]) == 1

    event = payload["events"][0]
    assert event["schema_version"] == 1
    assert event["event_type"] == "dismiss"
    assert event["rule_id"] == "SKY-L012"
    assert event["vibe_category"] == "hallucinated_reference"
    assert event["ai_likelihood"] == "high"
    assert event["file_ext"] == ".py"
    assert event["line_bucket"] == "21-30"
    assert event["message_hash"]
    assert event["structural_hash"]
    assert "message" not in event
    assert "file" not in event
    assert "absolute_file" not in event
    assert "code" not in event
    assert "source" not in event


def test_build_structural_event_supports_rule_alias_without_source():
    finding = {
        "rule": "SKY-D222",
        "message": "package does not exist",
        "file": "package.json",
        "line": 1,
    }

    event = build_structural_event(finding, event_type="accept")

    assert event["event_type"] == "accept"
    assert event["rule_id"] == "SKY-D222"
    assert event["file_ext"] == ".json"
    assert event["line_bucket"] == "1-10"
