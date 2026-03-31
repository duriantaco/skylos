from unittest.mock import Mock

import pytest

import skylos.login as loginmod


def test_parse_callback_request_rejects_state_mismatch():
    outcome, payload = loginmod._parse_callback_request(
        "/callback?token=abc&project_id=proj_1&state=wrong",
        expected_state="expected",
    )

    assert outcome == "invalid_state"
    assert payload is None


def test_parse_callback_request_escapes_error():
    outcome, payload = loginmod._parse_callback_request(
        "/callback?error=%3Cscript%3Ealert(1)%3C%2Fscript%3E&state=ok",
        expected_state="ok",
    )

    assert outcome == "error"
    assert payload == "&lt;script&gt;alert(1)&lt;/script&gt;"


def test_verify_login_result_rehydrates_metadata(monkeypatch):
    fake_response = Mock(status_code=200)
    fake_response.json.return_value = {
        "project": {"id": "proj_123", "name": "Real Project"},
        "organization": {"name": "Real Org"},
        "plan": "pro",
    }

    def fake_get(url, headers=None, timeout=None):
        assert url == "https://skylos.dev/api/sync/whoami"
        assert headers == {"Authorization": "Bearer TOK"}
        assert timeout == 30
        return fake_response

    monkeypatch.setattr(loginmod.requests, "get", fake_get)

    result = loginmod._verify_login_result("TOK", base_url="https://skylos.dev")

    assert result is not None
    assert result.token == "TOK"
    assert result.project_id == "proj_123"
    assert result.project_name == "Real Project"
    assert result.org_name == "Real Org"
    assert result.plan == "pro"


def test_verify_login_result_rejects_missing_project_id(monkeypatch):
    fake_response = Mock(status_code=200)
    fake_response.json.return_value = {
        "project": {"name": "No Id"},
        "organization": {"name": "Org"},
        "plan": "free",
    }

    monkeypatch.setattr(loginmod.requests, "get", lambda *args, **kwargs: fake_response)

    assert loginmod._verify_login_result("TOK", base_url="https://skylos.dev") is None
