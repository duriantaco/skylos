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


def test_browser_login_rejects_unverified_callback(monkeypatch):
    class FakeServer:
        timeout = 5

        def __init__(self, *args, **kwargs):
            pass

        def handle_request(self):
            loginmod._CallbackHandler.result = loginmod.LoginResult(
                token="TOK",
                project_id="callback_project",
                project_name="Callback Project",
                org_name="Callback Org",
                plan="pro",
            )

        def server_close(self):
            pass

    monkeypatch.setattr(loginmod, "_find_free_port", lambda: 8123)
    monkeypatch.setattr(loginmod, "_get_repo_name", lambda: "repo")
    monkeypatch.setattr(loginmod, "_get_repo_url", lambda: "")
    monkeypatch.setattr(loginmod, "_get_repo_subpath", lambda: "")
    monkeypatch.setattr(loginmod.webbrowser, "open", lambda _url: True)
    monkeypatch.setattr(loginmod.http.server, "HTTPServer", FakeServer)
    monkeypatch.setattr(loginmod, "_verify_login_result", lambda *args, **kwargs: None)

    assert loginmod.browser_login(base_url="https://skylos.dev") is None


def test_run_login_existing_cancel_keeps_current(monkeypatch):
    existing = loginmod.LoginResult(
        token="TOK",
        project_id="proj_123",
        project_name="Current Project",
        org_name="Org",
        plan="pro",
    )

    monkeypatch.setattr(
        loginmod, "get_current_connection", lambda base_url=None: existing
    )
    monkeypatch.setattr(
        loginmod, "browser_login", lambda console=None, base_url=None: None
    )

    manual = Mock(return_value=None)
    save = Mock()
    monkeypatch.setattr(loginmod, "manual_token_fallback", manual)
    monkeypatch.setattr(loginmod, "_save_login_result", save)

    result = loginmod.run_login()

    assert result is existing
    manual.assert_not_called()
    save.assert_not_called()
