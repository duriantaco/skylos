import json
from unittest.mock import Mock
from urllib.parse import urlparse

import pytest

import skylos.cloud.login as loginmod
import skylos.cloud.sync as syncmod


def test_parse_callback_request_rejects_state_mismatch():
    outcome, payload = loginmod._parse_callback_request(
        "/callback?token=abc&project_id=proj_1&state=wrong",
        expected_state="expected",
    )

    assert outcome == "invalid_state"
    assert payload is None


def test_parse_callback_request_rejects_missing_state_when_expected():
    outcome, payload = loginmod._parse_callback_request(
        "/callback?token=abc&project_id=proj_1",
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


def test_verify_login_result_rejects_unsafe_base_url(monkeypatch):
    def fail_get(*args, **kwargs):
        raise AssertionError("unsafe login URL should not be requested")

    monkeypatch.setattr(loginmod.requests, "get", fail_get)

    assert loginmod._verify_login_result("TOK", base_url="file:///tmp/socket") is None


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


def test_print_connected_result_plain_output_omits_raw_token(capsys):
    raw_token = "skylos_sensitive_login_token_1234567890"
    result = loginmod.LoginResult(
        token=raw_token,
        project_id="proj_123",
        project_name="Project",
        org_name="Org",
        plan="pro",
    )

    loginmod._print_connected_result(result)

    output = capsys.readouterr().out
    assert raw_token not in output
    assert "export SKYLOS_API_KEY=" not in output
    assert "Token saved locally" in output


def test_print_connected_result_console_output_omits_raw_token():
    raw_token = "skylos_sensitive_login_token_1234567890"
    result = loginmod.LoginResult(
        token=raw_token,
        project_id="proj_123",
        project_name="Project",
        org_name="Org",
        plan="pro",
    )

    class CaptureConsole:
        def __init__(self):
            self.messages = []

        def print(self, message="", *args, **kwargs):
            self.messages.append(str(message))

    console = CaptureConsole()
    loginmod._print_connected_result(result, console=console)

    output = "\n".join(console.messages)
    assert raw_token not in output
    assert "export SKYLOS_API_KEY=" not in output
    assert "Token saved locally" in output


@pytest.mark.parametrize("use_console", [False, True])
def test_manual_login_warns_ci_keys_retain_authority_locally(
    monkeypatch, capsys, use_console
):
    # An empty token keeps this UI check entirely offline.
    monkeypatch.setattr("builtins.input", lambda _prompt: "")
    console = Mock() if use_console else None

    assert loginmod.manual_token_fallback(console=console) is None

    output = (
        "\n".join(str(call.args[0]) for call in console.print.call_args_list)
        if use_console
        else capsys.readouterr().out
    )
    assert "can publish trusted uploads even from this machine" in output
    assert "any coding agent that can read it can use that authority" in output
    assert "Keep CI keys in your CI secret store" in output
    assert "saved as unverified and never publish checks" not in output


def _isolate_login_storage(monkeypatch, tmp_path):
    credentials = tmp_path / "credentials" / "credentials.json"
    monkeypatch.setattr(syncmod, "GLOBAL_CREDS_DIR", credentials.parent)
    monkeypatch.setattr(syncmod, "GLOBAL_CREDS_FILE", credentials)
    monkeypatch.setattr(syncmod, "_find_repo_root", lambda: tmp_path)
    return credentials


@pytest.mark.parametrize(
    ("environment_url", "explicit_url", "expected_url"),
    [
        (" https://staging.example.invalid/ ", None, "https://staging.example.invalid"),
        (
            "https://environment.example.invalid",
            " https://explicit.example.invalid/ ",
            "https://explicit.example.invalid",
        ),
        (None, None, "https://skylos.dev"),
        ("", None, "https://skylos.dev"),
    ],
)
def test_browser_login_persists_the_selected_server_through_environment_changes(
    monkeypatch, tmp_path, environment_url, explicit_url, expected_url
):
    credentials = _isolate_login_storage(monkeypatch, tmp_path)
    if environment_url is None:
        monkeypatch.delenv("SKYLOS_API_URL", raising=False)
    else:
        monkeypatch.setenv("SKYLOS_API_URL", environment_url)

    def current_token():
        # Selection must already be frozen before any interactive work.
        monkeypatch.setenv("SKYLOS_API_URL", "https://changed.example.invalid")
        return None

    monkeypatch.setattr(syncmod, "get_token", current_token)
    monkeypatch.setattr(loginmod, "_find_free_port", lambda: 8123)
    monkeypatch.setattr(loginmod, "_get_repo_name", lambda: "fixture-repo")
    monkeypatch.setattr(loginmod, "_get_repo_url", lambda: "")
    monkeypatch.setattr(loginmod, "_get_repo_subpath", lambda: "")
    browser_urls = []
    monkeypatch.setattr(loginmod.webbrowser, "open", browser_urls.append)

    class FakeServer:
        def __init__(self, *_args, **_kwargs):
            pass

        def handle_request(self):
            loginmod._CallbackHandler.result = loginmod.LoginResult(
                "fixture-browser-token", "unverified-callback-project", "", "", "free"
            )

        def server_close(self):
            pass

    monkeypatch.setattr(loginmod.http.server, "HTTPServer", FakeServer)
    response = Mock(status_code=200)
    response.json.return_value = {
        "project": {"id": "verified-project", "name": "Verified Project"},
        "organization": {"name": "Fixture Workspace"},
        "plan": "free",
    }
    requests = []

    def verify(url, headers, timeout):
        requests.append((url, headers, timeout))
        return response

    monkeypatch.setattr(loginmod.requests, "get", verify)

    result = loginmod.run_login(base_url=explicit_url)

    assert result is not None
    assert result.project_id == "verified-project"
    assert len(browser_urls) == 1
    opened = urlparse(browser_urls[0])
    assert f"{opened.scheme}://{opened.netloc}" == expected_url
    assert opened.path == "/cli/connect"
    assert requests == [
        (
            f"{expected_url}/api/sync/whoami",
            {"Authorization": "Bearer fixture-browser-token"},
            30,
        )
    ]
    saved_credentials = json.loads(credentials.read_text())
    link = json.loads((tmp_path / ".skylos" / "link.json").read_text())
    assert saved_credentials["tokens"]["verified-project"]["token"] == (
        "fixture-browser-token"
    )
    assert link["project_id"] == "verified-project"
    assert link["base_url"] == expected_url


def test_manual_fallback_verifies_and_saves_the_explicit_server(
    monkeypatch, tmp_path, capsys
):
    credentials = _isolate_login_storage(monkeypatch, tmp_path)
    monkeypatch.setenv("SKYLOS_API_URL", "https://other.example.invalid")
    monkeypatch.setattr(syncmod, "get_token", lambda: None)
    monkeypatch.setattr(loginmod, "browser_login", lambda **_kwargs: None)
    monkeypatch.setattr("builtins.input", lambda _prompt: "fixture-manual-token")
    response = Mock(status_code=200)
    response.json.return_value = {
        "project": {"id": "manual-project", "name": "Manual Project"},
        "organization": {"name": "Fixture Workspace"},
        "plan": "free",
    }

    def verify(url, headers, timeout):
        assert url == "https://explicit.example.invalid/api/sync/whoami"
        assert headers == {"Authorization": "Bearer fixture-manual-token"}
        assert timeout == 30
        monkeypatch.setenv("SKYLOS_API_URL", "https://changed.example.invalid")
        return response

    monkeypatch.setattr(loginmod.requests, "get", verify)

    result = loginmod.run_login(base_url="https://explicit.example.invalid/")

    assert result is not None
    assert result.project_id == "manual-project"
    link = json.loads((tmp_path / ".skylos" / "link.json").read_text())
    assert link["base_url"] == "https://explicit.example.invalid"
    assert json.loads(credentials.read_text())["token"] == "fixture-manual-token"
    assert "https://explicit.example.invalid/dashboard/settings" in (
        capsys.readouterr().out
    )


def test_existing_connection_verifies_the_explicit_server_with_oidc_headers(
    monkeypatch,
):
    monkeypatch.setenv("SKYLOS_API_URL", "https://other.example.invalid")
    monkeypatch.setattr(syncmod, "get_token", lambda: "oidc:fixture-ci-token")
    response = Mock(status_code=200)
    response.json.return_value = {
        "project": {"id": "existing-project", "name": "Existing Project"},
        "organization": {"name": "Fixture Workspace"},
        "plan": "free",
    }

    def verify(url, headers, timeout):
        assert url == "https://selected.example.invalid/api/sync/whoami"
        assert headers == {
            "Authorization": "Bearer fixture-ci-token",
            "X-Skylos-Auth": "oidc",
        }
        assert timeout == 30
        return response

    monkeypatch.setattr(loginmod.requests, "get", verify)

    result = loginmod.get_current_connection(
        base_url="https://selected.example.invalid"
    )

    assert result is not None
    assert result.project_id == "existing-project"


@pytest.mark.parametrize(
    "url",
    [
        "file:///tmp/socket",
        "https://fixture-user:fixture-password@server.example.invalid",
        "https://server.example.invalid/#fragment",
    ],
)
def test_login_rejects_unsafe_server_before_authentication(monkeypatch, url):
    connection = Mock(side_effect=AssertionError("must not inspect credentials"))
    browser = Mock(side_effect=AssertionError("must not open an unsafe browser URL"))
    monkeypatch.setattr(loginmod, "get_current_connection", connection)
    monkeypatch.setattr(loginmod, "browser_login", browser)

    with pytest.raises(syncmod.AuthError):
        loginmod.run_login(base_url=url)

    connection.assert_not_called()
    browser.assert_not_called()
