import json
from pathlib import Path
import pytest
import skylos.sync as syncmod
import builtins


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text="OK", raise_exc=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text
        self._raise_exc = raise_exc

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self._raise_exc:
            raise self._raise_exc


@pytest.fixture()
def isolated_creds(monkeypatch, tmp_path):
    monkeypatch.delenv("SKYLOS_TOKEN", raising=False)
    monkeypatch.delenv("SKYLOS_API_URL", raising=False)

    home_dir = tmp_path / "home"
    home_dir.mkdir(parents=True, exist_ok=True)

    creds_dir = home_dir / ".skylos"
    creds_file = creds_dir / "credentials.json"

    monkeypatch.setattr(syncmod, "GLOBAL_CREDS_DIR", creds_dir, raising=False)
    monkeypatch.setattr(syncmod, "GLOBAL_CREDS_FILE", creds_file, raising=False)

    return creds_dir, creds_file


def test_mask_token_short():
    assert syncmod.mask_token("abc") == "****"
    assert syncmod.mask_token("") == "****"
    assert syncmod.mask_token(None) == "****"


def test_mask_token_long():
    tok = "skylos_token_1234567890ABCDEFG"
    masked = syncmod.mask_token(tok)
    assert masked.startswith(tok[:8] + "...")
    assert masked.endswith(tok[-4:])
    assert tok not in masked


def test_get_token_env_wins(isolated_creds, monkeypatch):
    _, creds_file = isolated_creds
    creds_file.parent.mkdir(parents=True, exist_ok=True)
    creds_file.write_text(json.dumps({"token": "FILE_TOKEN"}))

    monkeypatch.setenv("SKYLOS_TOKEN", "ENV_TOKEN")
    assert syncmod.get_token() == "ENV_TOKEN"


def test_get_token_from_global_creds_file(isolated_creds):
    _, creds_file = isolated_creds
    creds_file.parent.mkdir(parents=True, exist_ok=True)
    creds_file.write_text(json.dumps({"token": "FILE_TOKEN"}))
    assert syncmod.get_token() == "FILE_TOKEN"


def test_get_token_none_if_missing(isolated_creds):
    _, creds_file = isolated_creds
    assert not creds_file.exists()
    assert syncmod.get_token() is None


def test_save_token_writes_file(isolated_creds):
    _, creds_file = isolated_creds
    assert not creds_file.exists()

    out_path = syncmod.save_token(
        "TOK_123",
        project_name="Proj",
        org_name="Org",
        plan="pro",
    )

    assert out_path == str(creds_file)
    assert creds_file.exists()
    data = json.loads(creds_file.read_text())
    assert data["token"] == "TOK_123"
    assert data["project_name"] == "Proj"
    assert data["org_name"] == "Org"
    assert data["plan"] == "pro"
    assert data["saved_at"].endswith("Z")


def test_clear_token(isolated_creds):
    _, creds_file = isolated_creds
    creds_file.parent.mkdir(parents=True, exist_ok=True)
    creds_file.write_text("{}")

    assert syncmod.clear_token() is True
    assert not creds_file.exists()
    assert syncmod.clear_token() is False


def test_api_get_success(monkeypatch):
    def fake_get(url, headers=None, timeout=None):
        assert "Authorization" in (headers or {})
        return FakeResponse(200, {"ok": True})

    monkeypatch.setattr(syncmod.requests, "get", fake_get)
    monkeypatch.setenv("SKYLOS_API_URL", "https://example.com")
    out = syncmod.api_get("/api/sync/whoami", "TOKEN")
    assert out == {"ok": True}


def test_api_get_401_raises(monkeypatch):
    def fake_get(url, headers=None, timeout=None):
        return FakeResponse(401, {"ok": False})

    monkeypatch.setattr(syncmod.requests, "get", fake_get)
    with pytest.raises(syncmod.AuthError) as e:
        syncmod.api_get("/api/sync/whoami", "BADTOKEN")
    assert "Invalid API token" in str(e.value)


def test_api_get_connection_error(monkeypatch):
    def fake_get(url, headers=None, timeout=None):
        raise syncmod.requests.exceptions.ConnectionError()

    monkeypatch.setattr(syncmod.requests, "get", fake_get)
    with pytest.raises(syncmod.AuthError) as e:
        syncmod.api_get("/api/sync/whoami", "TOKEN")
    assert "Cannot connect" in str(e.value)


def test_api_get_timeout(monkeypatch):
    def fake_get(url, headers=None, timeout=None):
        raise syncmod.requests.exceptions.Timeout()

    monkeypatch.setattr(syncmod.requests, "get", fake_get)
    with pytest.raises(syncmod.AuthError) as e:
        syncmod.api_get("/api/sync/whoami", "TOKEN")
    assert "Request timed out" in str(e.value)


def test_cmd_status_not_connected(isolated_creds, capsys):
    syncmod.cmd_status()
    out = capsys.readouterr().out
    assert "Not connected" in out
    assert "skylos sync connect" in out


def test_cmd_status_connected_ok(isolated_creds, monkeypatch, capsys):
    _, creds_file = isolated_creds
    creds_file.parent.mkdir(parents=True, exist_ok=True)
    creds_file.write_text(json.dumps({"token": "TOK"}))

    def fake_api_get(endpoint, token):
        assert endpoint == "/api/sync/whoami"
        assert token == "TOK"
        return {
            "project": {"name": "MyProj"},
            "organization": {"name": "MyOrg"},
            "plan": "free",
        }

    monkeypatch.setattr(syncmod, "api_get", fake_api_get)

    syncmod.cmd_status()
    out = capsys.readouterr().out
    assert "✓ Connected" in out
    assert "Project:" in out and "MyProj" in out
    assert "Organization:" in out and "MyOrg" in out
    assert "Plan:" in out and "Free" in out


def test_cmd_disconnect(isolated_creds, capsys):
    _, creds_file = isolated_creds
    creds_file.parent.mkdir(parents=True, exist_ok=True)
    creds_file.write_text("{}")

    syncmod.cmd_disconnect()
    out = capsys.readouterr().out
    assert "Disconnected" in out

    syncmod.cmd_disconnect()
    out2 = capsys.readouterr().out
    assert "No saved credentials" in out2


def test_cmd_connect_with_token_arg_saves_creds(isolated_creds, monkeypatch, capsys):
    def fake_api_get(endpoint, token):
        assert endpoint == "/api/sync/whoami"
        assert token == "TOK_ARG"
        return {
            "project": {"name": "Proj"},
            "organization": {"name": "Org"},
            "plan": "pro",
        }

    monkeypatch.setattr(syncmod, "api_get", fake_api_get)

    syncmod.cmd_connect("TOK_ARG")
    out = capsys.readouterr().out

    assert "Verifying token" in out
    assert "✓ Connected!" in out
    assert "Project:" in out and "Proj" in out
    assert "Organization:" in out and "Org" in out
    assert "Plan:" in out and "Pro" in out

    _, creds_file = isolated_creds
    assert creds_file.exists()
    data = json.loads(creds_file.read_text())
    assert data["token"] == "TOK_ARG"
    assert data["project_name"] == "Proj"
    assert data["org_name"] == "Org"
    assert data["plan"] == "pro"


def test_cmd_connect_cancel_input(monkeypatch):
    monkeypatch.delenv("SKYLOS_TOKEN", raising=False)

    def _raise_keyboard_interrupt(_prompt=""):
        raise KeyboardInterrupt

    monkeypatch.setattr(builtins, "input", _raise_keyboard_interrupt)

    with pytest.raises(SystemExit) as e:
        syncmod.cmd_connect(None)

    assert e.value.code == 1


def test_cmd_pull_not_connected_exits(isolated_creds, capsys):
    with pytest.raises(SystemExit) as e:
        syncmod.cmd_pull()
    assert e.value.code == 1
    out = capsys.readouterr().out
    assert "Not connected" in out or "Run 'skylos sync connect'" in out


def test_cmd_pull_writes_config_and_suppressions(
    isolated_creds, monkeypatch, tmp_path, capsys
):
    _, creds_file = isolated_creds
    creds_file.parent.mkdir(parents=True, exist_ok=True)
    creds_file.write_text(json.dumps({"token": "TOK"}))

    monkeypatch.setattr(syncmod, "SKYLOS_DIR", str(tmp_path / ".skylos"), raising=False)

    def fake_api_get(endpoint, token):
        assert token == "TOK"
        if endpoint == "/api/sync/whoami":
            return {"project": {"name": "Proj"}}
        if endpoint == "/api/sync/config":
            return {"config": {"complexity": 12, "nesting": 4}}
        if endpoint == "/api/sync/suppressions":
            return {"suppressions": [{"rule_id": "SKY-D212"}], "count": 1}
        raise AssertionError(f"Unexpected endpoint {endpoint}")

    monkeypatch.setattr(syncmod, "api_get", fake_api_get)

    syncmod.cmd_pull()
    out = capsys.readouterr().out

    assert "Pulling configuration" in out
    assert "Pulling suppressions" in out
    assert "Sync complete" in out

    skylos_dir = Path(syncmod.SKYLOS_DIR)
    config_path = skylos_dir / syncmod.CONFIG_FILE
    supp_path = skylos_dir / syncmod.SUPPRESSIONS_FILE

    assert config_path.exists()
    assert supp_path.exists()

    config_text = config_path.read_text()
    assert "complexity" in config_text
    assert "nesting" in config_text

    supp = json.loads(supp_path.read_text())
    assert isinstance(supp, list)
    assert supp[0]["rule_id"] == "SKY-D212"


def test_main_usage_no_args(capsys):
    syncmod.main([])
    out = capsys.readouterr().out
    assert "Usage: skylos sync <command>" in out
    assert "connect" in out
    assert "pull" in out


def test_main_unknown_command_exits(capsys):
    with pytest.raises(SystemExit) as e:
        syncmod.main(["wat"])
    assert e.value.code == 1
    out = capsys.readouterr().out
    assert "Unknown command" in out


def test_main_dispatch_connect(monkeypatch):
    called = {"ok": False}

    def fake_connect(arg):
        called["ok"] = True
        assert arg == "T"

    monkeypatch.setattr(syncmod, "cmd_connect", fake_connect)
    syncmod.main(["connect", "T"])
    assert called["ok"] is True
