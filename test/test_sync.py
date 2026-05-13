import json
import os
from pathlib import Path
import subprocess
import pytest
import skylos.cloud.sync as syncmod
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


def test_get_token_prefers_github_oidc_before_saved_token(isolated_creds, monkeypatch):
    _, creds_file = isolated_creds
    creds_file.parent.mkdir(parents=True, exist_ok=True)
    creds_file.write_text(json.dumps({"token": "FILE_TOKEN"}))
    monkeypatch.setattr(syncmod, "_try_ci_oidc_token", lambda: "oidc:JWT")

    assert syncmod.get_token() == "oidc:JWT"


def test_api_get_sends_oidc_auth_headers(monkeypatch):
    captured = {}

    def fake_get(url, headers=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        captured["timeout"] = timeout
        return FakeResponse(payload={"ok": True})

    monkeypatch.setattr(syncmod.requests, "get", fake_get)

    assert syncmod.api_get("/api/sync/whoami", "oidc:JWT") == {"ok": True}
    assert captured["headers"] == {
        "Authorization": "Bearer JWT",
        "X-Skylos-Auth": "oidc",
    }


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
        project_id="proj_abc",
        project_name="Proj",
        org_name="Org",
        plan="pro",
    )

    assert out_path == str(creds_file)
    assert creds_file.exists()
    data = json.loads(creds_file.read_text())
    assert data["token"] == "TOK_123"
    assert data["plan"] == "pro"
    assert data["saved_at"].endswith("Z")
    assert data["tokens"]["proj_abc"]["project_name"] == "Proj"
    assert data["tokens"]["proj_abc"]["org_name"] == "Org"
    if os.name != "nt":
        assert (creds_file.stat().st_mode & 0o777) == 0o600
        assert (creds_file.parent.stat().st_mode & 0o777) == 0o700


def test_get_token_uses_repo_subpath_link(isolated_creds, monkeypatch, tmp_path):
    _, creds_file = isolated_creds
    repo = tmp_path / "repo"
    api_dir = repo / "apps" / "api"
    web_dir = repo / "apps" / "web"
    api_dir.mkdir(parents=True)
    web_dir.mkdir(parents=True)

    syncmod._write_link(
        repo,
        "proj-api",
        project_name="API",
        repo_subpath="apps/api",
    )
    syncmod._write_link(
        repo,
        "proj-web",
        project_name="Web",
        repo_subpath="apps/web",
    )
    syncmod.save_token("TOK_API", project_id="proj-api", repo_subpath="apps/api")
    syncmod.save_token("TOK_WEB", project_id="proj-web", repo_subpath="apps/web")

    monkeypatch.setattr(syncmod, "_find_repo_root", lambda: repo)

    monkeypatch.chdir(api_dir)
    assert syncmod.get_token() == "TOK_API"

    monkeypatch.chdir(web_dir)
    assert syncmod.get_token() == "TOK_WEB"


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


def test_api_get_rejects_absolute_endpoint(monkeypatch):
    def fail_get(*args, **kwargs):
        raise AssertionError("unsafe endpoint should not be requested")

    monkeypatch.setattr(syncmod.requests, "get", fail_get)

    with pytest.raises(syncmod.AuthError) as e:
        syncmod.api_get("https://evil.example/api/sync/whoami", "TOKEN")
    assert "relative" in str(e.value)


def test_api_get_rejects_unsafe_base_url(monkeypatch):
    monkeypatch.setenv("SKYLOS_API_URL", "file:///tmp/socket")

    with pytest.raises(syncmod.AuthError) as e:
        syncmod.api_get("/api/sync/whoami", "TOKEN")
    assert "HTTP or HTTPS" in str(e.value)


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
    assert "skylos login" in out


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


def test_cmd_project_unlink_removes_only_link(
    isolated_creds, monkeypatch, tmp_path, capsys
):
    repo_root = tmp_path / "repo"
    link_path = repo_root / ".skylos" / "link.json"
    link_path.parent.mkdir(parents=True, exist_ok=True)
    link_path.write_text(json.dumps({"project_id": "proj_123"}))

    _, creds_file = isolated_creds
    creds_file.parent.mkdir(parents=True, exist_ok=True)
    creds_file.write_text(json.dumps({"token": "TOK"}))

    monkeypatch.setattr(syncmod, "_find_repo_root", lambda: repo_root)

    syncmod.cmd_project_unlink()
    out = capsys.readouterr().out

    assert "Removed repo link" in out
    assert not link_path.exists()
    assert creds_file.exists()


def test_cmd_project_list_marks_active_project(
    isolated_creds, monkeypatch, tmp_path, capsys
):
    repo_root = tmp_path / "repo"
    link_path = repo_root / ".skylos" / "link.json"
    link_path.parent.mkdir(parents=True, exist_ok=True)
    link_path.write_text(json.dumps({"project_id": "proj_active"}))

    _, creds_file = isolated_creds
    creds_file.parent.mkdir(parents=True, exist_ok=True)
    creds_file.write_text(
        json.dumps(
            {
                "tokens": {
                    "proj_active": {
                        "token": "TOK1",
                        "project_name": "Active Project",
                        "org_name": "Org",
                        "plan": "pro",
                        "saved_at": "2026-01-01T00:00:00Z",
                    },
                    "proj_other": {
                        "token": "TOK2",
                        "project_name": "Other Project",
                        "org_name": "Org",
                        "plan": "free",
                        "saved_at": "2025-01-01T00:00:00Z",
                    },
                }
            }
        )
    )

    monkeypatch.setattr(syncmod, "_find_repo_root", lambda: repo_root)

    syncmod.cmd_project_list()
    out = capsys.readouterr().out

    assert "* Active Project  [proj_active]" in out
    assert "Other Project  [proj_other]" in out
    assert "active for this repo" in out


def test_cmd_connect_with_token_arg_saves_creds(isolated_creds, monkeypatch, capsys):
    def fake_api_get(endpoint, token):
        assert endpoint == "/api/sync/whoami"
        assert token == "TOK_ARG"
        return {
            "project": {"id": "proj_123", "name": "Proj"},
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
    assert data["plan"] == "pro"
    assert data["tokens"]["proj_123"]["project_name"] == "Proj"
    assert data["tokens"]["proj_123"]["org_name"] == "Org"


def test_cmd_connect_cancel_input(monkeypatch):
    monkeypatch.delenv("SKYLOS_TOKEN", raising=False)

    def _raise_keyboard_interrupt(_prompt=""):
        raise KeyboardInterrupt

    monkeypatch.setattr(builtins, "input", _raise_keyboard_interrupt)

    with pytest.raises(SystemExit) as e:
        syncmod.cmd_connect(None)

    assert e.value.code == 1


def test_cmd_connect_declines_env_token_then_cancels(monkeypatch, capsys):
    monkeypatch.setenv("SKYLOS_TOKEN", "ENV_TOKEN")

    answers = iter(["n"])

    def fake_input(_prompt=""):
        try:
            return next(answers)
        except StopIteration:
            raise KeyboardInterrupt

    monkeypatch.setattr(builtins, "input", fake_input)

    with pytest.raises(SystemExit) as e:
        syncmod.cmd_connect(None)

    assert e.value.code == 1
    out = capsys.readouterr().out
    assert "SKYLOS_TOKEN environment variable is set" in out
    assert "Cancelled." in out


def test_cmd_connect_accepts_project_project_id(isolated_creds, monkeypatch, capsys):
    def fake_api_get(endpoint, token):
        assert endpoint == "/api/sync/whoami"
        assert token == "TOK_ARG"
        return {
            "project": {"project_id": "proj_legacy", "name": "Proj"},
            "organization": {"name": "Org"},
            "plan": "pro",
        }

    monkeypatch.setattr(syncmod, "api_get", fake_api_get)

    syncmod.cmd_connect("TOK_ARG")
    out = capsys.readouterr().out

    assert "✓ Connected!" in out
    _, creds_file = isolated_creds
    data = json.loads(creds_file.read_text())
    assert data["tokens"]["proj_legacy"]["project_name"] == "Proj"


def test_cmd_pull_not_connected_exits(isolated_creds, capsys):
    with pytest.raises(SystemExit) as e:
        syncmod.cmd_pull()
    assert e.value.code == 1
    out = capsys.readouterr().out
    assert "Not connected" in out or "Run 'skylos login'" in out


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
            return {
                "config": {
                    "complexity_threshold": 12,
                    "nesting_threshold": 4,
                    "security_contracts": [
                        {
                            "framework": "fastapi",
                            "file": "app/api/routes.py",
                            "handler": "list_users",
                            "guards": ["require_admin"],
                        }
                    ],
                }
            }
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
    assert "complexity_threshold" in config_text
    assert "nesting_threshold" in config_text
    assert "security_contracts" in config_text
    assert "list_users" in config_text

    supp = json.loads(supp_path.read_text())
    assert isinstance(supp, list)
    assert supp[0]["rule_id"] == "SKY-D212"


def test_cmd_pull_writes_top_level_config_shape(
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
            return {
                "project_id": "p1",
                "project_name": "Proj",
                "gate_mode": "severity",
                "gate": {"enabled": True, "mode": "severity"},
            }
        if endpoint == "/api/sync/suppressions":
            return {"suppressions": [], "count": 0}
        raise AssertionError(f"Unexpected endpoint {endpoint}")

    monkeypatch.setattr(syncmod, "api_get", fake_api_get)

    syncmod.cmd_pull()
    out = capsys.readouterr().out

    assert "Sync complete" in out

    skylos_dir = Path(syncmod.SKYLOS_DIR)
    config_path = skylos_dir / syncmod.CONFIG_FILE

    config_text = config_path.read_text()
    assert "project_id: p1" in config_text
    assert "gate_mode: severity" in config_text


def test_cmd_pull_calls_endpoints_in_order(isolated_creds, monkeypatch, tmp_path):
    _, creds_file = isolated_creds
    creds_file.parent.mkdir(parents=True, exist_ok=True)
    creds_file.write_text(json.dumps({"token": "TOK"}))

    monkeypatch.setattr(syncmod, "SKYLOS_DIR", str(tmp_path / ".skylos"), raising=False)

    calls = []

    def fake_api_get(endpoint, token):
        calls.append(endpoint)
        if endpoint == "/api/sync/whoami":
            return {"project": {"name": "Proj"}}
        if endpoint == "/api/sync/config":
            return {"config": {"complexity": 12}}
        if endpoint == "/api/sync/suppressions":
            return {"suppressions": [], "count": 0}
        raise AssertionError(f"Unexpected endpoint {endpoint}")

    monkeypatch.setattr(syncmod, "api_get", fake_api_get)

    syncmod.cmd_pull()

    assert calls == [
        "/api/sync/whoami",
        "/api/sync/config",
        "/api/sync/suppressions",
    ]


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


def test_project_main_unknown_command_exits(capsys):
    with pytest.raises(SystemExit) as e:
        syncmod.project_main(["wat"])
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


def test_create_precommit_config_limits_gate_to_pre_commit(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    created = syncmod.create_precommit_config()

    assert created is True
    content = (tmp_path / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    assert "Fast staged-only local hook." in content
    assert "Full repo and diff-aware enforcement runs in CI." in content
    assert "stages: [pre-commit]" in content
    assert "entry: python -m skylos.cli" in content
    assert "language: python" in content
    assert "additional_dependencies:" in content
    assert '- "rich>=14.0.0"' in content
    assert '- "libcst>=1.8.2"' in content
    assert '- "tree-sitter-php>=0.24.1"' in content
    assert '- "tree-sitter-rust>=0.24.2"' in content
    assert '- "tomli>=2.0.1; python_version < \'3.11\'"' in content
    assert 'args: ["agent", "pre-commit", "."]' in content
    assert "--gate" not in content


def test_cmd_setup_installs_parity_only_pre_push_hook(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".git").mkdir()

    monkeypatch.setattr(
        syncmod,
        "api_get",
        lambda endpoint, token: {
            "/api/sync/whoami": {
                "project": {"id": "proj_123", "name": "Proj"},
                "organization": {"name": "Org"},
                "plan": "pro",
            }
        }[endpoint],
    )
    monkeypatch.setattr(syncmod, "_write_link", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        syncmod, "save_token", lambda *args, **kwargs: str(tmp_path / "creds.json")
    )

    answers = iter(["y", "n", "n"])
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(answers))

    syncmod.cmd_setup("TOK")

    hook = (tmp_path / ".git" / "hooks" / "pre-push").read_text(encoding="utf-8")
    assert "skylos ." not in hook
    assert "direct pushes to $remote_ref are not allowed" in hook
    assert "refs/heads/main|refs/heads/master" in hook
    assert "Rust/Python parity check" in hook
    assert "test/test_fast_parity.py" in hook


def _run_generated_pre_push_hook(
    tmp_path: Path, stdin: str
) -> subprocess.CompletedProcess:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    python_stub = bin_dir / "python3"
    python_stub.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    python_stub.chmod(0o755)

    hook = tmp_path / "pre-push"
    hook.write_text(syncmod._build_pre_push_hook(), encoding="utf-8")
    hook.chmod(0o755)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
    return subprocess.run(
        [str(hook)],
        input=stdin,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        check=False,
    )


@pytest.mark.parametrize(
    ("stdin", "blocked_ref"),
    [
        pytest.param(
            "refs/heads/main "
            + "1" * 40
            + " refs/heads/main "
            + "2" * 40
            + "\n",
            "refs/heads/main",
            id="local-main-to-remote-main",
        ),
        pytest.param(
            "refs/heads/topic "
            + "1" * 40
            + " refs/heads/main "
            + "2" * 40
            + "\n",
            "refs/heads/main",
            id="topic-to-remote-main",
        ),
        pytest.param(
            "(delete) " + "0" * 40 + " refs/heads/main " + "2" * 40 + "\n",
            "refs/heads/main",
            id="delete-main",
        ),
        pytest.param(
            "refs/heads/master "
            + "1" * 40
            + " refs/heads/master "
            + "2" * 40
            + "\n",
            "refs/heads/master",
            id="master",
        ),
    ],
)
def test_pre_push_hook_blocks_protected_branch_updates(
    tmp_path, stdin, blocked_ref
):
    result = _run_generated_pre_push_hook(tmp_path, stdin)

    assert result.returncode == 1
    assert f"direct pushes to {blocked_ref} are not allowed" in result.stdout
    assert "open a pull request" in result.stdout


@pytest.mark.parametrize(
    "stdin",
    [
        "",
        "refs/heads/topic " + "1" * 40 + " refs/heads/topic " + "2" * 40 + "\n",
        "refs/tags/v1.0.0 " + "1" * 40 + " refs/tags/v1.0.0 " + "0" * 40 + "\n",
        "refs/heads/main-fix "
        + "1" * 40
        + " refs/heads/main-fix "
        + "2" * 40
        + "\n",
    ],
)
def test_pre_push_hook_allows_non_protected_refs(tmp_path, stdin):
    result = _run_generated_pre_push_hook(tmp_path, stdin)

    assert result.returncode == 0
    assert "direct pushes" not in result.stdout


def test_cmd_setup_accepts_project_project_id(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".git").mkdir()

    monkeypatch.setattr(
        syncmod,
        "api_get",
        lambda endpoint, token: {
            "/api/sync/whoami": {
                "project": {"project_id": "proj_legacy", "name": "Proj"},
                "organization": {"name": "Org"},
                "plan": "free",
            }
        }[endpoint],
    )
    monkeypatch.setattr(syncmod, "_write_link", lambda *args, **kwargs: None)
    saved = {}

    def fake_save_token(token, **kwargs):
        saved.update(kwargs)
        return str(tmp_path / "creds.json")

    monkeypatch.setattr(syncmod, "save_token", fake_save_token)
    answers = iter(["n", "n", "n"])
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(answers))

    syncmod.cmd_setup("TOK")

    assert saved["project_id"] == "proj_legacy"


def test_cmd_setup_writes_workflow_that_syncs_cloud_policy(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".git").mkdir()

    monkeypatch.setattr(
        syncmod,
        "api_get",
        lambda endpoint, token: {
            "/api/sync/whoami": {
                "project": {"id": "proj_123", "name": "Proj"},
                "organization": {"name": "Org"},
                "plan": "pro",
            }
        }[endpoint],
    )
    monkeypatch.setattr(syncmod, "_write_link", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        syncmod, "save_token", lambda *args, **kwargs: str(tmp_path / "creds.json")
    )

    answers = iter(["n", "n", "y"])
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(answers))

    syncmod.cmd_setup("TOK")

    workflow = (tmp_path / ".github" / "workflows" / "skylos.yml").read_text(
        encoding="utf-8"
    )
    assert "Pull Skylos Cloud Policy" in workflow
    assert "skylos sync pull" in workflow
    assert "id-token: write" in workflow
    assert "skylos . --danger --secrets --quality --upload" in workflow
    assert "--sha" not in workflow
    assert "SKYLOS_COMMIT" in workflow
    assert "SKYLOS_BRANCH" in workflow
    assert "SKYLOS_TOKEN" not in workflow


def test_cmd_upgrade_installs_parity_only_pre_push_hook(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".git").mkdir()

    monkeypatch.setattr(syncmod, "get_token", lambda: "TOK")
    monkeypatch.setattr(
        syncmod,
        "api_get",
        lambda endpoint, token: {"/api/sync/whoami": {"plan": "pro"}}[endpoint],
    )

    syncmod.cmd_upgrade()

    hook = (tmp_path / ".git" / "hooks" / "pre-push").read_text(encoding="utf-8")
    assert "skylos ." not in hook
    assert "direct pushes to $remote_ref are not allowed" in hook
    assert "refs/heads/main|refs/heads/master" in hook
    assert "Rust/Python parity check" in hook
    assert "test/test_fast_parity.py" in hook
    workflow = (tmp_path / ".github" / "workflows" / "skylos.yml").read_text(
        encoding="utf-8"
    )
    assert "Pull Skylos Cloud Policy" in workflow
    assert "skylos sync pull" in workflow
    assert "id-token: write" in workflow
    assert "skylos . --danger --secrets --quality --upload" in workflow
    assert "--sha" not in workflow
    assert "SKYLOS_COMMIT" in workflow
    assert "SKYLOS_BRANCH" in workflow
    assert "SKYLOS_TOKEN" not in workflow
