"""Cloud setup and upload stay scoped to the requested repository."""

import json
from pathlib import Path

import pytest

from skylos import api, cli
from skylos.cloud import login
from skylos.commands import cloud_cmd


@pytest.fixture
def isolated_cloud(monkeypatch, tmp_path):
    monkeypatch.delenv("SKYLOS_TOKEN", raising=False)
    monkeypatch.setattr(api, "GLOBAL_CREDS_FILE", tmp_path / "credentials.json")
    monkeypatch.setattr(api, "get_key", lambda _key: None)
    monkeypatch.setattr(api, "_try_github_oidc_token", lambda: None)
    monkeypatch.setattr(api, "_try_gitlab_oidc_token", lambda: None)
    monkeypatch.setattr(cli, "_is_ci", lambda: False)
    monkeypatch.setattr(cli, "_is_tty", lambda: False)
    monkeypatch.setattr(cloud_cmd, "done_receipt_argv", lambda *_args: ([], None))


def test_stale_link_without_credentials_requires_sign_in(
    isolated_cloud, monkeypatch, tmp_path, capsys
):
    target = tmp_path / "target"
    (target / ".skylos").mkdir(parents=True)
    (target / ".skylos/link.json").write_text('{"project_id":"deleted-project"}')
    seen = []
    monkeypatch.setattr(
        "skylos.commands.scan_cmd.run_scan_command", lambda *_a, **_k: seen.append(1)
    )

    assert cloud_cmd.run_cloud_command([str(target)], cli_module=cli) == 1

    assert seen == []
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "sign in in your browser" in captured.err


@pytest.mark.parametrize(
    "format_args", [["--format", "json"], ["--json"], ["--format=json-ci"]]
)
def test_machine_output_never_opens_sign_in_or_writes_stdout(
    isolated_cloud, monkeypatch, tmp_path, capsys, format_args
):
    monkeypatch.setattr(cli, "_is_tty", lambda: True)

    def unexpected_login(**_kwargs):
        raise AssertionError("machine output must not start interactive sign-in")

    monkeypatch.setattr(login, "run_login", unexpected_login)

    assert (
        cloud_cmd.run_cloud_command([str(tmp_path), *format_args], cli_module=cli) == 1
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert cloud_cmd.NOT_CONNECTED in captured.err


def test_machine_format_from_project_addopts_does_not_open_sign_in(
    isolated_cloud, monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(cli, "_is_tty", lambda: True)
    monkeypatch.setattr(cli, "_load_addopts", lambda: ["--format=json"])
    monkeypatch.setattr(
        login, "run_login", lambda **kwargs: pytest.fail("unexpected login")
    )

    assert cloud_cmd.run_cloud_command([str(tmp_path)], cli_module=cli) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert cloud_cmd.NOT_CONNECTED in captured.err


@pytest.mark.parametrize("linked_project", [None, "target-project"])
def test_global_legacy_token_cannot_select_a_new_repo_project(
    isolated_cloud, monkeypatch, tmp_path, capsys, linked_project
):
    target = tmp_path / "target"
    target.mkdir()
    if linked_project:
        (target / ".skylos").mkdir()
        (target / ".skylos/link.json").write_text(
            json.dumps({"project_id": linked_project})
        )
    api.GLOBAL_CREDS_FILE.write_text(
        json.dumps(
            {
                "token": "last-used-project-token",
                "project_id": "last-project",
                "tokens": {"last-project": {"token": "last-used-project-token"}},
            }
        )
    )
    monkeypatch.setattr(
        "skylos.commands.scan_cmd.run_scan_command",
        lambda *_args, **_kwargs: pytest.fail("unscoped credential must not upload"),
    )

    assert cloud_cmd.run_cloud_command([str(target)], cli_module=cli) == 1

    assert cloud_cmd.NOT_CONNECTED in capsys.readouterr().err


@pytest.mark.parametrize(
    "credentials",
    [
        {"project_id": "target-project", "token": "matching-legacy-token"},
        {"tokens": {"target-project": {"token": "matching-token"}}},
    ],
)
def test_target_link_requires_a_credential_saved_for_that_project(
    isolated_cloud, monkeypatch, tmp_path, credentials
):
    target = tmp_path / "target"
    (target / ".skylos").mkdir(parents=True)
    (target / ".skylos/link.json").write_text('{"project_id":"target-project"}')
    api.GLOBAL_CREDS_FILE.write_text(json.dumps(credentials))
    observed = []
    monkeypatch.setattr(
        "skylos.commands.scan_cmd.run_scan_command",
        lambda *_a, **_k: observed.append(1),
    )

    assert cloud_cmd.run_cloud_command([str(target)], cli_module=cli) == 0

    assert observed == [1]


@pytest.mark.parametrize(
    "link, credentials",
    [
        (["not-an-object"], {}),
        ({"project_id": "target-project"}, ["not-an-object"]),
        ({"project_id": "target-project"}, {"tokens": ["not-an-object"]}),
        ({"project_id": "target-project"}, {"tokens": {"target-project": "bad"}}),
    ],
)
def test_malformed_saved_connection_is_not_a_credential(
    isolated_cloud, monkeypatch, tmp_path, link, credentials
):
    target = tmp_path / "target"
    (target / ".skylos").mkdir(parents=True)
    (target / ".skylos/link.json").write_text(json.dumps(link))
    api.GLOBAL_CREDS_FILE.write_text(json.dumps(credentials))

    assert cloud_cmd.run_cloud_command([str(target)], cli_module=cli) == 1


def test_cloud_uses_target_saved_project_instead_of_caller_project(
    isolated_cloud, monkeypatch, tmp_path
):
    caller = tmp_path / "caller"
    target = tmp_path / "target"
    for root, project in ((caller, "caller-project"), (target, "target-project")):
        (root / ".skylos").mkdir(parents=True)
        (root / ".skylos/link.json").write_text(json.dumps({"project_id": project}))
    api.GLOBAL_CREDS_FILE.write_text(
        json.dumps(
            {
                "token": "caller-token",
                "tokens": {
                    "caller-project": {"token": "caller-token"},
                    "target-project": {"token": "target-token"},
                },
            }
        )
    )
    monkeypatch.chdir(caller)
    observed = []

    def scan(argv, **kwargs):
        observed.append((Path.cwd(), api.get_project_token(), argv[0]))

    monkeypatch.setattr("skylos.commands.scan_cmd.run_scan_command", scan)

    assert cloud_cmd.run_cloud_command(["../target"], cli_module=cli) == 0

    assert observed == [(target, "target-token", str(target))]
    assert Path.cwd() == caller
    assert api.get_project_token() == "caller-token"


def test_cloud_sign_in_and_scan_both_use_target_context(
    isolated_cloud, monkeypatch, tmp_path
):
    caller = tmp_path / "caller"
    target = tmp_path / "target"
    caller.mkdir()
    target.mkdir()
    monkeypatch.chdir(caller)
    monkeypatch.setattr(cli, "_is_tty", lambda: True)
    observed = []

    def sign_in(**kwargs):
        observed.append(("login", Path.cwd(), kwargs["allow_manual"]))
        return object()

    def scan(argv, **kwargs):
        observed.append(("scan", Path.cwd(), argv[0]))

    monkeypatch.setattr(login, "run_login", sign_in)
    monkeypatch.setattr("skylos.commands.scan_cmd.run_scan_command", scan)

    assert cloud_cmd.run_cloud_command(["../target"], cli_module=cli) == 0

    assert observed == [("login", target, False), ("scan", target, str(target))]
    assert Path.cwd() == caller


def test_cloud_preserves_multiple_scan_paths_and_project_relative_filters(
    isolated_cloud, monkeypatch, tmp_path
):
    caller = tmp_path / "caller"
    target = tmp_path / "target"
    caller.mkdir()
    (target / "src").mkdir(parents=True)
    (target / "tests").mkdir()
    monkeypatch.chdir(caller)
    monkeypatch.setenv("SKYLOS_TOKEN", "explicit-token")
    observed = []

    def scan(argv, **kwargs):
        parsed = cli._build_main_parser().parse_args(argv)
        observed.append((Path.cwd(), parsed.path, parsed.exclude_folders, parsed.diff))

    monkeypatch.setattr("skylos.commands.scan_cmd.run_scan_command", scan)

    assert (
        cloud_cmd.run_cloud_command(
            [
                "../target/src",
                "../target/tests",
                "--exclude",
                "generated/**",
                "--diff",
                "main",
            ],
            cli_module=cli,
        )
        == 0
    )

    assert observed == [
        (target, [str(target / "src"), str(target / "tests")], ["generated/**"], "main")
    ]


def test_cloud_selects_saved_monorepo_project_for_target_subpath(
    isolated_cloud, monkeypatch, tmp_path
):
    root = tmp_path / "repo"
    first = root / "apps" / "first"
    second = root / "apps" / "second"
    first.mkdir(parents=True)
    second.mkdir()
    (root / ".skylos").mkdir()
    (root / ".skylos/link.json").write_text(
        json.dumps(
            {
                "project_id": "root-project",
                "projects": {
                    "apps/first": {"project_id": "first-project"},
                    "apps/second": {"project_id": "second-project"},
                },
            }
        )
    )
    api.GLOBAL_CREDS_FILE.write_text(
        json.dumps(
            {
                "token": "last-used-token",
                "tokens": {
                    "first-project": {"token": "first-token"},
                    "second-project": {"token": "second-token"},
                },
            }
        )
    )
    monkeypatch.setattr(api, "get_git_root", lambda: str(root))
    observed = []
    monkeypatch.setattr(
        "skylos.commands.scan_cmd.run_scan_command",
        lambda *_args, **_kwargs: observed.append(
            (Path.cwd(), api.get_project_token())
        ),
    )

    assert cloud_cmd.run_cloud_command([str(first)], cli_module=cli) == 0
    assert cloud_cmd.run_cloud_command([str(second)], cli_module=cli) == 0

    assert observed == [(first, "first-token"), (second, "second-token")]


def test_an_unlinked_monorepo_subdirectory_gets_its_own_first_connection(
    isolated_cloud, monkeypatch, tmp_path
):
    root = tmp_path / "repo"
    second = root / "apps" / "second"
    second.mkdir(parents=True)
    (root / ".skylos").mkdir()
    (root / ".skylos/link.json").write_text(json.dumps({
        "project_id": "first-project",
        "repo_subpath": "apps/first",
        "projects": {"apps/first": {"project_id": "first-project"}},
    }))
    api.GLOBAL_CREDS_FILE.write_text(json.dumps({
        "tokens": {"first-project": {"token": "first-token"}},
    }))
    monkeypatch.setattr(api, "get_git_root", lambda: str(root))
    monkeypatch.setattr(cli, "_is_tty", lambda: True)
    login_attempts = []
    monkeypatch.setattr(login, "run_login", lambda **kwargs: login_attempts.append(Path.cwd()))
    monkeypatch.setattr(
        "skylos.commands.scan_cmd.run_scan_command",
        lambda *_args, **_kwargs: pytest.fail("must wait for the new project's login"),
    )

    assert cloud_cmd.run_cloud_command([str(second)], cli_module=cli) == 1
    assert login_attempts == [second]


@pytest.mark.parametrize("failure", [SystemExit(3), RuntimeError("scan failed")])
def test_cloud_restores_caller_directory_when_scan_exits(
    isolated_cloud, monkeypatch, tmp_path, failure
):
    caller = tmp_path / "caller"
    target = tmp_path / "target"
    caller.mkdir()
    target.mkdir()
    monkeypatch.chdir(caller)
    monkeypatch.setenv("SKYLOS_TOKEN", "explicit-token")

    def scan(*_args, **_kwargs):
        assert Path.cwd() == target
        raise failure

    monkeypatch.setattr("skylos.commands.scan_cmd.run_scan_command", scan)

    with pytest.raises(type(failure)):
        cloud_cmd.run_cloud_command(["../target"], cli_module=cli)

    assert Path.cwd() == caller


def test_cloud_missing_path_stops_before_login(
    isolated_cloud, monkeypatch, tmp_path, capsys
):
    monkeypatch.chdir(tmp_path)

    def unexpected_login(**_kwargs):
        raise AssertionError("invalid paths must not start sign-in")

    monkeypatch.setattr(login, "run_login", unexpected_login)

    assert cloud_cmd.run_cloud_command(["missing"], cli_module=cli) == 2
    assert Path.cwd() == tmp_path
    assert "scan path does not exist" in capsys.readouterr().err


@pytest.mark.parametrize(
    "file_args, expected_paths",
    [
        (["--output", "report.json"], {"output": "report.json"}),
        (["--output=report.json"], {"output": "report.json"}),
        (["-oreport.json"], {"output": "report.json"}),
        (["--config-file", "settings.toml"], {"config_file": "settings.toml"}),
        (["--done-receipt=receipt.json"], {"done_receipt": "receipt.json"}),
        (["--profile-output", "profile.json"], {"profile_output": "profile.json"}),
        (["--sarif", "report.sarif"], {"sarif": "report.sarif"}),
        (["--sarif"], {"sarif": "skylos.sarif.json"}),
        (["--output", "-", "--sarif=-"], {"output": "-", "sarif": "-"}),
    ],
)
def test_cloud_preserves_caller_relative_file_options(
    isolated_cloud, monkeypatch, tmp_path, file_args, expected_paths
):
    caller = tmp_path / "caller"
    target = tmp_path / "target"
    caller.mkdir()
    target.mkdir()
    monkeypatch.chdir(caller)
    monkeypatch.setenv("SKYLOS_TOKEN", "explicit-token")
    observed = []

    def scan(argv, **kwargs):
        assert Path.cwd() == target
        parsed = cli._build_main_parser().parse_args(argv)
        assert parsed.path == [str(target)]
        observed.append({key: getattr(parsed, key) for key in expected_paths})

    monkeypatch.setattr("skylos.commands.scan_cmd.run_scan_command", scan)

    assert cloud_cmd.run_cloud_command(["../target", *file_args], cli_module=cli) == 0

    assert observed == [
        {
            key: value if value == "-" else str(caller / value)
            for key, value in expected_paths.items()
        }
    ]


def test_cloud_machine_done_progress_stays_off_stdout(
    isolated_cloud, monkeypatch, tmp_path, capsys
):
    monkeypatch.setenv("SKYLOS_TOKEN", "explicit-token")

    def done(_root, console):
        console.print("Checking the Done receipt")
        return [], None

    monkeypatch.setattr(cloud_cmd, "done_receipt_argv", done)
    monkeypatch.setattr(
        "skylos.commands.scan_cmd.run_scan_command", lambda *_a, **_k: None
    )

    assert (
        cloud_cmd.run_cloud_command([str(tmp_path), "--format=json"], cli_module=cli)
        == 0
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Checking the Done receipt" in captured.err


def test_cloud_does_not_resolve_output_symlink_before_safe_writer_checks_it(
    isolated_cloud, monkeypatch, tmp_path
):
    from skylos.commands.scan_cmd import _write_scan_output

    caller = tmp_path / "caller"
    target = tmp_path / "target"
    caller.mkdir()
    target.mkdir()
    preserved = caller / "preserved.json"
    preserved.write_text("original content")
    output = caller / "report.json"
    output.symlink_to(preserved)
    monkeypatch.chdir(caller)
    monkeypatch.setenv("SKYLOS_TOKEN", "explicit-token")

    def scan(argv, **kwargs):
        parsed = cli._build_main_parser().parse_args(argv)
        assert parsed.output == str(output)
        _write_scan_output(parsed.output, "replacement")

    monkeypatch.setattr("skylos.commands.scan_cmd.run_scan_command", scan)

    with pytest.raises(OSError, match="could not safely write output file"):
        cloud_cmd.run_cloud_command(
            ["../target", "--output", "report.json"], cli_module=cli
        )

    assert preserved.read_text() == "original content"
    assert output.is_symlink()
    assert Path.cwd() == caller
