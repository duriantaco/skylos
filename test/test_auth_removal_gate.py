"""Authentication-control losses survive the public scan and CI gate paths."""

import difflib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from skylos.cicd.policy import base_policy_context, resolve_policy_base
from skylos.config import ConfigError, load_config
from skylos.core.baseline import filter_new_findings
from skylos.core.gatekeeper import check_gate
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.quality.regression import detect_security_regressions

IMPORTS = "from django.contrib.auth.decorators import login_required\nfrom django.http import HttpResponseForbidden\n"
PROTECTED = (
    IMPORTS + "\n@login_required\ndef export_customer(request):\n    return 42\n"
)
OPEN = PROTECTED.replace("@login_required\n", "")


def _regressions(before, after):
    diff = "".join(
        difflib.unified_diff(
            before.splitlines(True),
            after.splitlines(True),
            fromfile="a/views.py",
            tofile="b/views.py",
        )
    )
    return detect_security_regressions(
        diff, "views.py", old_source=before, new_source=after
    )


def _write(path, content):
    assert write_text_no_symlink(path, content)


def _git(root, *args):
    result = subprocess.run(
        ["git", *args], cwd=root, text=True, capture_output=True, check=True
    )
    return result.stdout.strip()


@pytest.fixture
def removed_auth_repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    _write(root / "views.py", PROTECTED)
    _write(root / "pyproject.toml", "[tool.skylos.gate]\nmax_high=0\nmax_quality=0\n")
    _git(root, "init", "-q")
    _git(
        root,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "add",
        "views.py",
        "pyproject.toml",
    )
    _git(
        root,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-qm",
        "protected base",
    )
    _git(root, "tag", "base")
    _git(root, "update-ref", "refs/remotes/origin/main", "HEAD")
    _write(root / "views.py", OPEN)
    # Head attempts to disable discovery, suppress the rule and raise allowances.
    _write(
        root / "pyproject.toml",
        '[tool.skylos]\nignore=["SKY-L021"]\nexclude=["."]\n[tool.skylos.gate]\nmax_high=999\nmax_quality=999\n',
    )
    (root / ".skylos").mkdir()
    _write(
        root / ".skylos/config.yaml",
        'ignore: [SKY-L021]\nexclude: ["."]\ngate:\n  max_high: 999\n',
    )
    _git(
        root,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "add",
        "views.py",
        "pyproject.toml",
        ".skylos/config.yaml",
    )
    _git(
        root,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-qm",
        "remove auth and weaken head policy",
    )
    return root


def test_base_policy_ignores_head_toml_and_forged_synced_yaml(
    removed_auth_repo, monkeypatch
):
    monkeypatch.delenv("SKYLOS_CONFIG_FILE", raising=False)
    monkeypatch.delenv("SKYLOS_POLICY_BASE", raising=False)
    with base_policy_context(removed_auth_repo, "base"):
        cfg = load_config(removed_auth_repo)
        assert cfg["gate"]["max_high"] == 0
        assert "SKY-L021" not in cfg["ignore"]
        assert "." not in cfg["exclude"]
    assert "SKYLOS_POLICY_BASE" not in os.environ
    with pytest.raises(ConfigError):
        resolve_policy_base(removed_auth_repo, "missing-base")


def test_auth_loss_cannot_be_baselined_or_allowed_as_quality_debt():
    finding = _regressions(PROTECTED, OPEN)[0]
    result = {"quality": [finding], "danger": []}
    baseline = {"fingerprints": [f"SKY-L021:{finding['file']}:{finding['line']}"]}
    assert filter_new_findings(result, baseline)["quality"] == [finding]
    passed, reasons = check_gate(
        result, {"gate": {"max_high": 999, "max_quality": 999}}
    )
    assert not passed
    assert any("security control regression" in reason for reason in reasons)


def test_low_quality_issue_keeps_existing_gate_allowance():
    finding = {
        "rule_id": "SKY-L009",
        "severity": "LOW",
        "kind": "debug_leftover",
        "file": "views.py",
        "line": 1,
    }
    passed, reasons = check_gate({"quality": [finding]}, {"gate": {"max_quality": 10}})
    assert passed and not reasons


def test_base_synced_policy_keeps_precedence_over_operator_toml(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    _write(root / "pyproject.toml", "[tool.skylos.gate]\nmax_high=9\n")
    (root / ".skylos").mkdir()
    _write(root / ".skylos/config.yaml", "gate:\n  max_high: 0\n")
    _git(root, "init", "-q")
    _git(root, "add", "pyproject.toml", ".skylos/config.yaml")
    _git(
        root,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-qm",
        "trusted policy",
    )
    operator = tmp_path / "operator.toml"
    _write(operator, "[skylos.gate]\nmax_high=20\n")
    monkeypatch.setenv("SKYLOS_CONFIG_FILE", str(operator))
    with base_policy_context(root, "HEAD"):
        config = load_config(root)
        assert config["gate"]["max_high"] == 0
        assert config.dependency_baseline_locked


def test_base_policy_follows_nearest_base_manifest_not_new_head_manifest(
    tmp_path, monkeypatch
):
    root = tmp_path / "repo"
    selected = root / "apps" / "api"
    selected.mkdir(parents=True)
    _write(root / "pyproject.toml", "[tool.skylos.gate]\nmax_high=0\n")
    _write(selected / "views.py", PROTECTED)
    _git(root, "init", "-q")
    _git(root, "add", "pyproject.toml", "apps/api/views.py")
    _git(
        root,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-qm",
        "root policy",
    )
    _write(selected / "pyproject.toml", "[tool.skylos.gate]\nmax_high=999\n")
    monkeypatch.delenv("SKYLOS_CONFIG_FILE", raising=False)
    with base_policy_context(selected, "HEAD"):
        assert load_config(selected)["gate"]["max_high"] == 0


@pytest.mark.parametrize("kind", ["invalid-toml", "symlink"])
def test_unreadable_base_policy_fails_closed(tmp_path, monkeypatch, kind):
    root = tmp_path / "repo"
    root.mkdir()
    if kind == "symlink":
        (root / "pyproject.toml").symlink_to("elsewhere.toml")
    else:
        _write(root / "pyproject.toml", "[invalid\n")
    _git(root, "init", "-q")
    _git(root, "add", "pyproject.toml")
    _git(
        root,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-qm",
        "invalid base policy",
    )
    monkeypatch.delenv("SKYLOS_CONFIG_FILE", raising=False)
    with base_policy_context(root, "HEAD"), pytest.raises(ConfigError):
        load_config(root)


@pytest.fixture
def cli_environment():
    source = str(Path(__file__).resolve().parents[1])
    env = {
        key: os.environ[key]
        for key in ("PATH", "HOME", "TMPDIR", "LANG")
        if key in os.environ
    }
    env.update(PYTHONPATH=source, SKYLOS_NO_TELEMETRY="1", SKYLOS_JOBS="1")
    for name in (
        "SKYLOS_DIFF_BASE",
        "SKYLOS_CONFIG_FILE",
        "SKYLOS_POLICY_BASE",
        "GITHUB_BASE_REF",
    ):
        env.pop(name, None)
    return env


def _cli(root, args, env):
    command = str(Path(sys.executable).with_name("skylos"))
    return subprocess.run(
        [command, *args],
        cwd=root,
        env=env,
        text=True,
        capture_output=True,
    )


def _blocked(result):
    assert result.returncode == 1, result.stdout + result.stderr
    assert "SKY-L021" in result.stdout


def test_actual_public_direct_gate_blocks_auth_removal(
    removed_auth_repo, cli_environment
):
    _blocked(
        _cli(
            removed_auth_repo,
            ["cicd", "gate", ".", "--diff-base", "base"],
            cli_environment,
        )
    )


def test_actual_public_diff_report_retains_auth_loss(
    removed_auth_repo, tmp_path, cli_environment
):
    cli_environment["SKYLOS_POLICY_BASE"] = resolve_policy_base(
        removed_auth_repo, "base"
    )
    report = tmp_path / "results.json"
    scan = _cli(
        removed_auth_repo,
        [
            ".",
            "--danger",
            "--quality",
            "--diff-base",
            "base",
            "--diff",
            "base",
            "--no-upload",
            "--format",
            "json",
            "-o",
            str(report),
        ],
        cli_environment,
    )
    assert scan.returncode == 0, scan.stdout + scan.stderr
    result = json.loads(report.read_text())
    assert any(item["rule_id"] == "SKY-L021" for item in result["quality"])
    _blocked(
        _cli(
            removed_auth_repo,
            ["cicd", "gate", "--input", str(report), "--diff-base", "base"],
            cli_environment,
        )
    )


@pytest.mark.parametrize("automatic", [False, True])
def test_actual_input_gate_rechecks_omitted_auth_loss(
    removed_auth_repo, tmp_path, cli_environment, automatic
):
    report = tmp_path / "omitted.json"
    _write(
        report,
        json.dumps(
            {"project_root": str(removed_auth_repo), "quality": [], "danger": []}
        ),
    )
    comparison = [] if automatic else ["--diff-base", "base"]
    if automatic:
        cli_environment["GITHUB_BASE_REF"] = "main"
    _blocked(
        _cli(
            removed_auth_repo,
            ["cicd", "gate", ".", "--input", str(report), *comparison],
            cli_environment,
        )
    )


def test_actual_input_gate_rejects_unavailable_auto_base(
    removed_auth_repo, tmp_path, cli_environment
):
    report = tmp_path / "omitted.json"
    _write(report, json.dumps({"quality": [], "danger": []}))
    cli_environment["GITHUB_BASE_REF"] = "missing-base"
    result = _cli(
        removed_auth_repo,
        ["cicd", "gate", ".", "--input", str(report)],
        cli_environment,
    )
    assert result.returncode == 1
    assert "Could not resolve PR policy base" in result.stdout


@pytest.mark.parametrize("flag", ["--diff", "--diff-base"])
def test_actual_plain_compared_gate_uses_base_policy(
    removed_auth_repo, tmp_path, cli_environment, flag
):
    report = tmp_path / "results.json"
    result = _cli(
        removed_auth_repo,
        [
            ".",
            flag,
            "base",
            "--gate",
            "--no-upload",
            "--format",
            "json",
            "-o",
            str(report),
        ],
        cli_environment,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert any(
        item["rule_id"] == "SKY-L021"
        for item in json.loads(report.read_text())["quality"]
    )


@pytest.fixture
def rename_auth_repo(tmp_path):
    root = tmp_path / "rename-repo"
    root.mkdir()
    _write(root / "views.py", PROTECTED)
    _write(
        root / "pyproject.toml", "[tool.skylos.gate]\nmax_high=999\nmax_quality=999\n"
    )
    _git(root, "init", "-q")
    _git(root, "add", "views.py", "pyproject.toml")
    _git(
        root,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-qm",
        "protected base",
    )
    _git(root, "tag", "base")
    return root


@pytest.mark.parametrize(
    "destination, retained",
    [
        ("handlers.py", False),
        ("tests/test_handlers.py", False),
        (".venv/handlers.py", False),
        ("handlers.py", True),
        (None, False),
    ],
)
def test_actual_file_rename_retains_control_history(
    rename_auth_repo, tmp_path, cli_environment, destination, retained
):
    root = rename_auth_repo
    if destination:
        target = root / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        _git(root, "mv", "views.py", destination)
        _write(target, PROTECTED if retained else OPEN)
    else:
        _git(root, "rm", "views.py")
    report = tmp_path / "omitted.json"
    _write(report, json.dumps({"project_root": str(root), "quality": [], "danger": []}))
    expected = 0 if retained or destination is None else 1
    commands = [
        ["cicd", "gate", ".", "--diff-base", "base"],
        ["cicd", "gate", ".", "--diff-base", "base", "--input", str(report)],
        [".", "--gate", "--diff", "base", "--no-upload", "--format", "json"],
    ]
    for args in commands:
        result = _cli(root, args, cli_environment)
        assert result.returncode == expected, result.stdout + result.stderr
        if expected:
            assert "SKY-L021" in result.stdout
            assert destination in result.stdout


@pytest.mark.parametrize("raises", [False, True])
def test_public_scan_restores_diff_environment_between_calls(
    removed_auth_repo, monkeypatch, raises
):
    from skylos import cli
    from skylos.commands import scan_cmd

    monkeypatch.delenv("SKYLOS_DIFF_BASE", raising=False)
    seen = []

    def run(argv, *, cli_module, parser, args):
        seen.append(os.environ.get("SKYLOS_DIFF_BASE"))
        if args.diff:
            os.environ["SKYLOS_DIFF_BASE"] = args.diff
            if raises:
                raise SystemExit(1)

    monkeypatch.setattr(scan_cmd, "_run_scan_command", run)
    first = [str(removed_auth_repo), "--diff", "base", "--gate", "--no-upload"]
    if raises:
        with pytest.raises(SystemExit):
            scan_cmd.run_scan_command(first, cli_module=cli)
    else:
        scan_cmd.run_scan_command(first, cli_module=cli)
    scan_cmd.run_scan_command([str(removed_auth_repo), "--no-upload"], cli_module=cli)
    assert seen == [None, None]
    assert "SKYLOS_DIFF_BASE" not in os.environ
