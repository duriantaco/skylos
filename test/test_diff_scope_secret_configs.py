"""Changed config secrets under automatic excludes still reach the PR gate."""

import json
from pathlib import Path

import pytest

from test.test_diff_default_exclusions import (
    _cli,
    _gate,
    _git,
    _scan,
    cli_environment as cli_environment,
)


# The same synthetic provider fixture used by the existing secret shape tests.
TOKEN = "ghp_" + "Zx8Kq2Lm9Pq4Rs7Tv1Wx6Ya3Bc5De0Fg2HjK"


def _repo(tmp_path, relative, source, *, exclude=None):
    root = (tmp_path / "repo").resolve()
    root.mkdir()
    config = '[project]\nname="diff-config-fixture"\nversion="0.1.0"\n'
    if exclude is not None:
        config += f"\n[tool.skylos]\nexclude={json.dumps([exclude])}\n"
    (root / "pyproject.toml").write_text(config, encoding="utf-8")
    (root / "main.py").write_text("value = 1\nprint(value)\n", encoding="utf-8")
    vendor = root / "vendor"
    vendor.mkdir()
    (vendor / "unchanged.env").write_text(f"API_KEY={TOKEN}\n", encoding="utf-8")
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "--", "main.py", "pyproject.toml", "vendor/unchanged.env")
    _git(root, "commit", "-qm", "trusted baseline with unchanged excluded config")
    _git(root, "tag", "scope-base")
    _git(root, "update-ref", "refs/remotes/origin/main", "HEAD")
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    _git(root, "add", "--", relative)
    _git(root, "commit", "-qm", "change config")
    return root, target


def _identities(result, root):
    return {
        (
            finding["rule_id"],
            str((root / Path(finding["file"])).resolve()),
            finding["line"],
            finding["severity"],
        )
        for finding in result.get("secrets", [])
    }


@pytest.mark.parametrize("mode", ["diff", "combined", "changed"])
@pytest.mark.parametrize(
    "relative,source",
    [
        ("vendor/.env", f"GITHUB_TOKEN={TOKEN}\n"),
        ("vendor/config.yaml", f"github_token: {TOKEN}\n"),
    ],
)
def test_changed_config_secret_survives_default_exclusion_and_blocks_gate(
    tmp_path, cli_environment, mode, relative, source
):
    root, target = _repo(tmp_path, relative, source)

    result, report, env = _scan(
        root,
        tmp_path,
        cli_environment,
        mode=mode,
        extra=["--secrets", "--no-grep-verify"],
    )

    assert _identities(result, root) == {("SKY-S101", str(target), 1, "CRITICAL")}
    # Config secrets use the bounded config scanner, not a source worker.
    assert result["analysis_summary"]["total_files"] == 1
    gate = _gate(root, report, env)
    assert gate.returncode == 1, gate.stdout + gate.stderr
    assert "secret" in (gate.stdout + gate.stderr).lower()


@pytest.mark.parametrize("mode", ["diff", "combined", "changed"])
def test_safe_changed_config_and_unchanged_excluded_secret_still_pass(
    tmp_path, cli_environment, mode
):
    root, _ = _repo(tmp_path, "vendor/.env", "API_KEY=${SERVICE_API_KEY}\n")

    result, report, env = _scan(
        root,
        tmp_path,
        cli_environment,
        mode=mode,
        extra=["--secrets", "--no-grep-verify"],
    )

    assert _identities(result, root) == set()
    assert result["analysis_summary"]["total_files"] == 1
    gate = _gate(root, report, env)
    assert gate.returncode == 0, gate.stdout + gate.stderr


def test_changed_config_outside_requested_directory_is_not_scanned(
    tmp_path, cli_environment
):
    root, _ = _repo(tmp_path, "vendor/.env", f"API_KEY={TOKEN}\n")
    report = tmp_path / "scoped-results.json"
    env = dict(
        cli_environment, SKYLOS_POLICY_BASE=_git(root, "rev-parse", "scope-base")
    )

    scan = _cli(
        root,
        [
            "main.py",
            "--secrets",
            "--diff-base",
            "scope-base",
            "--no-upload",
            "--format",
            "json",
            "-o",
            str(report),
        ],
        env,
    )

    assert scan.returncode == 0, scan.stdout + scan.stderr
    result = json.loads(report.read_text(encoding="utf-8"))
    assert _identities(result, root) == set()
    assert result["analysis_summary"]["total_files"] == 1


def test_trusted_explicit_config_exclusion_remains_authoritative(
    tmp_path, cli_environment
):
    root, _ = _repo(tmp_path, "vendor/.env", f"API_KEY={TOKEN}\n", exclude="vendor")

    result, report, env = _scan(
        root,
        tmp_path,
        cli_environment,
        extra=["--secrets", "--no-grep-verify"],
    )

    assert _identities(result, root) == set()
    assert result["analysis_summary"]["total_files"] == 1
    gate = _gate(root, report, env)
    assert gate.returncode == 0, gate.stdout + gate.stderr


def test_changed_env_secret_is_scanned_when_no_source_files_remain(
    tmp_path, cli_environment
):
    root, target = _repo(tmp_path, "vendor/.env", f"GITHUB_TOKEN={TOKEN}\n")
    (root / "main.py").unlink()
    _git(root, "add", "--", "main.py")
    _git(root, "commit", "-qm", "remove source so only config remains")

    result, report, env = _scan(
        root,
        tmp_path,
        cli_environment,
        extra=["--secrets", "--no-grep-verify"],
    )

    assert _identities(result, root) == {("SKY-S101", str(target), 1, "CRITICAL")}
    assert result["analysis_summary"]["total_files"] == 0
    gate = _gate(root, report, env)
    assert gate.returncode == 1, gate.stdout + gate.stderr
