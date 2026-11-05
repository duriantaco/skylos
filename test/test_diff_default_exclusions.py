"""PR changes must survive automatic exclusions through the public CI gate."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from test.test_auth_removal_gate import OPEN, PROTECTED


UNSAFE = (
    "import pickle\n\ndef handler(request):\n    return pickle.loads(request.body)\n"
)
SAFE = "def handler(request):\n    return request.body\n"
SOURCE_ROOT = Path(__file__).resolve().parents[1]


def _git(root, *args):
    return subprocess.run(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.name=Skylos Tests",
            "-c",
            "user.email=skylos-tests@example.invalid",
            *args,
        ],
        cwd=root,
        text=True,
        capture_output=True,
        check=True,
        timeout=30,
    ).stdout.strip()


@pytest.fixture
def cli_environment():
    env = {
        name: os.environ[name]
        for name in ("PATH", "HOME", "TMPDIR", "LANG")
        if name in os.environ
    }
    env.update(
        PYTHONPATH=str(SOURCE_ROOT),
        SKYLOS_NO_TELEMETRY="1",
        SKYLOS_JOBS="1",
        GIT_CONFIG_GLOBAL="/dev/null",
        GIT_CONFIG_NOSYSTEM="1",
    )
    return env


def _repo(
    tmp_path,
    relative,
    *,
    modified=False,
    source=UNSAFE,
    baseline_source=SAFE,
    exclude=None,
    config_extra="",
):
    root = (tmp_path / "repo").resolve()
    root.mkdir()
    config = '[project]\nname="diff-scope-fixture"\nversion="0.1.0"\n'
    if exclude is not None:
        config += f"\n[tool.skylos]\nexclude={json.dumps([exclude])}\n"
    config += config_extra
    (root / "pyproject.toml").write_text(config, encoding="utf-8")
    (root / "main.py").write_text("value = 1\nprint(value)\n", encoding="utf-8")

    # These unchanged dependencies must remain pruned even when a nearby
    # changed file is rescued from an automatic directory exclusion.
    untouched = root / "vendor" / "unchanged.py"
    untouched.parent.mkdir()
    untouched.write_text(UNSAFE, encoding="utf-8")
    target = root / relative
    if modified:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(baseline_source, encoding="utf-8")
    _git(root, "init", "-q", "-b", "main")
    base_files = ["pyproject.toml", "main.py", "vendor/unchanged.py"]
    if modified:
        base_files.append(relative)
    _git(root, "add", "--", *base_files)
    _git(root, "commit", "-qm", "trusted baseline")
    _git(root, "tag", "scope-base")
    _git(root, "update-ref", "refs/remotes/origin/main", "HEAD")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    _git(root, "add", "--", relative)
    _git(root, "commit", "-qm", "change source")
    return root, target


def _cli(root, args, env, *, pypi_missing=False):
    program = "from skylos.cli import main; main()"
    if pypi_missing:
        program = (
            "from skylos.rules.ai_defect import dependency_hallucination as deps; "
            "deps._check_pypi_status = lambda _name, _cache: 'missing'; " + program
        )
    return subprocess.run(
        [sys.executable, "-c", program, *args],
        cwd=root,
        env=env,
        text=True,
        capture_output=True,
        timeout=90,
    )


def _scan(root, tmp_path, env, *, mode="combined", extra=(), pypi_missing=False):
    env = dict(env, SKYLOS_POLICY_BASE=_git(root, "rev-parse", "scope-base"))
    report = tmp_path / "results.json"
    flags = {
        "combined": ["--diff-base", "scope-base", "--diff", "scope-base"],
        "diff": ["--diff", "scope-base"],
        "changed": ["--diff-base", "scope-base"],
        "full": [],
    }[mode]
    scan = _cli(
        root,
        [
            ".",
            "--danger",
            "--baseline",
            *flags,
            "--no-upload",
            "--format",
            "json",
            "-o",
            str(report),
            *extra,
        ],
        env,
        pypi_missing=pypi_missing,
    )
    assert scan.returncode == 0, scan.stdout + scan.stderr
    result = json.loads(report.read_text(encoding="utf-8"))
    assert not result.get("analysis_errors"), result.get("analysis_errors")
    return result, report, env


def _critical_identities(result):
    return {
        (item["rule_id"], str(Path(item["file"]).resolve()), item["line"])
        for item in result.get("danger", [])
        if item.get("severity") == "CRITICAL"
    }


def _gate(root, report, env):
    return _cli(
        root,
        [
            "cicd",
            "gate",
            ".",
            "--input",
            str(report),
            "--diff-base",
            "scope-base",
            "--summary",
        ],
        env,
    )


@pytest.mark.parametrize("mode", ["diff", "combined", "changed"])
@pytest.mark.parametrize("modified", [False, True], ids=["added", "modified"])
@pytest.mark.parametrize(
    "relative",
    ["src/views.py", "vendor/views.py", "src/shop/vendor/views.py", "dist/views.py"],
    ids=["ordinary", "root-vendor", "nested-vendor", "dist"],
)
def test_changed_findings_survive_default_exclusions_and_block_gate(
    tmp_path, cli_environment, mode, modified, relative
):
    root, target = _repo(tmp_path, relative, modified=modified)
    result, report, env = _scan(root, tmp_path, cli_environment, mode=mode)

    assert _critical_identities(result) == {("SKY-D205", str(target), 4)}
    assert result["analysis_summary"]["total_files"] == 2
    gate = _gate(root, report, env)
    assert gate.returncode == 1, gate.stdout + gate.stderr
    assert "SKY-D205" in gate.stdout


@pytest.mark.parametrize("mode", ["diff", "combined", "changed"])
def test_safe_changed_file_under_default_exclusion_still_passes(
    tmp_path, cli_environment, mode
):
    root, _ = _repo(tmp_path, "src/shop/vendor/views.py", source=SAFE)
    result, report, env = _scan(root, tmp_path, cli_environment, mode=mode)

    assert _critical_identities(result) == set()
    assert result["analysis_summary"]["total_files"] == 2
    gate = _gate(root, report, env)
    assert gate.returncode == 0, gate.stdout + gate.stderr


@pytest.mark.parametrize("mode", ["diff", "combined", "changed"])
@pytest.mark.parametrize("policy", ["config", "cli"])
def test_explicit_exclusions_still_control_changed_scan_scope(
    tmp_path, cli_environment, mode, policy
):
    root, _ = _repo(
        tmp_path,
        "src/shop/vendor/views.py",
        exclude="vendor" if policy == "config" else None,
    )
    result, report, env = _scan(
        root,
        tmp_path,
        cli_environment,
        mode=mode,
        extra=["--exclude-folder", "vendor"] if policy == "cli" else [],
    )

    assert _critical_identities(result) == set()
    assert result["analysis_summary"]["total_files"] == 1
    gate = _gate(root, report, env)
    assert gate.returncode == 0, gate.stdout + gate.stderr


def test_full_scan_keeps_default_exclusions(tmp_path, cli_environment):
    root, _ = _repo(tmp_path, "src/shop/vendor/views.py")
    result, _, _ = _scan(root, tmp_path, cli_environment, mode="full")

    assert _critical_identities(result) == set()
    assert result["analysis_summary"]["total_files"] == 1


@pytest.mark.parametrize("mode", ["diff", "combined", "changed"])
def test_head_config_cannot_authorize_a_new_exclusion(tmp_path, cli_environment, mode):
    root, target = _repo(tmp_path, "src/shop/vendor/views.py")
    config = root / "pyproject.toml"
    config.write_text(
        config.read_text(encoding="utf-8") + '\n[tool.skylos]\nexclude=["vendor"]\n',
        encoding="utf-8",
    )
    _git(root, "add", "--", "pyproject.toml")
    _git(root, "commit", "-qm", "attempt to exclude source in head policy")

    result, report, env = _scan(root, tmp_path, cli_environment, mode=mode)

    assert _critical_identities(result) == {("SKY-D205", str(target), 4)}
    gate = _gate(root, report, env)
    assert gate.returncode == 1, gate.stdout + gate.stderr


@pytest.mark.parametrize(
    "relative, generated",
    [
        ("src/refunds.py", False),
        ("vendor/refunds.py", False),
        ("src/shop/vendor/refunds.py", False),
        ("src/shop/vendor/refunds.py", True),
    ],
    ids=["ordinary", "root-vendor", "nested-vendor", "generated-nested-vendor"],
)
def test_hallucinated_import_survives_diff_scope_and_blocks_gate(
    tmp_path, cli_environment, relative, generated
):
    source = (
        "import invented_payment_sdk\n\n"
        "def refund(amount):\n"
        "    return invented_payment_sdk.refund(amount)\n"
    )
    if generated:
        source = "# @generated\n" + source
    root, target = _repo(tmp_path, relative, source=source)
    result, report, env = _scan(
        root,
        tmp_path,
        cli_environment,
        extra=["--ai-defects"],
        pypi_missing=True,
    )

    hallucinations = {
        (item["rule_id"], str(Path(item["file"]).resolve()), item["line"])
        for item in result.get("ai_defects", [])
        if item.get("rule_id") == "SKY-D222"
    }
    assert hallucinations == {("SKY-D222", str(target), 2 if generated else 1)}
    gate = _gate(root, report, env)
    assert gate.returncode == 1, gate.stdout + gate.stderr
    assert "SKY-D222" in gate.stdout


def test_direct_cicd_gate_analyzes_changed_default_excluded_file(
    tmp_path, cli_environment
):
    root, _ = _repo(tmp_path, "src/shop/vendor/views.py")

    gate = _cli(
        root,
        ["cicd", "gate", ".", "--diff-base", "origin/main", "--summary"],
        cli_environment,
    )

    assert gate.returncode == 1, gate.stdout + gate.stderr
    assert "SKY-D205" in gate.stdout


def test_auth_removal_under_default_excluded_folder_still_blocks_gate(
    tmp_path, cli_environment
):
    root, target = _repo(
        tmp_path,
        "src/shop/vendor/views.py",
        modified=True,
        baseline_source=PROTECTED,
        source=OPEN,
        config_extra="\n[tool.skylos.gate]\nmax_high=0\nmax_quality=0\n",
    )
    result, report, env = _scan(root, tmp_path, cli_environment, extra=["--quality"])

    regressions = {
        (item["rule_id"], str(Path(item["file"]).resolve()), item["line"])
        for item in result.get("quality", [])
        if item.get("rule_id") == "SKY-L021"
    }
    assert regressions == {("SKY-L021", str(target), 4)}
    gate = _gate(root, report, env)
    assert gate.returncode == 1, gate.stdout + gate.stderr
    assert "SKY-L021" in gate.stdout
