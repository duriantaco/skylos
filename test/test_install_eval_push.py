"""Contracts for push-only setup and immutable, reviewed gate bundles."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="local Git push gate is POSIX-only"
)
SCRIPT = Path(__file__).resolve().parents[1] / "scripts/install_eval_push.py"
SPEC = importlib.util.spec_from_file_location("_install_eval_push_test", SCRIPT)
installer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = installer
SPEC.loader.exec_module(installer)


def _git(repo, *args, check=True):
    return subprocess.run(
        ["git", "-C", str(repo), *args], text=True, capture_output=True, check=check
    )


@pytest.fixture
def checkout(tmp_path):
    repo = tmp_path / "repo with spaces"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Eval Setup Tests")
    _git(repo, "config", "user.email", "eval@example.invalid")
    _git(repo, "checkout", "-qb", "feature/evals")
    for relative in installer.RUNTIME_FILES:
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# trusted runtime fixture\n")
    # This gate fixture records what the executable wrapper actually passes.
    (repo / "scripts/eval_pre_push.py").write_text(
        "import json,os,sys\nfrom pathlib import Path\n"
        "record={'argv':sys.argv[1:],'stdin':sys.stdin.read(),'cwd':os.getcwd()}\n"
        "Path('.gate-run.json').write_text(json.dumps(record))\n"
    )
    for suite, ids in installer.CASE_IDS.items():
        manifest = repo / "benchmarks" / suite / "manifest.json"
        cases = []
        for case_id in (*ids, "unselected-case"):
            fixture = manifest.parent / "fixtures" / case_id
            fixture.mkdir(parents=True)
            (fixture / "app.py").write_text(f"value = {case_id!r}\n")
            cases.append(
                {
                    "id": case_id,
                    "path": f"fixtures/{case_id}",
                    "expect": {"present": {"danger": ["SKY-D216"]}, "absent": {}},
                }
            )
        manifest.write_text(json.dumps({"version": 1, "cases": cases}))
    return repo


def _install(repo, **kwargs):
    return installer.install_push(repo, Path(sys.executable), source=repo, **kwargs)


def _run_hook(repo, report, data=b"refs/heads/feature a refs/heads/feature b\n", *args):
    return subprocess.run(
        [report["hook_path"], *(args or ("origin", "remote with spaces"))],
        cwd=repo,
        input=data,
        capture_output=True,
    )


def test_installs_only_git_hook_and_pins_reviewed_subset(checkout):
    report = _install(checkout)
    assert Path(report["hook_path"]).stat().st_mode & 0o111
    assert report["native_agent_callbacks_installed"] is False
    assert not (checkout / ".codex/hooks.json").exists()
    assert not (checkout / ".claude/settings.local.json").exists()
    bundle = Path(report["bundle"])
    for suite, ids in installer.CASE_IDS.items():
        manifest = json.loads(
            (bundle / "benchmarks" / suite / "manifest.json").read_text()
        )
        assert [case["id"] for case in manifest["cases"]] == list(ids)
        assert not (bundle / "benchmarks" / suite / "fixtures/unselected-case").exists()
    assert _git(checkout, "check-ignore", str(bundle)).returncode == 0
    assert _run_hook(checkout, report).returncode == 0


def test_existing_hook_gets_exact_stdin_args_cwd_and_dir_helpers(checkout):
    hook = checkout / ".git/hooks/pre-push"
    helper = hook.parent / "helper.txt"
    helper.write_text("sibling helper")
    hook.write_text(
        '#!/bin/sh\ncat > .prior-input\nprintf \'%s\\n\' "$1" "$2" > .prior-args\n'
        'pwd > .prior-cwd\ncat "$(dirname "$0")/helper.txt" > .prior-helper\n'
    )
    hook.chmod(0o755)
    before = hook.read_bytes()
    report = _install(checkout)
    data = b"first complete update\nsecond complete update\n"
    result = _run_hook(checkout, report, data)
    assert result.returncode == 0, result.stderr
    assert (checkout / ".prior-input").read_bytes() == data
    assert (checkout / ".prior-args").read_text() == "origin\nremote with spaces\n"
    assert (
        Path((checkout / ".prior-cwd").read_text().strip()).resolve()
        == checkout.resolve()
    )
    assert (checkout / ".prior-helper").read_text() == "sibling helper"
    gate = json.loads((checkout / ".gate-run.json").read_text())
    assert gate["stdin"].encode() == data
    assert gate["argv"] == [
        "--repo",
        str(checkout),
        "--",
        "origin",
        "remote with spaces",
    ]
    assert (Path(report["backup_directory"]) / "pre-push.before").read_bytes() == before


def test_prior_failure_still_blocks_before_ours(checkout):
    hook = checkout / ".git/hooks/pre-push"
    hook.write_text("#!/bin/sh\ncat > .prior-input\nexit 23\n")
    hook.chmod(0o755)
    report = _install(checkout)
    assert _run_hook(checkout, report, b"all updates\n").returncode == 23
    assert (checkout / ".prior-input").read_bytes() == b"all updates\n"
    assert not (checkout / ".gate-run.json").exists()


def test_nonexecutable_prior_is_preserved_without_becoming_active(checkout):
    hook = checkout / ".git/hooks/pre-push"
    hook.write_text("#!/bin/sh\nexit 23\n")
    hook.chmod(0o644)
    report = _install(checkout)
    assert report["chains_existing_hook"] is False
    assert _run_hook(checkout, report).returncode == 0


def test_pinned_bundle_survives_other_agents_uncommitted_source_edits(checkout):
    report = _install(checkout)
    (checkout / "scripts/eval_pre_push.py").write_text("invalid Python !!!\n")
    (checkout / "skylos/benchmarks/security.py").write_text("invalid grader !!!\n")
    (checkout / "benchmarks/security/fixtures/ssrf-tainted-host/app.py").write_text(
        "changed WIP\n"
    )
    result = _run_hook(checkout, report)
    assert result.returncode == 0, result.stderr
    assert (checkout / ".gate-run.json").exists()
    assert (
        Path(report["bundle"]) / "benchmarks/security/fixtures/ssrf-tainted-host/app.py"
    ).read_text() != "changed WIP\n"


def test_modified_bundle_blocks_instead_of_running_mutable_code(checkout):
    report = _install(checkout)
    entry = Path(report["bundle"]) / "scripts/eval_pre_push.py"
    entry.chmod(0o600)
    entry.write_text("raise SystemExit(0)\n")
    assert _run_hook(checkout, report).returncode != 0
    assert not (checkout / ".gate-run.json").exists()
    with pytest.raises(ValueError, match="bundle was modified"):
        _install(checkout)


def test_reinstall_is_idempotent_and_refresh_does_not_chain_ours(checkout):
    first = _install(checkout)
    second = _install(checkout)
    assert not second["changed"] and not second["exclude_changed"]
    assert second["backup_directory"] is None
    (checkout / "skylos/benchmarks/security.py").write_text(
        "# reviewed grader update\n"
    )
    third = _install(checkout)
    assert third["changed"] and third["bundle_id"] != first["bundle_id"]
    assert third["chains_existing_hook"] is False
    assert _run_hook(checkout, third).returncode == 0


def test_shared_global_hookspath_refuses_without_mutations(checkout, tmp_path):
    shared = tmp_path / "shared-hooks"
    shared.mkdir()
    hook = shared / "pre-push"
    hook.write_text("keep global bytes")
    _git(checkout, "config", "core.hooksPath", str(shared))
    exclude = checkout / ".git/info/exclude"
    before = exclude.read_bytes()
    with pytest.raises(ValueError, match="shared/global"):
        _install(checkout)
    assert hook.read_text() == "keep global bytes"
    assert exclude.read_bytes() == before
    assert not (checkout / ".skylos").exists()


def test_dry_run_ignores_parent_git_repository_overrides(
    checkout, tmp_path, monkeypatch
):
    victim = tmp_path / "other-repository"
    victim.mkdir()
    _git(victim, "init", "-q")
    before = (victim / ".git/info/exclude").read_bytes()
    monkeypatch.setenv("GIT_DIR", str(victim / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(checkout))
    monkeypatch.setenv("GIT_INDEX_FILE", str(victim / ".git/index"))
    report = _install(checkout, dry_run=True)
    assert Path(report["hook_path"]) == checkout / ".git/hooks/pre-push"
    assert (victim / ".git/info/exclude").read_bytes() == before
    assert not (victim / ".git/hooks/pre-push").exists()
    assert not (checkout / ".git/hooks/pre-push").exists()
    assert not (checkout / ".skylos").exists()


def test_global_hookspath_is_still_discovered_after_environment_scrubbing(
    checkout, tmp_path, monkeypatch
):
    shared = tmp_path / "global-hooks"
    shared.mkdir()
    global_config = tmp_path / "isolated-global-config"
    global_config.write_text(f'[core]\n\thooksPath = "{shared}"\n')
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))
    with pytest.raises(ValueError, match="shared/global"):
        _install(checkout, dry_run=True)
    assert not (checkout / ".skylos").exists()


def test_project_local_hooks_path_is_honoured_and_ignored(checkout):
    _git(checkout, "config", "core.hooksPath", ".project-hooks")
    report = _install(checkout)
    assert Path(report["hook_path"]) == checkout / ".project-hooks/pre-push"
    assert _git(checkout, "check-ignore", ".project-hooks/pre-push").returncode == 0
    assert _run_hook(checkout, report).returncode == 0


def test_tracked_project_hook_is_not_overwritten(checkout):
    path = checkout / ".project-hooks/pre-push"
    path.parent.mkdir()
    path.write_text("versioned hook")
    _git(checkout, "add", ".project-hooks/pre-push")
    _git(checkout, "config", "core.hooksPath", ".project-hooks")
    before = (checkout / ".git/info/exclude").read_bytes()
    with pytest.raises(ValueError, match="Git-tracked"):
        _install(checkout)
    assert path.read_text() == "versioned hook"
    assert (checkout / ".git/info/exclude").read_bytes() == before


@pytest.mark.parametrize("symlink", [False, True])
def test_readonly_or_symlink_existing_hook_is_refused(checkout, tmp_path, symlink):
    hook = checkout / ".git/hooks/pre-push"
    if symlink:
        other = tmp_path / "other"
        other.write_text("keep")
        hook.symlink_to(other)
    else:
        hook.write_text("keep")
        hook.chmod(0o444)
    with pytest.raises((ValueError, PermissionError)):
        _install(checkout)
    assert hook.read_text() == "keep"
    assert not (checkout / ".skylos").exists()


@pytest.mark.parametrize("variant", ["missing-case", "escape", "symlink"])
def test_untrusted_or_missing_selected_fixtures_refuse(checkout, tmp_path, variant):
    manifest = checkout / "benchmarks/security/manifest.json"
    data = json.loads(manifest.read_text())
    if variant == "missing-case":
        data["cases"] = data["cases"][1:]
    elif variant == "escape":
        data["cases"][0]["path"] = "../../outside"
    else:
        outside = tmp_path / "outside.py"
        outside.write_text("private source")
        (
            checkout / "benchmarks/security/fixtures/ssrf-tainted-host/leak.py"
        ).symlink_to(outside)
    manifest.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        _install(checkout)
    assert not (checkout / ".git/hooks/pre-push").exists()


def test_dry_run_makes_no_hook_bundle_or_exclusion_changes(checkout):
    exclude = checkout / ".git/info/exclude"
    before = exclude.read_bytes()
    report = _install(checkout, dry_run=True)
    assert report["changed"] and report["dry_run"]
    assert exclude.read_bytes() == before
    assert not Path(report["hook_path"]).exists()
    assert not Path(report["bundle"]).exists()


def test_venv_python_with_spaces_remains_executable_in_actual_hook(checkout):
    python = checkout / "venv with spaces/bin/python"
    python.parent.mkdir(parents=True)
    python.symlink_to(sys.executable)
    report = installer.install_push(checkout, python, source=checkout)
    result = _run_hook(checkout, report)
    assert result.returncode == 0, result.stderr


def test_existing_configuration_change_is_not_overwritten(checkout):
    report = _install(checkout)
    hook = Path(report["hook_path"])
    hook.write_text("#!/bin/sh\n# user replacement\n")
    with pytest.raises(ValueError, match="changed since"):
        _install(checkout)
    assert "user replacement" in hook.read_text()


def test_actual_local_git_push_replays_stdin_to_prior_and_pinned_gate(
    checkout, tmp_path
):
    _git(checkout, "add", "scripts", "skylos", "benchmarks")
    _git(checkout, "commit", "-qm", "trusted fixture")
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)
    _git(checkout, "remote", "add", "origin", str(remote))
    hook = checkout / ".git/hooks/pre-push"
    hook.write_text("#!/bin/sh\ncat > .prior-input\n")
    hook.chmod(0o755)
    _install(checkout)
    result = _git(
        checkout, "push", "origin", "HEAD:refs/heads/feature/evals", check=False
    )
    assert result.returncode == 0, result.stderr
    prior = (checkout / ".prior-input").read_text()
    gate = json.loads((checkout / ".gate-run.json").read_text())
    assert gate["stdin"] == prior
    fields = prior.strip().split()
    assert fields[0] == "HEAD" and fields[2] == "refs/heads/feature/evals"
    assert fields[1] == _git(checkout, "rev-parse", "HEAD").stdout.strip()
    assert gate["cwd"] == str(checkout)


def test_unsupported_platform_refuses_before_mutation(checkout, monkeypatch):
    monkeypatch.setattr(installer, "os", SimpleNamespace(name="nt"))
    with pytest.raises(ValueError, match="macOS/Linux"):
        _install(checkout)
    assert not (checkout / ".skylos").exists()


def test_concurrent_hook_replacement_is_preserved(checkout, monkeypatch):
    hook = checkout / ".git/hooks/pre-push"
    hook.write_text("#!/bin/sh\n# original hook\n")
    hook.chmod(0o755)
    actual = installer._atomic_write

    def racing_write(path, content, expected, mode):
        if path == hook:
            hook.write_text("#!/bin/sh\n# concurrent user replacement\n")
        return actual(path, content, expected, mode)

    monkeypatch.setattr(installer, "_atomic_write", racing_write)
    with pytest.raises(ValueError, match="changed concurrently"):
        _install(checkout)
    assert "concurrent user replacement" in hook.read_text()


def test_metadata_failure_restores_the_prior_hook(checkout, monkeypatch):
    hook = checkout / ".git/hooks/pre-push"
    original = b"#!/bin/sh\n# keep this exact hook\n"
    hook.write_bytes(original)
    hook.chmod(0o750)
    actual = installer._atomic_write

    def fail_metadata(path, content, expected, mode):
        if path.parent.name == "skylos-evals":
            raise OSError("synthetic metadata write failure")
        return actual(path, content, expected, mode)

    monkeypatch.setattr(installer, "_atomic_write", fail_metadata)
    with pytest.raises(OSError, match="synthetic metadata"):
        _install(checkout)
    assert hook.read_bytes() == original
    assert hook.stat().st_mode & 0o777 == 0o750


def test_shared_git_hook_uses_actual_linked_worktree_cwd(checkout, tmp_path):
    _git(checkout, "add", "scripts", "skylos", "benchmarks")
    _git(checkout, "commit", "-qm", "trusted fixture")
    report = _install(checkout)
    linked = tmp_path / "linked worktree"
    _git(checkout, "worktree", "add", "-qb", "feature/linked", str(linked))
    data = b"refs/heads/feature/linked a refs/heads/feature/linked b\n"
    result = subprocess.run(
        [report["hook_path"], "origin", "remote"],
        cwd=linked,
        input=data,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    assert not (checkout / ".gate-run.json").exists()
    observed = json.loads((linked / ".gate-run.json").read_text())
    assert observed["argv"][:2] == ["--repo", str(linked)]
    assert observed["cwd"] == str(linked) and observed["stdin"].encode() == data


def test_existing_main_push_guard_is_preserved_in_real_local_push(checkout, tmp_path):
    _git(checkout, "add", "scripts", "skylos", "benchmarks")
    _git(checkout, "commit", "-qm", "trusted fixture")
    remote = tmp_path / "guarded-remote.git"
    subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)
    _git(checkout, "remote", "add", "origin", str(remote))
    hook = checkout / ".git/hooks/pre-push"
    hook.write_text(
        "#!/bin/sh\nwhile read local_ref local_sha remote_ref remote_sha; do\n"
        '  case "$remote_ref" in refs/heads/main|refs/heads/master) exit 41;; esac\n'
        "done\n"
    )
    hook.chmod(0o755)
    _install(checkout)
    result = _git(checkout, "push", "origin", "HEAD:refs/heads/main", check=False)
    assert result.returncode != 0
    assert not (checkout / ".gate-run.json").exists()
    refs = subprocess.run(
        ["git", "--git-dir", str(remote), "show-ref"], text=True, capture_output=True
    )
    assert not refs.stdout


def test_real_installed_bundle_push_runs_complete_grader_dependency_closure(tmp_path):
    # Exercise the actual installed entry/controller/worker, not a stub gate. A
    # missing transitive grader dependency must fail this integration contract.
    source = SCRIPT.parent.parent
    with tempfile.TemporaryDirectory(prefix="real-bundle-", dir=tmp_path) as directory:
        repo = Path(directory) / "candidate"
        repo.mkdir()
        _git(repo, "init", "-q")
        _git(repo, "config", "user.name", "Pinned Bundle Tests")
        _git(repo, "config", "user.email", "eval@example.invalid")
        _git(repo, "checkout", "-qb", "feature/bundle")
        shutil.copytree(
            source / "skylos",
            repo / "skylos",
            ignore=shutil.ignore_patterns(
                "benchmarks", "__pycache__", "*.pyc", "skylos-go"
            ),
        )
        # Candidate commits need neither evaluation code nor candidate-provided
        # expected answers. Those must come from the independently pinned bundle.
        (repo / "skylos/benchmarks").mkdir()
        (repo / "skylos/benchmarks/__init__.py").write_text("")
        _git(repo, "add", "skylos")
        _git(repo, "commit", "-qm", "real committed analyzer without eval harness")
        commit = _git(repo, "rev-parse", "HEAD").stdout.strip()
        remote = Path(directory) / "local-only.git"
        subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)
        _git(repo, "remote", "add", "origin", str(remote))
        prior = repo / ".git/hooks/pre-push"
        prior.write_text("#!/bin/sh\ncat > .prior-input\n")
        prior.chmod(0o755)
        report = installer.install_push(repo, Path(sys.executable), source=source)
        result = _git(
            repo, "push", "origin", "HEAD:refs/heads/feature/bundle", check=False
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "Skylos pre-push: PASS" in result.stdout
        records = list((repo / ".skylos/evals/pre-push/runs").glob("*/*/receipt.json"))
        assert len(records) == 1
        receipt = json.loads(records[0].read_text())
        assert receipt["commit"] == commit and receipt["passed"] is True
        assert receipt["worker"]["passed"] is True
        assert (
            sum(len(suite["results"]) for suite in receipt["worker"]["cases"].values())
            == 3
        )
        assert all(suite["passed"] for suite in receipt["worker"]["cases"].values())
        assert (repo / ".prior-input").read_text().split()[1] == commit
        assert not (repo / "benchmarks").exists()
        assert Path(report["bundle"]).is_dir()
