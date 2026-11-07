"""Native secret-only text collection stays scoped, bounded, and low noise."""

import json
import os

import pytest

from skylos.analyzer import analyze
from test.fixture_paths import make_fixture_directory, write_fixture
from test.test_diff_default_exclusions import (
    _cli,
    _gate,
    _git,
    _scan as _cli_scan,
    cli_environment as cli_environment,
)


# Synthetic provider-shaped fixture; no credential is issued or validated.
TOKEN = "ghp_" + "Zx8Kq2Lm9Pq4Rs7Tv1Wx6Ya3Bc5De0Fg2HjK"
SECRET_TEXT_NAMES = (
    "index.html",
    "page.htm",
    "styles.css",
    "bundle.map",
    "README.md",
    "README.MD",
    "credentials.txt",
    "service.key",
    "service.pem",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "identity",
)


def _scan(target, **kwargs):
    return json.loads(
        analyze(str(target), enable_secrets=True, grep_verify=False, **kwargs)
    )


def _secret_locations(result):
    return {
        (finding["rule_id"], finding["file"], finding["line"])
        for finding in result.get("secrets", [])
    }


@pytest.mark.parametrize("name", SECRET_TEXT_NAMES)
@pytest.mark.parametrize("with_source", [False, True])
def test_native_collection_finds_provider_tokens_in_secret_only_text(
    tmp_path, name, with_source
):
    write_fixture(tmp_path, name, f"github_token: {TOKEN}\n")
    if with_source:
        write_fixture(tmp_path, "app.py", "print('ok')\n")

    result = _scan(tmp_path)

    assert _secret_locations(result) == {("SKY-S101", name, 1)}
    assert result["analysis_summary"]["analysis_error_count"] == 0
    # Documentation and key files must never enter a language parser.
    assert result["analysis_summary"]["total_files"] == int(with_source)
    assert result["analysis_summary"]["secrets_files_scanned"] == 1 + int(with_source)
    assert TOKEN not in json.dumps(result)


@pytest.mark.parametrize(
    "name", ["README.md", "credentials.txt", "service.key", "index.html"]
)
@pytest.mark.parametrize("empty", [False, True])
@pytest.mark.parametrize("explicit_file", [False, True])
def test_data_only_project_and_direct_file_are_checked_without_source_anchor(
    tmp_path, name, empty, explicit_file
):
    path = write_fixture(tmp_path, name, "" if empty else f"token: {TOKEN}\n")

    result = _scan(path if explicit_file else tmp_path)

    assert _secret_locations(result) == (set() if empty else {("SKY-S101", name, 1)})
    assert result["analysis_summary"]["total_files"] == 0
    assert result["analysis_summary"]["languages"] == {}
    assert result["analysis_summary"]["analysis_error_count"] == 0
    assert result["analysis_summary"]["secrets_files_scanned"] == 1
    assert result["analysis_errors"] == []


@pytest.mark.parametrize("empty", [False, True])
def test_data_only_cli_json_records_secret_coverage_and_gate_result(
    tmp_path, cli_environment, empty
):
    root = make_fixture_directory(tmp_path, "repo")
    write_fixture(root, "README.md", "Public baseline notes.\n")
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "--", "README.md")
    _git(root, "commit", "-qm", "public baseline")
    _git(root, "tag", "scope-base")
    _git(root, "update-ref", "refs/remotes/origin/main", "HEAD")
    write_fixture(
        root, "README.md", "" if empty else f"token: {TOKEN}\n", overwrite=True
    )
    _git(root, "add", "--", "README.md")
    _git(root, "commit", "-qm", "change documentation")

    result, report, environment = _cli_scan(
        root,
        tmp_path,
        cli_environment,
        mode="full",
        extra=["--secrets", "--no-grep-verify"],
    )

    assert _secret_locations(result) == (
        set() if empty else {("SKY-S101", "README.md", 1)}
    )
    assert result["analysis_summary"]["total_files"] == 0
    assert result["analysis_summary"]["secrets_files_scanned"] == 1
    assert result["analysis_errors"] == []
    gate = _gate(root, report, environment)
    assert gate.returncode == (0 if empty else 1), gate.stdout + gate.stderr


@pytest.mark.parametrize("name", SECRET_TEXT_NAMES)
def test_secret_only_text_avoids_generic_entropy_and_public_material_noise(
    tmp_path, name
):
    write_fixture(
        tmp_path,
        name,
        "Public setup notes.\n"
        'password = "w7Qx2Kp9Vt4Mz8Lc6Bn3Rh5Fy1Ds0JgU"\n'
        'api_key = "a6b8c1d0e9f23745a6b8c1d0e9f23745"\n'
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n"
        "-----END PUBLIC KEY-----\n",
    )

    result = _scan(tmp_path)

    assert _secret_locations(result) == set()
    assert result["analysis_summary"]["analysis_error_count"] == 0


def test_original_five_native_collection_gaps_are_reported_together(tmp_path):
    for name in (
        "tests/test_credentials.py",
        "index.html",
        "README.md",
        "credentials.txt",
        "service.key",
    ):
        write_fixture(tmp_path, name, f'github_token = "{TOKEN}"\n')

    result = _scan(tmp_path)

    assert _secret_locations(result) == {
        ("SKY-S101", name, 1)
        for name in (
            "tests/test_credentials.py",
            "index.html",
            "README.md",
            "credentials.txt",
            "service.key",
        )
    }
    assert result["analysis_summary"]["analysis_error_count"] == 0
    assert result["analysis_summary"]["total_files"] == 1


def test_changed_text_files_do_not_expand_target_or_scan_unchanged_files(tmp_path):
    target = make_fixture_directory(tmp_path, "selected")
    selected = write_fixture(tmp_path, "selected/credentials.txt", f"token: {TOKEN}\n")
    write_fixture(tmp_path, "selected/README.md", f"token: {TOKEN}\n")
    outside = write_fixture(tmp_path, "outside/service.key", f"token: {TOKEN}\n")

    result = _scan(target, changed_files={str(selected), str(outside)})

    assert _secret_locations(result) == {("SKY-S101", "credentials.txt", 1)}
    assert result["analysis_summary"]["analysis_error_count"] == 0


def test_multiple_explicit_text_targets_keep_common_scope_and_deduplicate(tmp_path):
    first = write_fixture(tmp_path, "first/README.md", f"token: {TOKEN}\n")
    second = write_fixture(tmp_path, "second/credentials.txt", f"token: {TOKEN}\n")
    write_fixture(tmp_path, "outside/service.key", f"token: {TOKEN}\n")

    result = json.loads(
        analyze(
            [str(first), str(second), str(first)],
            enable_secrets=True,
            grep_verify=False,
        )
    )

    assert _secret_locations(result) == {
        ("SKY-S101", "first/README.md", 1),
        ("SKY-S101", "second/credentials.txt", 1),
    }
    assert result["analysis_summary"]["total_files"] == 0
    assert result["analysis_summary"]["secrets_files_scanned"] == 2
    assert result["analysis_errors"] == []


@pytest.mark.parametrize("excluded", ["ignored", "**/ignored/**"])
def test_explicit_exclusions_remain_authoritative_for_new_text(tmp_path, excluded):
    write_fixture(tmp_path, "visible/README.md", f"token: {TOKEN}\n")
    write_fixture(tmp_path, "ignored/service.key", f"token: {TOKEN}\n")

    result = _scan(tmp_path, exclude_folders=[excluded])

    assert _secret_locations(result) == {("SKY-S101", "visible/README.md", 1)}


def test_automatic_generated_grep_cache_is_not_rescanned_with_new_text(tmp_path):
    write_fixture(tmp_path, "README.md", f"token: {TOKEN}\n")
    cache = write_fixture(
        tmp_path,
        ".skylos/cache/grep_results.json",
        json.dumps({"cached_source": TOKEN}),
    )

    result = _scan(tmp_path)

    assert _secret_locations(result) == {("SKY-S101", "README.md", 1)}
    # An explicit operator request can still select the generated cache itself.
    assert _secret_locations(_scan(cache)) == {("SKY-S101", "grep_results.json", 1)}


@pytest.mark.parametrize("name", ["index.html", "README.md", "service.key"])
@pytest.mark.parametrize("failure", ["limit", "encoding", "read"])
def test_selected_text_read_failures_are_reported_as_incomplete(
    tmp_path, monkeypatch, name, failure
):
    path = write_fixture(tmp_path, name, f"token: {TOKEN}\n")
    if failure == "limit":
        monkeypatch.setattr("skylos.analyzer.MAX_SECRET_CONFIG_BYTES", 16)
    elif failure == "encoding":
        write_fixture(tmp_path, name, b"\xff" + TOKEN.encode(), overwrite=True)
    else:
        monkeypatch.setattr(
            "skylos.analyzer.read_project_text_no_symlink", lambda *a, **k: None
        )

    result = _scan(path)

    assert _secret_locations(result) == set()
    assert result["analysis_summary"]["analysis_error_count"] == 1
    assert result["analysis_summary"]["secrets_files_scanned"] == 0
    assert result["analysis_errors"][0]["kind"] == (
        "secret_config_too_large" if failure == "limit" else "secret_config_read_error"
    )
    assert TOKEN not in json.dumps(result)


@pytest.mark.parametrize("explicit_file", [False, True])
def test_new_text_symlink_does_not_read_outside_target(
    tmp_path, monkeypatch, explicit_file
):
    root = make_fixture_directory(tmp_path, "project")
    outside = write_fixture(tmp_path, "outside.txt", f"token: {TOKEN}\n")
    (root / "README.md").symlink_to(outside)
    read_paths = []

    def unexpected_read(*args, **kwargs):
        read_paths.append(args[1])
        raise AssertionError("symlink must never be opened")

    monkeypatch.setattr("skylos.analyzer.read_project_text_no_symlink", unexpected_read)

    result = _scan(root / "README.md" if explicit_file else root)

    assert _secret_locations(result) == set()
    assert read_paths == []
    assert result["analysis_summary"]["analysis_error_count"] == 1
    assert result["analysis_summary"]["secrets_files_scanned"] == 0
    assert result["analysis_errors"][0]["kind"] == "secret_text_unsafe_input"
    assert result["analysis_errors"][0]["file"] == "README.md"
    assert str(outside) not in json.dumps(result)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO paths require POSIX")
def test_new_text_fifo_is_not_opened_as_a_regular_file(tmp_path, monkeypatch):
    from skylos.analyzer import _scan_secret_config_candidates

    fifo = tmp_path / "credentials.txt"
    os.mkfifo(fifo)
    reads = []

    def unexpected_read(*args, **kwargs):
        reads.append(args)
        raise AssertionError("FIFO must never be opened")

    monkeypatch.setattr("skylos.analyzer.read_project_text_no_symlink", unexpected_read)
    errors = []

    findings = _scan_secret_config_candidates(
        root=tmp_path,
        scan_target=fifo,
        changed_files=None,
        exclude_folders=None,
        analysis_errors=errors,
    )

    assert findings == []
    assert reads == []
    assert len(errors) == 1
    assert errors[0]["kind"] == "secret_text_unsafe_input"
    assert errors[0]["file"] == "credentials.txt"
    result = _scan(fifo)
    assert _secret_locations(result) == set()
    assert result["analysis_summary"]["analysis_error_count"] == 1
    assert result["analysis_summary"]["secrets_files_scanned"] == 0
    assert result["analysis_errors"][0]["file"] == "credentials.txt"
    assert reads == []


def test_changed_unsafe_text_stays_incomplete_when_source_is_also_discovered(tmp_path):
    write_fixture(tmp_path, "app.py", "print('ok')\n")
    public = write_fixture(tmp_path, "public.txt", "Public notes.\n")
    link = tmp_path / "README.md"
    link.symlink_to(public)

    result = _scan(tmp_path, changed_files={str(link)})

    assert _secret_locations(result) == set()
    assert result["analysis_summary"]["analysis_error_count"] == 1
    assert result["analysis_summary"]["secrets_files_scanned"] == 0
    assert result["analysis_errors"][0]["kind"] == "secret_text_unsafe_input"
    assert result["analysis_errors"][0]["file"] == "README.md"
    assert result.get("analysis_warnings", []) == []


@pytest.mark.parametrize("with_source", [False, True])
@pytest.mark.parametrize("parent_link", [False, True])
def test_changed_unsafe_text_outside_target_is_reported_without_following(
    tmp_path, monkeypatch, with_source, parent_link
):
    root = make_fixture_directory(tmp_path, "project")
    outside = write_fixture(tmp_path, "outside/README.md", f"token: {TOKEN}\n")
    if with_source:
        write_fixture(root, "app.py", "print('ok')\n")
    if parent_link:
        (root / "linked").symlink_to(outside.parent, target_is_directory=True)
        selected = root / "linked/README.md"
    else:
        selected = root / "README.md"
        selected.symlink_to(outside)
    reads = []

    def unexpected_read(*args, **kwargs):
        reads.append(args)
        raise AssertionError("unsafe text must never be opened")

    monkeypatch.setattr("skylos.analyzer.read_project_text_no_symlink", unexpected_read)

    result = _scan(root, changed_files={str(selected)})

    assert _secret_locations(result) == set()
    assert result["analysis_summary"]["secrets_files_scanned"] == 0
    assert len(result["analysis_errors"]) == 1
    assert result["analysis_errors"][0]["kind"] == "secret_text_unsafe_input"
    assert result["analysis_errors"][0]["file"] == str(selected.relative_to(root))
    assert str(outside) not in json.dumps(result)
    assert reads == []


def test_direct_unsafe_text_through_repository_alias_is_reported(tmp_path):
    root = make_fixture_directory(tmp_path, "project")
    outside = write_fixture(tmp_path, "outside.txt", f"token: {TOKEN}\n")
    (root / "README.md").symlink_to(outside)
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)

    result = _scan(alias / "README.md")

    assert _secret_locations(result) == set()
    assert result["analysis_summary"]["secrets_files_scanned"] == 0
    assert len(result["analysis_errors"]) == 1
    assert result["analysis_errors"][0]["file"] == "README.md"
    assert str(outside) not in json.dumps(result)


@pytest.mark.parametrize("parent_link", [False, True])
def test_unsafe_secret_diff_selection_is_opt_in_and_keeps_literal_scope(
    tmp_path, parent_link
):
    from skylos.core.diff_scope import changed_source_files

    root = make_fixture_directory(tmp_path, "project")
    outside = write_fixture(tmp_path, "outside/README.md", "Public notes.\n")
    if parent_link:
        (root / "vendor").symlink_to(outside.parent, target_is_directory=True)
        selected = root / "vendor/README.md"
    else:
        make_fixture_directory(root, "vendor")
        selected = root / "vendor/README.md"
        selected.symlink_to(outside)
    options = {
        "changed_files": {str(selected), str(outside)},
        "explicit_exclude_folders": [],
        "diff_base": None,
    }

    assert changed_source_files(root, root, **options) == []
    assert changed_source_files(
        root, root, include_unsafe_secret_text=True, **options
    ) == [selected]
    options["explicit_exclude_folders"] = ["**/vendor/**"]
    assert (
        changed_source_files(root, root, include_unsafe_secret_text=True, **options)
        == []
    )


def test_regular_new_text_diff_selection_does_not_widen_source_only_default(tmp_path):
    from skylos.core.diff_scope import changed_source_files

    path = write_fixture(tmp_path, "README.md", "Public notes.\n")
    options = {
        "changed_files": {str(path)},
        "explicit_exclude_folders": [],
        "diff_base": None,
    }

    assert changed_source_files(tmp_path, tmp_path, **options) == []
    assert changed_source_files(
        tmp_path, tmp_path, include_unsafe_secret_text=True, **options
    ) == [path]


@pytest.mark.parametrize("mode", ["diff", "combined", "changed"])
@pytest.mark.parametrize("explicit_exclude", [False, True])
def test_changed_unsafe_text_in_vendor_honors_explicit_policy_and_blocks_gate(
    tmp_path, cli_environment, mode, explicit_exclude
):
    root = make_fixture_directory(tmp_path, "repo")
    write_fixture(root, "app.py", "print('ok')\n")
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "--", "app.py")
    _git(root, "commit", "-qm", "baseline")
    _git(root, "tag", "scope-base")
    _git(root, "update-ref", "refs/remotes/origin/main", "HEAD")
    outside = write_fixture(tmp_path, "outside.txt", f"token: {TOKEN}\n")
    make_fixture_directory(root, "vendor")
    (root / "vendor/README.md").symlink_to(outside)
    _git(root, "add", "--", "vendor/README.md")
    _git(root, "commit", "-qm", "add unsafe documentation path")
    environment = dict(
        cli_environment, SKYLOS_POLICY_BASE=_git(root, "rev-parse", "scope-base")
    )
    report = tmp_path / "results.json"
    flags = {
        "combined": ["--diff-base", "scope-base", "--diff", "scope-base"],
        "diff": ["--diff", "scope-base"],
        "changed": ["--diff-base", "scope-base"],
    }[mode]
    scan = _cli(
        root,
        [
            ".",
            "--secrets",
            "--baseline",
            *flags,
            "--no-grep-verify",
            "--no-upload",
            "--format",
            "json",
            "-o",
            str(report),
            *(["--exclude-folder", "**/vendor/**"] if explicit_exclude else []),
        ],
        environment,
    )
    assert scan.returncode == (0 if explicit_exclude else 2), scan.stdout + scan.stderr
    result = json.loads(report.read_text(encoding="utf-8"))

    assert _secret_locations(result) == set()
    assert len(result["analysis_errors"]) == int(not explicit_exclude)
    if not explicit_exclude:
        assert result["analysis_errors"][0]["kind"] == "secret_text_unsafe_input"
        assert result["analysis_errors"][0]["file"] == "vendor/README.md"
    gate = _gate(root, report, environment)
    assert gate.returncode == (0 if explicit_exclude else 2), gate.stdout + gate.stderr


@pytest.mark.parametrize("selection", ["excluded", "unchanged"])
def test_new_text_unsafe_paths_outside_selection_do_not_report_errors(
    tmp_path, selection
):
    target = write_fixture(tmp_path, "public.txt", "Public notes.\n")
    make_fixture_directory(tmp_path, "ignored")
    (tmp_path / "ignored/service.key").symlink_to(target)
    options = (
        {"exclude_folders": ["ignored"]}
        if selection == "excluded"
        else {"changed_files": set()}
    )

    result = _scan(tmp_path, **options)

    assert _secret_locations(result) == set()
    assert result["analysis_summary"]["analysis_error_count"] == 0
