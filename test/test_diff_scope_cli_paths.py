"""Literal Git filenames must not hide changed source from the PR gate."""

import json

import pytest

from skylos.cicd.review import (
    _parse_unified_diff,
    filter_findings_to_diff,
    get_changed_line_ranges,
    get_untracked_files,
)
from test.test_diff_default_exclusions import (
    SAFE,
    UNSAFE,
    _cli,
    _critical_identities,
    _gate,
    _git,
    _repo,
    _scan,
    cli_environment as cli_environment,
)


CHANGED_PATHS = [
    "vendor/café.py",
    "vendor/has space.py",
    'vendor/has"quote.py',
    "vendor/has\\backslash.py",
    "vendor/has\nnewline.py",
    "vendor/has\rcarriage.py",
]
PATH_IDS = ["unicode", "space", "quote", "backslash", "newline", "carriage"]


def _compared_python_source(tmp_path, *, preexisting_cr=False, crlf=False):
    before = (
        'message = """hello\n"""\n'
        + "\n".join(f"value_{index} = {index}" for index in range(20))
        + "\n\nimport pickle\ndef handler(request):\n    return request.body\n"
    )
    if preexisting_cr:
        before = before.replace("hello", "hello\rcontinued")
    if crlf:
        before = before.replace("\n", "\r\n")
    root, target = _repo(tmp_path, "vendor/source.py", source=before)
    _git(root, "tag", "line-base")
    after = before.replace("return request.body", "return pickle.loads(request.body)")
    if not preexisting_cr and not crlf:
        after = after.replace(
            "hello", "hello\rdiff --git a/decoy.py b/decoy.py\r+++ b/decoy.py"
        )
    target.write_bytes(after.encode("utf-8"))
    _git(root, "add", "--", "vendor/source.py")
    _git(root, "commit", "-qm", "change source with literal line endings")
    return root, target


def _line_scan(root, env, mode):
    flags = ["--diff", "line-base"]
    if mode == "combined":
        flags = ["--diff-base", "line-base", *flags]
    return _cli(
        root,
        [
            ".",
            "--danger",
            *flags,
            "--no-grep-verify",
            "--no-upload",
            "--format",
            "json",
        ],
        dict(env, SKYLOS_POLICY_BASE=_git(root, "rev-parse", "line-base")),
    )


@pytest.mark.parametrize("mode", ["combined", "diff"])
@pytest.mark.parametrize(
    "preexisting", [False, True], ids=["introduced", "preexisting"]
)
def test_python_carriage_return_line_mismatch_cannot_be_a_clean_diff_scan(
    tmp_path, cli_environment, mode, preexisting
):
    root, _ = _compared_python_source(tmp_path, preexisting_cr=preexisting)

    scan = _line_scan(root, cli_environment, mode)

    assert scan.returncode == 2, scan.stdout + scan.stderr
    assert "carriage returns" in scan.stderr


@pytest.mark.parametrize("mode", ["combined", "diff"])
def test_crlf_python_source_keeps_critical_findings(tmp_path, cli_environment, mode):
    root, target = _compared_python_source(tmp_path, crlf=True)

    scan = _line_scan(root, cli_environment, mode)

    assert scan.returncode == 0, scan.stdout + scan.stderr
    result = json.loads(scan.stdout)
    assert _critical_identities(result) == {("SKY-D205", str(target), 26)}
    assert not result.get("analysis_errors")


def test_unchanged_python_carriage_returns_do_not_block_another_files_diff(
    tmp_path, monkeypatch
):
    unchanged = tmp_path / "old.py"
    unchanged.write_bytes(b'value = """old\rcarriage"""\n')

    def forbid_read(*args, **kwargs):
        pytest.fail("unchanged source must not be read to filter another file's diff")

    monkeypatch.setattr(
        "skylos.core.safe_cache_io.read_project_text_no_symlink", forbid_read
    )
    assert (
        filter_findings_to_diff(
            [{"file": str(unchanged), "line": 2}],
            [{"file": "changed.py", "start": 1, "end": 3}],
            project_root=tmp_path,
        )
        == []
    )


def test_unreadable_changed_python_source_is_not_assumed_line_safe(
    tmp_path, monkeypatch
):
    source = tmp_path / "changed.py"
    source.write_text(UNSAFE, encoding="utf-8")
    monkeypatch.setattr(
        "skylos.core.safe_cache_io.read_project_text_no_symlink", lambda *a, **kw: None
    )

    with pytest.raises(ValueError, match="line endings unavailable"):
        filter_findings_to_diff(
            [{"file": str(source), "line": 4}],
            [{"file": "changed.py", "start": 1, "end": 4}],
            project_root=tmp_path,
        )


def test_untracked_inventory_preserves_a_literal_carriage_return(tmp_path):
    root, _ = _repo(tmp_path, "src/safe.py", source=SAFE)
    source = root / "vendor/has\rcarriage.py"
    source.write_text(UNSAFE, encoding="utf-8")

    assert get_untracked_files(root) == ["vendor/has\rcarriage.py"]


@pytest.mark.parametrize("mode", ["combined", "changed", "diff"])
def test_untracked_carriage_return_filename_cannot_hide_a_critical_finding(
    tmp_path, cli_environment, mode
):
    root, _ = _repo(tmp_path, "src/safe.py", source=SAFE)
    source = root / "vendor/has\rcarriage.py"
    source.write_text(UNSAFE, encoding="utf-8")

    result, report, env = _scan(
        root,
        tmp_path,
        cli_environment,
        mode=mode,
        extra=["--no-grep-verify"],
    )

    assert _critical_identities(result) == {("SKY-D205", str(source), 4)}
    gate = _gate(root, report, env)
    assert gate.returncode == 1, gate.stdout + gate.stderr


def test_source_carriage_returns_cannot_create_git_patch_headers(tmp_path):
    before = (
        'message = """hello\n"""\n'
        + "\n".join(f"value_{index} = {index}" for index in range(20))
        + "\n\nimport pickle\ndef handler(request):\n    return request.body\n"
    )
    root, target = _repo(tmp_path, "vendor/source.py", source=before)
    _git(root, "tag", "literal-base")
    after = before.replace(
        "hello", "hello\rdiff --git a/decoy.py b/decoy.py\r+++ b/decoy.py"
    ).replace("return request.body", "return pickle.loads(request.body)")
    target.write_bytes(after.encode("utf-8"))
    _git(root, "add", "--", "vendor/source.py")
    _git(root, "commit", "-qm", "change source containing carriage returns")

    ranges = get_changed_line_ranges("literal-base", cwd=root, raise_on_error=True)

    assert ranges == [
        {"file": "vendor/source.py", "start": 1, "end": 1},
        {"file": "vendor/source.py", "start": 26, "end": 26},
    ]


@pytest.mark.parametrize("header", ["+++ b/decoy.py", '+++ "b/decoy.py"'])
def test_added_source_that_looks_like_a_patch_header_cannot_redirect_later_hunks(
    header,
):
    diff = (
        "diff --git a/vendor/source.py b/vendor/source.py\n"
        "--- a/vendor/source.py\n"
        "+++ b/vendor/source.py\n"
        "@@ -0,0 +1,3 @@\n"
        '+message = """\n'
        f"{header}\n"
        '+"""\n'
        "@@ -10,0 +14,1 @@\n"
        "+pickle.loads(request.body)\n"
    )

    assert _parse_unified_diff(diff) == [
        {"file": "vendor/source.py", "start": 1, "end": 3},
        {"file": "vendor/source.py", "start": 14, "end": 14},
    ]


@pytest.mark.parametrize("relative", CHANGED_PATHS, ids=PATH_IDS)
def test_changed_line_ranges_preserve_literal_git_filenames(tmp_path, relative):
    root, _ = _repo(tmp_path, relative)

    ranges = get_changed_line_ranges(
        "scope-base", cwd=root, raise_on_error=True, include_working_tree=True
    )

    assert ranges == [{"file": relative, "start": 1, "end": 4}]


@pytest.mark.parametrize("mode", ["combined", "changed", "diff"])
@pytest.mark.parametrize("relative", CHANGED_PATHS, ids=PATH_IDS)
def test_literal_changed_filenames_survive_default_exclusions_and_block_gate(
    tmp_path, cli_environment, mode, relative
):
    root, target = _repo(tmp_path, relative)

    result, report, env = _scan(
        root,
        tmp_path,
        cli_environment,
        mode=mode,
        extra=["--no-grep-verify"],
    )

    assert _critical_identities(result) == {("SKY-D205", str(target), 4)}
    assert result["analysis_summary"]["total_files"] == 2
    gate = _gate(root, report, env)
    assert gate.returncode == 1, gate.stdout + gate.stderr
    assert "SKY-D205" in gate.stdout
