import subprocess

from skylos.cicd.review import _detect_regressions_from_diff, _get_per_file_diffs

OLD = "@login_required\ndef view():\n    return 1\n"
NEW = "def view():\n    return 1\n"


def _git(root, *args):
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.safecrlf=false",
            *args,
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def _repo_with_change(tmp_path, name, before=OLD, after=NEW):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    path = root / "src" / name
    path.parent.mkdir(parents=True)
    path.write_bytes(before.encode("utf-8"))
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "add")
    path.write_bytes(after.encode("utf-8"))
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "change")
    return root


def test_quoted_non_ascii_path_is_parsed(tmp_path):
    root = _repo_with_change(tmp_path, "vues_caf\u00e9.py")

    diffs = _get_per_file_diffs("HEAD~1", cwd=root)

    assert list(diffs) == ["src/vues_caf\u00e9.py"]
    findings = _detect_regressions_from_diff("HEAD~1", cwd=root)
    assert [finding["file"] for finding in findings] == ["src/vues_caf\u00e9.py"]


def test_unquoted_path_with_space_has_no_tab_suffix(tmp_path):
    root = _repo_with_change(tmp_path, "my views.py")

    diffs = _get_per_file_diffs("HEAD~1", cwd=root)

    assert list(diffs) == ["src/my views.py"]


def test_hunk_line_that_looks_like_a_header_keeps_its_own_file(tmp_path):
    root = _repo_with_change(
        tmp_path,
        "evil.js",
        'const note = "";\n',
        "const note = `\n++ b/victim.js\n`;\n",
    )

    diffs = _get_per_file_diffs("HEAD~1", cwd=root)

    assert list(diffs) == ["src/evil.js"]


def test_bare_cr_in_source_cannot_fabricate_a_file_header(tmp_path):
    # Read with universal newlines, the raw CR below turns the rest of the line
    # into a column-0 "diff --git" header and the removed decorator that follows
    # is dropped before the security-regression check ever sees it.
    before = 'note = "a\rdiff --git a/zz/zz b/zz/zz"\n@login_required\ndef view():\n    return 1\n'
    after = 'note = "a\rdiff --git a/zz/zz b/zz/zz"\n\ndef view():\n    return 1\n'
    root = _repo_with_change(tmp_path, "app.py", before, after)

    diffs = _get_per_file_diffs("HEAD~1", cwd=root)

    assert list(diffs) == ["src/app.py"]
    findings = _detect_regressions_from_diff("HEAD~1", cwd=root)
    assert [(finding["file"], finding["line"]) for finding in findings] == [
        ("src/app.py", 2)
    ]
