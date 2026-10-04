"""In-process grep backend used when ripgrep is not installed.

Without ripgrep every grep-verification request used to start its own
`grep -r` over the whole tree. On a real project that took minutes, the
verification budget ran out, the scan was marked incomplete and uploads were
refused. These tests pin the replacement: same answers, no per-request
processes for batchable requests, and the same file boundary as the analyzer.
"""

import os
import re
import shutil
import stat
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import skylos.core.grep_verify_common as gc
from skylos.core.grep_verify_common import (
    GrepRequest,
    _make_grep_request,
    _required_literal,
    _run_grep_request,
    execute_grep_batch,
    grep_verification_scope,
)

REAL_WHICH = shutil.which


def _no_ripgrep(executable, *args, **kwargs):
    return None if executable == "rg" else REAL_WHICH(executable, *args, **kwargs)


def _request(
    pattern, root, *, regex=True, fixed=False, globs=("*.py",), max_results=20
):
    return _make_grep_request(
        pattern,
        str(root),
        use_regex=regex,
        include_globs=list(globs),
        fixed_string=fixed,
        max_results=max_results,
    )


@pytest.mark.parametrize(
    "pattern,fixed,expected",
    [
        (r"\bbackend\.slam\.OdomCalibration\b", False, "backend.slam.OdomCalibration"),
        (
            r"""(getattr|setattr|hasattr|delattr)[[:space:]]*\([^,]+,[[:space:]]*["']OdomCalibration["']""",
            False,
            "OdomCalibration",
        ),
        (r"\[[\"']fcntl[\"']\]", False, "fcntl"),
        (r"__all__.*\bfcntl\b", False, "__all__"),
        # Escape payloads are never literal text.
        (r"\x27Name\x27", False, "Name"),
        (r"x\x{1F600}yz", False, None),
        (r"name\p{L}tail", False, "name"),
        # Optional or repeated atoms end a run.
        (r"colou?rful", False, "colo"),
        (r"ab+cd", False, None),
        # Groups, top-level alternation and flags give no required literal.
        (r"foo(bar)baz", False, "foo"),
        (r"abc|def", False, None),
        (r"(?i)Name", False, None),
        (r"(?x) a b c", False, None),
        (r"\bab\b", False, None),
        ("plain.fixed(text", True, "plain.fixed(text"),
    ],
)
def test_required_literal_is_a_substring_every_match_contains(pattern, fixed, expected):
    assert (
        _required_literal(_request(pattern, ".", regex=not fixed, fixed=fixed))
        == expected
    )


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / ".gitignore").write_text("data/\n", encoding="utf-8")
    (root / "app.py").write_text(
        "from helpers import OdomCalibration\n"
        "value = getattr(module, 'OdomCalibration')\n"
        "other = OdomCalibrationX\n",
        encoding="utf-8",
    )
    (root / "crlf.py").write_bytes(b"x = 1\r\nuse(OdomCalibration)\r\n")
    (root / "binary.py").write_bytes(b"OdomCalibration\x00\x01")
    (root / "test_app.py").write_text("OdomCalibration()\n", encoding="utf-8")
    (root / "notes.md").write_text("OdomCalibration is documented\n", encoding="utf-8")
    hidden = root / ".config"
    hidden.mkdir()
    (hidden / "hidden.py").write_text("OdomCalibration\n", encoding="utf-8")
    # Gitignored data and virtualenvs are outside the analyzer's boundary.
    data = root / "data"
    data.mkdir()
    (data / "dump.py").write_text("OdomCalibration\n", encoding="utf-8")
    venv = root / "venv" / "lib"
    venv.mkdir(parents=True)
    (venv / "site.py").write_text("OdomCalibration\n", encoding="utf-8")
    try:
        (root / "loop").symlink_to(root, target_is_directory=True)
    except OSError:
        pass  # Symlink creation needs special privileges on some Windows hosts.
    return root


def _lines(results, request):
    return sorted(
        os.path.relpath(line.split(":", 1)[0], request.project_root)
        + ":"
        + line.split(":", 2)[1]
        for line in results[request]
    )


@pytest.mark.parametrize(
    "pattern, text",
    [
        (r"foo.{0,80}bar", "foo bar"),
        (r"abc{1,10}", "abc"),
        (r"(?:abc){2,10}", "abcabc"),
        (r"foo.{0,80}?bar", "foobar"),
        (r"a{,10}", "aaa"),
        (r"foo{literal|other}bar", "foo{literal"),
        (r"foo\{12,34\}bar", "foo{12,34}bar"),
    ],
)
def test_python_backend_preserves_matches_with_counted_quantifiers(
    tmp_path, monkeypatch, pattern, text
):
    root = tmp_path / "quantifiers"
    root.mkdir()
    (root / "app.py").write_text(text + "\n", encoding="utf-8")
    assert re.search(pattern, text) is not None
    request = _request(pattern, root)
    anchor = _required_literal(request)
    assert anchor is None or anchor in text
    monkeypatch.setattr(gc.shutil, "which", _no_ripgrep)
    with grep_verification_scope(root, []):
        results = execute_grep_batch([request])
    assert _lines(results, request) == ["app.py:1"]


@pytest.mark.parametrize(
    "pattern, text",
    [
        (r"\123456abc", "S456abc"),
        (r"foo\123456bar", "fooS456bar"),
        (r"\141bar", "abar"),
        (r"\077tail", "?tail"),
        (r"(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)(k)\11tail", "abcdefghijkktail"),
    ],
)
def test_python_backend_preserves_matches_with_numeric_escapes(
    tmp_path, monkeypatch, pattern, text
):
    root = tmp_path / "numeric-escapes"
    root.mkdir()
    (root / "app.py").write_text(text + "\n", encoding="utf-8")
    assert re.search(pattern, text) is not None
    request = _request(pattern, root)
    assert _required_literal(request) is None
    monkeypatch.setattr(gc.shutil, "which", _no_ripgrep)
    with grep_verification_scope(root, []):
        results = execute_grep_batch([request])
    assert _lines(results, request) == ["app.py:1"]


def test_python_backend_answers_like_grep_within_the_scan_boundary(repo):
    word = _request(r"\bOdomCalibration\b", repo)
    fixed = _request("OdomCalibration", repo, regex=False, fixed=True)
    dispatch = _request(r"getattr[ \t]*\([^,]+,[ \t]*['\"]OdomCalibration['\"]", repo)
    tests_only = _request(r"\bOdomCalibration\b", repo, globs=("test_*.py",))
    docs = _request("OdomCalibration", repo, regex=False, fixed=True, globs=("*.md",))
    no_anchor = _request(r"Odom(Calibration|Other)\b", repo)

    with (
        patch("skylos.core.grep_verify_common.shutil.which", side_effect=_no_ripgrep),
        patch(
            "skylos.core.grep_verify_common._run_grep_request",
            side_effect=AssertionError("spawned grep"),
        ),
        grep_verification_scope(repo, ["venv"]),
    ):
        results = execute_grep_batch(
            [word, fixed, dispatch, tests_only, docs, no_anchor]
        )

    # Word boundaries exclude OdomCalibrationX; CRLF endings are stripped;
    # binary, gitignored, virtualenv and symlink-loop files are never searched;
    # hidden files are, as with ripgrep --hidden.
    assert _lines(results, word) == [
        ".config/hidden.py:1",
        "app.py:1",
        "app.py:2",
        "crlf.py:2",
        "test_app.py:1",
    ]
    assert _lines(results, fixed) == [
        ".config/hidden.py:1",
        "app.py:1",
        "app.py:2",
        "app.py:3",
        "crlf.py:2",
        "test_app.py:1",
    ]
    assert _lines(results, dispatch) == ["app.py:2"]
    assert _lines(results, tests_only) == ["test_app.py:1"]
    assert _lines(results, docs) == ["notes.md:1"]
    assert _lines(results, no_anchor) == [
        ".config/hidden.py:1",
        "app.py:1",
        "app.py:2",
        "crlf.py:2",
        "test_app.py:1",
    ]
    crlf = [
        line for line in results[word] if line.split(":", 1)[0].endswith("crlf.py")
    ][0]
    assert crlf.endswith(":use(OdomCalibration)")
    assert str(repo) in crlf


@pytest.mark.skipif(shutil.which("grep") is None, reason="needs a grep executable")
def test_python_backend_agrees_with_the_one_process_grep_path(repo):
    # The old path can't parse grep's "Binary file ... matches" line; the new
    # backend skips binary files like ripgrep does. Compare on text files.
    (repo / "binary.py").unlink()
    requests = [
        _request(r"\bOdomCalibration\b", repo),
        _request("OdomCalibration", repo, regex=False, fixed=True),
        _request(r"getattr[ \t]*\([^,]+,[ \t]*['\"]OdomCalibration['\"]", repo),
        _request(r"\bOdomCalibration\b", repo, globs=("test_*.py",)),
        _request(r"\bnothing_matches_this\b", repo),
    ]
    with (
        patch("skylos.core.grep_verify_common.shutil.which", side_effect=_no_ripgrep),
        grep_verification_scope(repo, ["venv"]),
    ):
        batched = execute_grep_batch(requests)
        for request in requests:
            serial = _run_grep_request(request, require_complete=True)
            assert set(map(str, serial)) <= set(map(str, batched[request])), (
                request.pattern
            )
            assert bool(serial) == bool(batched[request]), request.pattern


def test_requests_python_cannot_decide_keep_the_subprocess_path(repo):
    posix = _request(r"\bOdom[[:digit:]]\b", repo)  # untranslatable POSIX class
    plain = _request(r"\bOdomCalibration\b", repo)
    calls = []

    def fake_direct(request, **_kwargs):
        calls.append(request)
        return []

    with (
        patch("skylos.core.grep_verify_common.shutil.which", side_effect=_no_ripgrep),
        patch(
            "skylos.core.grep_verify_common._run_grep_request", side_effect=fake_direct
        ),
        grep_verification_scope(repo, []),
    ):
        results = execute_grep_batch([posix, plain])

    assert calls == [posix]
    assert results[posix] == ()
    assert results[plain]


def test_path_globs_keep_the_existing_subprocess_search(repo):
    request = _request(
        r"\bOdomCalibration\b", repo, globs=("**/*.py",)
    )
    calls = []

    def fake_direct(candidate, **_kwargs):
        calls.append(candidate)
        return []

    with (
        patch("skylos.core.grep_verify_common.shutil.which", side_effect=_no_ripgrep),
        patch(
            "skylos.core.grep_verify_common._run_grep_request", side_effect=fake_direct
        ),
        grep_verification_scope(repo, []),
    ):
        execute_grep_batch([request])
    assert calls == [request]


def test_an_expired_deadline_leaves_requests_unanswered(repo):
    request = _request(r"\bOdomCalibration\b", repo)
    with (
        patch("skylos.core.grep_verify_common.shutil.which", side_effect=_no_ripgrep),
        grep_verification_scope(repo, []),
    ):
        results = execute_grep_batch([request], deadline=time.monotonic() - 1)
    # Missing means incomplete; it must never be read as "no matches".
    assert request not in results


def test_the_file_cache_lives_only_for_one_verification_scope(repo, tmp_path):
    request = _request(r"\bOdomCalibration\b", repo)
    with (
        patch("skylos.core.grep_verify_common.shutil.which", side_effect=_no_ripgrep),
        grep_verification_scope(repo, []),
    ):
        execute_grep_batch([request])
        caches = gc._PYTHON_GREP_CACHES.get()
        assert caches and str(repo) in caches
    assert gc._PYTHON_GREP_CACHES.get() is None

    # Edits between scans are seen: nothing stale is reused.
    (tmp_path / "repo" / "app.py").write_text("unrelated = 1\n", encoding="utf-8")
    with (
        patch("skylos.core.grep_verify_common.shutil.which", side_effect=_no_ripgrep),
        grep_verification_scope(repo, []),
    ):
        results = execute_grep_batch([request])
    assert not any(
        Path(line.split(":", 1)[0]).name == "app.py" for line in results[request]
    )


def test_the_memory_cap_falls_back_once_instead_of_rereading(repo):
    first = _request(r"\bOdomCalibration\b", repo)
    second = _request("OdomCalibration", repo, regex=False, fixed=True)
    direct_calls = []

    def fake_direct(request, **_kwargs):
        direct_calls.append(request)
        return []

    with (
        patch("skylos.core.grep_verify_common.shutil.which", side_effect=_no_ripgrep),
        patch.object(gc, "_PY_BACKEND_MAX_TOTAL_BYTES", 10),
        patch(
            "skylos.core.grep_verify_common._run_grep_request", side_effect=fake_direct
        ),
        patch(
            "skylos.core.grep_verify_common._read_python_grep_text",
            wraps=gc._read_python_grep_text,
        ) as reads,
        grep_verification_scope(repo, []),
    ):
        results = execute_grep_batch([first, second])
        cache = gc._PYTHON_GREP_CACHES.get()[str(repo)]
    assert cache.disabled is True
    assert direct_calls == [first, second]
    assert results == {first: (), second: ()}
    # The second request never re-read files after the cap tripped.
    assert reads.call_count <= 2


def test_a_missing_or_unreadable_root_is_incomplete_not_empty(tmp_path):
    missing = _request(r"\bOdomCalibration\b", tmp_path / "gone")
    with patch("skylos.core.grep_verify_common.shutil.which", return_value=None):
        results = execute_grep_batch([missing])
    assert missing not in results


def test_a_selected_file_disappearing_during_scan_abstains(repo):
    request = _request(r"\bOdomCalibration\b", repo)
    selected = str(repo / "app.py")
    (repo / "app.py").unlink()
    with (
        patch("skylos.core.grep_verify_common.shutil.which", side_effect=_no_ripgrep),
        patch("skylos.core.grep_verify_common._python_grep_files", return_value=[selected]),
        grep_verification_scope(repo, []),
    ):
        results = execute_grep_batch([request])
    assert request not in results


@pytest.mark.skipif(
    os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"),
    reason="needs nofollow directory-relative opens",
)
def test_an_outside_path_is_rejected_before_reading(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("OutsideReference()\n", encoding="utf-8")
    with patch("skylos.core.grep_verify_common.os.read") as read:
        with pytest.raises(OSError, match="outside the search root"):
            gc._read_python_grep_bytes(str(root), str(outside), 1024, None)
        with pytest.raises(OSError, match="outside the search root"):
            gc._read_python_grep_bytes(
                str(root), str(root / ".." / "outside.py"), 1024, None
            )
    read.assert_not_called()


@pytest.mark.skipif(
    os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"),
    reason="needs nofollow directory-relative opens",
)
def test_an_intermediate_directory_swapped_for_a_symlink_abstains(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    nested = root / "nested"
    nested.mkdir()
    selected = nested / "app.py"
    selected.write_text("LocalReference()\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "app.py").write_text("OutsideReference()\n", encoding="utf-8")
    selected.unlink()
    nested.rmdir()
    nested.symlink_to(outside, target_is_directory=True)

    request = _request(r"\bOutsideReference\b", root)
    with (
        patch("skylos.core.grep_verify_common.shutil.which", side_effect=_no_ripgrep),
        patch(
            "skylos.core.grep_verify_common._python_grep_files",
            return_value=[str(selected)],
        ),
        grep_verification_scope(root, []),
    ):
        results = execute_grep_batch([request])
    assert request not in results


@pytest.mark.skipif(
    os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"),
    reason="needs nofollow directory-relative opens",
)
def test_a_file_swapped_for_an_outside_symlink_is_not_read(repo, tmp_path):
    request = _request(r"\bOdomCalibration\b", repo)
    selected = repo / "app.py"
    outside = tmp_path / "outside.py"
    outside.write_text("OdomCalibration()\n", encoding="utf-8")
    selected.unlink()
    selected.symlink_to(outside)
    with (
        patch("skylos.core.grep_verify_common.shutil.which", side_effect=_no_ripgrep),
        patch(
            "skylos.core.grep_verify_common._python_grep_files",
            return_value=[str(selected)],
        ),
        grep_verification_scope(repo, []),
    ):
        results = execute_grep_batch([request])
    assert request not in results


def test_a_non_utf8_nonmatch_uses_byte_preserving_fallback(repo, tmp_path):
    (tmp_path / "repo" / "latin1.py").write_bytes(b"caf\xe9\n")
    request = _request(r"\bno_such_reference\b", repo)
    calls = []

    def fake_direct(candidate, **_kwargs):
        calls.append(candidate)
        return []

    with (
        patch("skylos.core.grep_verify_common.shutil.which", side_effect=_no_ripgrep),
        patch(
            "skylos.core.grep_verify_common._run_grep_request", side_effect=fake_direct
        ),
        grep_verification_scope(repo, []),
    ):
        results = execute_grep_batch([request])
    assert calls == [request]
    assert results[request] == ()


@pytest.mark.parametrize(
    "source,pattern",
    [
        ("x = 'a\u0301word'\n", r"\bword"),
        ("x = 'a\x1cb'\n", r"a\sb"),
    ],
)
def test_engine_sensitive_unicode_uses_exact_subprocess_search(
    repo, tmp_path, source, pattern
):
    (tmp_path / "repo" / "sensitive.py").write_text(source, encoding="utf-8")
    request = _request(pattern, repo)
    calls = []

    def fake_direct(candidate, **_kwargs):
        calls.append(candidate)
        return []

    with (
        patch("skylos.core.grep_verify_common.shutil.which", side_effect=_no_ripgrep),
        patch(
            "skylos.core.grep_verify_common._run_grep_request", side_effect=fake_direct
        ),
        grep_verification_scope(repo, []),
    ):
        execute_grep_batch([request])
    assert calls == [request]


@pytest.mark.skipif(
    os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"),
    reason="needs nofollow directory-relative opens",
)
def test_file_growth_after_stat_still_respects_byte_cap(repo):
    target = repo / "app.py"
    with patch(
        "skylos.core.grep_verify_common.os.fstat",
        return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_size=1),
    ):
        with pytest.raises(gc._PythonCorpusTooLarge):
            gc._read_python_grep_bytes(str(repo), str(target), 2, None)


def test_matches_in_non_utf8_files_keep_the_conservative_subprocess_path(repo, tmp_path):
    (tmp_path / "repo" / "latin1.py").write_bytes(b"OdomCalibration()  # caf\xe9\n")
    request = _request(r"\bOdomCalibration\b", repo)
    direct_calls = []

    def fake_direct(request, **_kwargs):
        direct_calls.append(request)
        return []

    with (
        patch("skylos.core.grep_verify_common.shutil.which", side_effect=_no_ripgrep),
        patch(
            "skylos.core.grep_verify_common._run_grep_request", side_effect=fake_direct
        ),
        grep_verification_scope(repo, []),
    ):
        execute_grep_batch([request])
    assert direct_calls == [request]


def test_backend_name_reports_what_scans_will_use(tmp_path):
    with (
        patch("skylos.core.grep_verify_common.shutil.which", side_effect=_no_ripgrep),
        patch(
            "skylos.core.grep_verify_common._python_grep_secure_reads_available",
            return_value=True,
        ),
    ):
        assert gc.grep_backend_name(str(tmp_path)) == "in_process"
    with (
        patch("skylos.core.grep_verify_common.shutil.which", side_effect=_no_ripgrep),
        patch(
            "skylos.core.grep_verify_common._python_grep_secure_reads_available",
            return_value=False,
        ),
    ):
        assert gc.grep_backend_name(str(tmp_path)) == "serial_grep"
    with patch(
        "skylos.core.grep_verify_common._trusted_which",
        return_value="/usr/local/bin/rg",
    ):
        assert gc.grep_backend_name(str(tmp_path)) == "ripgrep"


def test_budget_error_tells_users_how_to_fix_it(tmp_path):
    from skylos.analyzer import _grep_verify_error_payload

    in_process = _grep_verify_error_payload(
        tmp_path,
        {
            "incomplete_reason": "budget_exhausted",
            "time_budget_seconds": 120,
            "backend": "in_process",
        },
    )
    assert "brew install ripgrep" in in_process["message"]
    assert "https://github.com/BurntSushi/ripgrep#installation" in in_process["message"]
    assert "rg is on PATH" in in_process["message"]
    assert "SKYLOS_GREP_BUDGET" in in_process["message"]
    with_rg = _grep_verify_error_payload(
        tmp_path,
        {
            "incomplete_reason": "budget_exhausted",
            "time_budget_seconds": 120,
            "backend": "ripgrep",
        },
    )
    assert "install ripgrep" not in with_rg["message"]
    assert "Increase SKYLOS_GREP_BUDGET" in with_rg["message"]


def test_a_single_file_root_is_searched_directly(tmp_path):
    target = tmp_path / "only.py"
    target.write_text("OdomCalibration()\n", encoding="utf-8")
    request = GrepRequest(
        pattern=r"\bOdomCalibration\b",
        project_root=str(target),
        use_regex=True,
        include_globs=("*.py",),
        fixed_string=False,
        max_results=5,
    )
    with patch("skylos.core.grep_verify_common.shutil.which", side_effect=_no_ripgrep):
        results = execute_grep_batch([request])
    assert [line.split(":", 2)[1] for line in results[request]] == ["1"]


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("", 512 * 1024 * 1024),
        ("abc", 512 * 1024 * 1024),
        ("-5", 512 * 1024 * 1024),
        ("1048576", 1048576),
    ],
)
def test_a_bad_memory_cap_setting_never_breaks_a_scan(monkeypatch, raw, expected):
    monkeypatch.setenv("SKYLOS_GREP_MAX_BYTES", raw)
    assert gc._env_byte_limit("SKYLOS_GREP_MAX_BYTES", 512 * 1024 * 1024) == expected
