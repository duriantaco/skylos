"""Raw session snapshots distinguish checkout normalization from hidden edits."""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import sys

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.done import session
from skylos.done.checks import CheckResult
from skylos.done.config import DoneConfig
from skylos.done.engine import CheckOutcome, DoneResult
from skylos.done.receipt import build_receipt, receipt_upload_error


def _git(root: Path, *args: str) -> str:
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    environment.update(
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_NOSYSTEM="1",
        GIT_AUTHOR_NAME="Fixture",
        GIT_AUTHOR_EMAIL="fixture@example.invalid",
        GIT_COMMITTER_NAME="Fixture",
        GIT_COMMITTER_EMAIL="fixture@example.invalid",
    )
    return (
        subprocess.check_output(
            [
                "git",
                "--no-pager",
                "--no-replace-objects",
                "-c",
                "core.fsmonitor=false",
                "-c",
                f"core.hooksPath={os.devnull}",
                "-c",
                "commit.gpgsign=false",
                *args,
            ],
            cwd=root,
            env=environment,
            stderr=subprocess.PIPE,
            timeout=15,
        )
        .decode()
        .strip()
    )


def _write(root: Path, name: str, content: str | bytes) -> Path:
    root = root.resolve(strict=True)
    path = root / name
    path.resolve(strict=False).relative_to(root)
    text = content.decode("latin1") if isinstance(content, bytes) else content
    assert write_text_no_symlink(path, text, encoding="latin1", newline="")
    return path


def _repo(
    root: Path, attributes: str, *, autocrlf: str | None = None, count: int = 1
) -> list[Path]:
    _git(root, "init", "--template=")
    _write(root, ".gitignore", ".skylos/\n")
    _write(root, ".gitattributes", attributes)
    _write(root, "pyproject.toml", "[tool.skylos.done]\n")
    files = [root / f"service_{index}.py" for index in range(count)]
    for path in files:
        _write(root, path.name, b"VALUE = 1\n")
    _git(
        root,
        "add",
        "--",
        ".gitignore",
        ".gitattributes",
        "pyproject.toml",
        *(path.name for path in files),
    )
    _git(root, "commit", "-m", "Initial fixture")
    if autocrlf is not None:
        _git(root, "config", "core.autocrlf", autocrlf)
    return files


def _receipt(comparison):
    check = CheckResult("tests_pass", "SKY-A113", "pass", "Fixture evidence")
    result = DoneResult(
        comparison, DoneConfig(), [CheckOutcome("block", check)], "pass", 0.0
    )
    return build_receipt(result)


@pytest.mark.parametrize(
    ("attributes", "autocrlf"),
    [
        ("*.py text eol=crlf\n", None),
        ("*.py text eol=lf\n", None),
        ("*.py text=auto\n", None),
        ("*.py eol=crlf\n", None),
        ("", "true"),
        ("", "input"),
    ],
)
def test_clean_crlf_checkout_preserves_raw_snapshot_and_uploads(
    tmp_path, attributes, autocrlf
):
    path = _repo(tmp_path, attributes, autocrlf=autocrlf)[0]
    _write(tmp_path, path.name, b"VALUE = 1\r\n")
    # Refresh index stat information; Git stores the unchanged canonical LF blob.
    _git(tmp_path, "add", "--", path.name)
    assert _git(tmp_path, "status", "--porcelain") == ""
    index = (tmp_path / ".git/index").read_bytes()
    session.capture_session(tmp_path, "normalization")
    comparison = session.open_session_comparison(tmp_path, "normalization")
    assert comparison.changed == ()
    assert comparison.base_text(path.name) == "VALUE = 1\r\n"
    assert comparison.head_dirty is False
    assert (tmp_path / ".git/index").read_bytes() == index
    assert receipt_upload_error(_receipt(comparison), tmp_path) is None


def test_hidden_crlf_content_edit_stays_dirty(tmp_path):
    path = _repo(tmp_path, "*.py text eol=crlf\n")[0]
    _write(tmp_path, path.name, b"VALUE = 1\r\n")
    _git(tmp_path, "add", "--", path.name)
    session.capture_session(tmp_path, "normalization")
    _git(tmp_path, "update-index", "--assume-unchanged", "--", path.name)
    status = path.stat()
    _write(tmp_path, path.name, b"VALUE = 9\r\n")
    os.utime(path, ns=(status.st_atime_ns, status.st_mtime_ns))
    assert _git(tmp_path, "diff", "--name-only", "HEAD") == ""
    comparison = session.open_session_comparison(tmp_path, "normalization")
    assert comparison.head_dirty
    assert [change.path for change in comparison.changed] == [path.name]
    assert "uncommitted" in receipt_upload_error(_receipt(comparison), tmp_path)


def test_explicit_binary_crlf_difference_stays_dirty(tmp_path):
    path = _repo(tmp_path, "*.py -text eol=crlf\n", autocrlf="true")[0]
    session.capture_session(tmp_path, "normalization")
    _git(tmp_path, "update-index", "--assume-unchanged", "--", path.name)
    _write(tmp_path, path.name, b"VALUE = 1\r\n")
    comparison = session.open_session_comparison(tmp_path, "normalization")
    assert comparison.head_dirty
    assert "uncommitted" in receipt_upload_error(_receipt(comparison), tmp_path)


@pytest.mark.parametrize(
    "attribute", ["filter=fixture", "ident", "working-tree-encoding=UTF-16"]
)
def test_custom_transform_is_never_used_to_claim_a_clean_receipt(tmp_path, attribute):
    # Configure transforms only after committing the untransformed fixture.
    path = _repo(tmp_path, "*.py text eol=crlf\n")[0]
    _write(tmp_path, ".gitattributes", f"*.py text eol=crlf {attribute}\n")
    _git(tmp_path, "add", "--", ".gitattributes")
    _git(tmp_path, "commit", "-m", "Declare transform without executing it")
    _git(tmp_path, "update-index", "--assume-unchanged", "--", path.name)
    if attribute == "filter=fixture":
        code = (
            "from pathlib import Path; import sys; "
            "Path('filter-executed').touch(); sys.stdout.write(sys.stdin.read())"
        )
        command = shlex.join([sys.executable, "-c", code])
        _git(tmp_path, "config", "filter.fixture.clean", command)
        _git(tmp_path, "config", "filter.fixture.smudge", command)
        _git(tmp_path, "config", "filter.fixture.required", "true")
    session.capture_session(tmp_path, "normalization")
    assert not (tmp_path / "filter-executed").exists(), "capture executed a filter"
    _write(tmp_path, path.name, b"VALUE = 1\r\n")
    comparison = session.open_session_comparison(tmp_path, "normalization")
    assert comparison.head_dirty
    assert "uncommitted" in receipt_upload_error(_receipt(comparison), tmp_path)
    assert not (tmp_path / "filter-executed").exists()


def test_checkout_normalization_reads_attributes_and_blobs_in_batches(
    tmp_path, monkeypatch
):
    files = _repo(tmp_path, "*.py text eol=crlf\n", count=32)
    for path in files:
        _write(tmp_path, path.name, b"VALUE = 1\r\n")
    _git(tmp_path, "add", "--", *(path.name for path in files))
    session.capture_session(tmp_path, "normalization")
    calls = []
    original = session._read_git_input

    def read(comparison, args, data):
        calls.append(args[0])
        return original(comparison, args, data)

    monkeypatch.setattr(session, "_read_git_input", read)
    comparison = session.open_session_comparison(tmp_path, "normalization")
    assert comparison.head_dirty is False
    assert calls == ["check-attr", "cat-file"]
