"""Static auth comparison must retain history behind unsupported selectors."""

import json
import os
from pathlib import Path
import subprocess

import pytest

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.security.contracts import resolve_diff_base_ref


PROTECTED = (
    "from django.contrib.auth.decorators import login_required\n"
    "\n@login_required\ndef export_customer(request):\n    return 42\n"
)


@pytest.fixture(autouse=True)
def local_comparison_context(monkeypatch):
    # These cases deliberately exercise comparison without an explicit base.
    # Keep CI's GITHUB_BASE_REF hint, but prevent unrelated Git hook context
    # and an explicit base/config from selecting another fixture's history.
    for name in tuple(os.environ):
        if name.startswith("GIT_") or name in {
            "SKYLOS_DIFF_BASE",
            "SKYLOS_POLICY_BASE",
            "SKYLOS_CONFIG_FILE",
        }:
            monkeypatch.delenv(name, raising=False)


def _write(path, content):
    assert write_text_no_symlink(path, content)


def _git(root, *arguments):
    return subprocess.run(
        [
            "git",
            "-c",
            f"core.hooksPath={os.devnull}",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            *arguments,
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()


def _renamed_repo(tmp_path, retained):
    root = tmp_path / "source"
    root.mkdir()
    _write(root / "views.py", PROTECTED)
    # Avoid matching CI's normal `main` hint: this is the no-base guard arm.
    _git(root, "init", "-q", "-b", "scope-fixture-base")
    _git(root, "add", "views.py")
    _git(root, "commit", "-qm", "protected fixture base")
    _git(root, "mv", "views.py", "handlers.vue")
    target = root / "handlers.vue"
    _write(
        target, PROTECTED if retained else PROTECTED.replace("@login_required\n", "")
    )
    return root, target


def _scan(root, target, *, use_changed_selector=True):
    assert resolve_diff_base_ref(root) is None
    result = json.loads(
        analyze(
            str(root),
            changed_files={str(target)} if use_changed_selector else None,
            enable_quality=True,
            enable_danger=True,
            grep_verify=False,
            trace_file=False,
        )
    )
    assert "error" not in result, result
    assert result["analysis_summary"]["total_files"] == 0
    return result


@pytest.mark.parametrize("external_metadata", [False, True])
@pytest.mark.parametrize("retained", [False, True])
@pytest.mark.parametrize("use_changed_selector", [False, True])
def test_unsupported_rename_keeps_auth_history_without_base(
    tmp_path, monkeypatch, external_metadata, retained, use_changed_selector
):
    root, target = _renamed_repo(tmp_path, retained)
    if external_metadata:
        metadata = tmp_path / "git-metadata"
        (root / ".git").rename(metadata)
        monkeypatch.setenv("GIT_DIR", str(metadata))
        monkeypatch.setenv("GIT_WORK_TREE", str(root))
        assert not (root / ".git").exists()

    result = _scan(root, target, use_changed_selector=use_changed_selector)

    assert result.get("analysis_errors", []) == []
    findings = [
        finding
        for finding in result.get("quality", [])
        if finding.get("rule_id") == "SKY-L021"
    ]
    assert len(findings) == (0 if retained else 1)
    if findings:
        finding = findings[0]
        assert finding["kind"] == "security_regression"
        assert finding["severity"] == "HIGH"
        assert finding["control_type"] == "auth"
        assert Path(finding["file"]) == target
        assert finding["basename"] == "handlers.vue"
        assert finding["line"] > 0
        assert "login_required" in finding["message"]
        assert "export_customer" in finding["message"]


def test_unsupported_selector_cannot_skip_invalid_external_git_metadata(
    tmp_path, monkeypatch
):
    root, target = _renamed_repo(tmp_path, retained=True)
    (root / ".git").rename(tmp_path / "git-metadata")
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "missing-metadata"))
    monkeypatch.setenv("GIT_WORK_TREE", str(root))

    result = _scan(root, target)

    assert len(result["analysis_errors"]) == 1
    error = result["analysis_errors"][0]
    assert error["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"
    assert error["kind"] == "security_regression_unavailable"
    assert result["analysis_summary"]["analysis_error_count"] == 1


def test_zero_source_changed_selector_does_not_include_other_renamed_handlers(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    other_protected = PROTECTED.replace("export_customer", "export_invoice").replace(
        "return 42", 'return "invoice"'
    )
    originals = {"views.py": PROTECTED, "invoices.py": other_protected}
    for name, content in originals.items():
        _write(root / name, content)
    _git(root, "init", "-q", "-b", "scope-fixture-base")
    _git(root, "add", "views.py", "invoices.py")
    _git(root, "commit", "-qm", "two protected handlers")
    for original, content in originals.items():
        renamed = Path(original).with_suffix(".vue").name
        _git(root, "mv", original, renamed)
        _write(root / renamed, content.replace("@login_required\n", ""))
    selected = root / "views.vue"

    result = _scan(root, selected)

    assert result.get("analysis_errors", []) == []
    findings = [
        item for item in result.get("quality", []) if item.get("rule_id") == "SKY-L021"
    ]
    assert len(findings) == 1
    assert Path(findings[0]["file"]) == selected
    assert findings[0]["control_type"] == "auth"
    assert "export_customer" in findings[0]["message"]
    assert "export_invoice" not in findings[0]["message"]


@pytest.mark.parametrize(
    "metadata",
    [
        "nongit",
        "unborn",
        "bad-marker",
        "dangling-marker",
        "dangling-parent-marker",
        "missing-external-metadata",
        "history-missing-head",
        "history-broken-head",
        "history-unsafe-filter",
    ],
)
def test_zero_source_full_scan_distinguishes_absent_and_unavailable_history(
    tmp_path, monkeypatch, metadata
):
    root = tmp_path / "pkg" if metadata == "dangling-parent-marker" else tmp_path
    root.mkdir(exist_ok=True)
    target = root / "App.vue"
    _write(target, "<template><p>hello</p></template>\n")
    if metadata == "unborn" or metadata.startswith("history-"):
        _git(root, "init", "-q", "-b", "scope-fixture-base")
        if metadata.startswith("history-"):
            _git(root, "add", "App.vue")
            _git(root, "commit", "-qm", "unsupported fixture history")
            if metadata == "history-missing-head":
                (root / ".git" / "HEAD").rename(root / ".git" / "HEAD.saved")
            elif metadata == "history-broken-head":
                _write(root / ".git" / "HEAD", "broken-head\n")
            else:
                _git(root, "config", "filter.bad/driver.clean", "NEVER_EXECUTE")
    elif metadata == "bad-marker":
        _write(root / ".git", "gitdir: missing-metadata\n")
    elif metadata in {"dangling-marker", "dangling-parent-marker"}:
        (tmp_path / ".git").symlink_to(tmp_path / "missing-metadata")
    elif metadata == "missing-external-metadata":
        monkeypatch.setenv("GIT_DIR", str(tmp_path / "missing-metadata"))
        monkeypatch.setenv("GIT_WORK_TREE", str(root))

    result = _scan(root, target, use_changed_selector=False)

    if metadata in {"nongit", "unborn"}:
        assert result.get("analysis_errors", []) == []
    else:
        assert len(result["analysis_errors"]) == 1
        error = result["analysis_errors"][0]
        assert error["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"
        assert error["kind"] == "security_regression_unavailable"
        assert result["analysis_summary"]["analysis_error_count"] == 1
    assert result.get("quality", []) == []
