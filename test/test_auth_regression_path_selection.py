"""Security comparisons select Git paths before refusing symlink traversal."""

import json
import os
from pathlib import Path
import subprocess

import pytest

from skylos.analyzer import analyze
from skylos.config import ConfigError
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.security import regression_diff
from skylos.security.regression_gate import collect_control_regressions


PROTECTED = (
    "from django.contrib.auth.decorators import login_required\n"
    "\n@login_required\ndef export_customer(request):\n    return 42\n"
)
UNPROTECTED = PROTECTED.replace("@login_required\n", "")


@pytest.fixture(autouse=True)
def local_comparison_context(monkeypatch):
    for name in tuple(os.environ):
        if name.startswith("GIT_") or name in {
            "SKYLOS_DIFF_BASE",
            "SKYLOS_POLICY_BASE",
            "SKYLOS_CONFIG_FILE",
        }:
            monkeypatch.delenv(name, raising=False)


def _write(path, source):
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, source)


def _git(root, *arguments):
    subprocess.run(
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
    )


def _repo(tmp_path, *, extra_source=False):
    root = tmp_path / "source"
    root.mkdir()
    _write(root / "views.py", PROTECTED)
    if extra_source:
        _write(root / "app.py", "def helper():\n    return 42\n")
    _git(root, "init", "-q", "-b", "path-selection-fixture")
    files = ["views.py", *(["app.py"] if extra_source else [])]
    _git(root, "add", *files)
    _git(root, "commit", "-qm", "protected fixture base")
    return root


def _external_symlink(root, *, dangling=False):
    outside = root.parent / "external.py"
    if not dangling:
        _write(outside, UNPROTECTED)
    target = root / "views.py"
    target.rename(root.parent / "original.py")
    target.symlink_to(outside)
    return target, outside


def _observe_guarded_reader(monkeypatch, outside):
    """Inspect real descriptor opens without disabling the native safe reader."""
    original_open = os.open
    outside_stat = None if not outside.exists() else outside.stat()
    calls = []
    original_reader = regression_diff.read_project_text_no_symlink

    def guarded_open(path, flags, *arguments, **keywords):
        if not isinstance(path, int) and Path(path).is_absolute():
            assert Path(os.path.abspath(path)) != outside
        descriptor = original_open(path, flags, *arguments, **keywords)
        current = os.fstat(descriptor)
        if outside_stat is not None and (current.st_dev, current.st_ino) == (
            outside_stat.st_dev,
            outside_stat.st_ino,
        ):
            os.close(descriptor)
            pytest.fail("Security comparison opened the outside target")
        return descriptor

    def observed_reader(root, path, **keywords):
        calls.append((Path(root), Path(path)))
        return original_reader(root, path, **keywords)

    supported = set(os.supports_dir_fd)
    if original_open in supported:
        supported.add(guarded_open)
    monkeypatch.setattr(os, "supports_dir_fd", supported)
    monkeypatch.setattr(os, "open", guarded_open)
    monkeypatch.setattr(
        regression_diff, "read_project_text_no_symlink", observed_reader
    )
    return calls


@pytest.mark.parametrize("extra_source", [False, True])
@pytest.mark.parametrize("selected", [False, True])
@pytest.mark.parametrize("dangling", [False, True])
def test_static_scan_cannot_drop_changed_symlink_before_safe_reader(
    tmp_path, monkeypatch, extra_source, selected, dangling
):
    root = _repo(tmp_path, extra_source=extra_source)
    target, outside = _external_symlink(root, dangling=dangling)
    calls = _observe_guarded_reader(monkeypatch, outside)

    report = json.loads(
        analyze(
            str(root),
            changed_files={str(target)} if selected else None,
            enable_quality=True,
            enable_danger=True,
            grep_verify=False,
            trace_file=False,
        )
    )

    assert report["analysis_summary"]["total_files"] == int(extra_source)
    assert len(report["analysis_errors"]) == 1
    error = report["analysis_errors"][0]
    assert error["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"
    assert error["kind"] == "security_regression_unavailable"
    assert "bounded and symlink-free" in error["message"]
    assert calls == [(root, Path("views.py"))]


@pytest.mark.parametrize("selector", ["absolute", "relative", "normalized-relative"])
def test_collector_preserves_changed_symlink_git_identity(
    tmp_path, monkeypatch, selector
):
    root = _repo(tmp_path)
    target, outside = _external_symlink(root)
    calls = _observe_guarded_reader(monkeypatch, outside)
    changed = {
        "absolute": str(target),
        "relative": "views.py",
        "normalized-relative": "unused/../views.py",
    }[selector]

    with pytest.raises(ConfigError, match="bounded and symlink-free"):
        collect_control_regressions(str(root), {}, "HEAD", changed_files={changed})

    assert calls == [(root, Path("views.py"))]


@pytest.mark.parametrize(
    "selection", ["empty", "outside", "excluded", "other-directory"]
)
def test_unselected_or_excluded_symlink_is_not_compared(
    tmp_path, monkeypatch, selection
):
    root = _repo(tmp_path)
    target, outside = _external_symlink(root)
    calls = _observe_guarded_reader(monkeypatch, outside)
    other = root / "other"
    other.mkdir()
    path = str(other) if selection == "other-directory" else str(root)
    changed = (
        set()
        if selection == "empty"
        else {str(outside)}
        if selection == "outside"
        else {str(target)}
    )
    config = {"exclude": ["views.py"]} if selection == "excluded" else {}

    assert (
        collect_control_regressions(path, config, "HEAD", changed_files=changed) == []
    )
    assert calls == []


def test_selected_other_file_does_not_broaden_to_symlink(tmp_path, monkeypatch):
    root = _repo(tmp_path)
    _write(root / "invoices.py", PROTECTED.replace("export_customer", "export_invoice"))
    _git(root, "add", "invoices.py")
    _git(root, "commit", "-qm", "second protected fixture")
    _, outside = _external_symlink(root)
    invoice = root / "invoices.py"
    _write(invoice, UNPROTECTED.replace("export_customer", "export_invoice"))
    calls = _observe_guarded_reader(monkeypatch, outside)

    findings = collect_control_regressions(
        str(root), {}, "HEAD", changed_files={str(invoice)}
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SKY-L021"
    assert Path(findings[0]["file"]) == invoice
    assert calls == [(root, Path("invoices.py"))]


@pytest.mark.parametrize("selector", [None, "views.py", "absolute"])
def test_ordinary_auth_removal_stays_visible(tmp_path, selector):
    root = _repo(tmp_path)
    target = root / "views.py"
    _write(target, UNPROTECTED)
    changed = (
        None
        if selector is None
        else {str(target) if selector == "absolute" else selector}
    )

    findings = collect_control_regressions(str(root), {}, "HEAD", changed_files=changed)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SKY-L021"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["control_type"] == "auth"
    assert Path(findings[0]["file"]) == target


@pytest.mark.parametrize("extra_source", [False, True])
def test_static_scan_respects_explicit_base_file_exclusion(tmp_path, extra_source):
    root = _repo(tmp_path, extra_source=extra_source)
    _write(root / "views.py", UNPROTECTED)

    report = json.loads(
        analyze(
            str(root),
            exclude_folders=["views.py"],
            enable_quality=True,
            enable_danger=True,
            grep_verify=False,
            trace_file=False,
        )
    )

    assert report["analysis_summary"]["total_files"] == int(extra_source)
    assert report["analysis_errors"] == []
    assert not [
        item for item in report.get("quality", []) if item.get("rule_id") == "SKY-L021"
    ]


@pytest.mark.parametrize("alias_root", [False, True])
@pytest.mark.parametrize("selector", [None, "canonical", "alias"])
@pytest.mark.parametrize("unsupported_rename", [False, True])
def test_repository_alias_preserves_auth_comparison(
    tmp_path, alias_root, selector, unsupported_rename
):
    real = tmp_path / "real"
    real.mkdir()
    root = _repo(real)
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    aliased_root = alias / "source"
    filename = "handlers.vue" if unsupported_rename else "views.py"
    if unsupported_rename:
        _git(root, "mv", "views.py", filename)
    target = root / filename
    _write(target, UNPROTECTED)
    selected = (
        None if selector is None else {
            str((aliased_root if selector == "alias" else root) / filename)
        }
    )

    report = json.loads(analyze(
        str(aliased_root if alias_root else root),
        changed_files=selected,
        enable_quality=True, enable_danger=True,
        grep_verify=False, trace_file=False,
    ))

    assert report["analysis_errors"] == []
    assert report["analysis_summary"]["total_files"] == int(not unsupported_rename)
    findings = [item for item in report["quality"] if item["rule_id"] == "SKY-L021"]
    assert len(findings) == 1
    assert Path(findings[0]["file"]) == target
    assert findings[0]["control_type"] == "auth"


@pytest.mark.parametrize("extra_source", [False, True])
@pytest.mark.parametrize("selected", [False, True])
@pytest.mark.parametrize("dangling", [False, True])
def test_deleted_git_child_cannot_hide_parent_directory_symlink(
    tmp_path, monkeypatch, extra_source, selected, dangling
):
    root = _repo(tmp_path, extra_source=extra_source)
    package = root / "pkg"
    package.mkdir()
    _git(root, "mv", "views.py", "pkg/views.py")
    _git(root, "commit", "-qm", "protected package fixture")
    package.rename(tmp_path / "saved-package")
    outside = tmp_path / "external" / "views.py"
    if not dangling:
        _write(outside, UNPROTECTED)
    package.symlink_to(outside.parent, target_is_directory=True)
    calls = _observe_guarded_reader(monkeypatch, outside)
    target = package / "views.py"

    report = json.loads(analyze(
        str(root), changed_files={str(target)} if selected else None,
        enable_quality=True, enable_danger=True,
        grep_verify=False, trace_file=False,
    ))

    assert report["analysis_summary"]["total_files"] == int(extra_source)
    assert len(report["analysis_errors"]) == 1
    error = report["analysis_errors"][0]
    assert error["kind"] == "security_regression_unavailable"
    assert "bounded and symlink-free" in error["message"]
    assert calls == []


@pytest.mark.parametrize("extra_source", [False, True])
@pytest.mark.parametrize("selected", [False, True])
@pytest.mark.parametrize("directory", [False, True])
def test_genuine_source_deletion_remains_a_complete_comparison(
    tmp_path, extra_source, selected, directory
):
    root = _repo(tmp_path, extra_source=extra_source)
    target = root / "views.py"
    if directory:
        package = root / "pkg"
        package.mkdir()
        _git(root, "mv", "views.py", "pkg/views.py")
        _git(root, "commit", "-qm", "protected package fixture")
        target = package / "views.py"
        package.rename(tmp_path / "removed-package")
    else:
        target.rename(tmp_path / "removed.py")

    report = json.loads(analyze(
        str(root), changed_files={str(target)} if selected else None,
        enable_quality=True, enable_danger=True,
        grep_verify=False, trace_file=False,
    ))

    assert report["analysis_summary"]["total_files"] == int(extra_source)
    assert report["analysis_errors"] == []
    assert not [
        item for item in report.get("quality", []) if item["rule_id"] == "SKY-L021"
    ]
