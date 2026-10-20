"""Explicit nested project scans retain advice beneath an ancestor sample folder."""

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.reporting.advice_scope import advice_source_context


def _write(root, relative, source="def process(value):\n    return value\n"):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, source)
    return path


def _advice(path):
    return {"rule_id": "SKY-Q301", "file": str(path), "line": 1}


def _checkout(root, boundary):
    if boundary == "git-directory":
        (root / ".git").mkdir()
    elif boundary == "git-file":
        _write(root, ".git", "gitdir: /unused/worktree/metadata\n")
    _write(root, "pyproject.toml", '[project]\nname = "workspace"\n')


@pytest.mark.parametrize("boundary", ["git-directory", "git-file", "archive"])
@pytest.mark.parametrize(
    "identity", ['[project]\nname = "realapp"\n', '[tool.poetry]\nname = "realapp"\n']
)
@pytest.mark.parametrize("sample_folder", ["examples", "docs_src", "benchmarks"])
def test_explicit_nested_app_uses_its_own_sample_conventions(
    tmp_path, boundary, identity, sample_folder
):
    _checkout(tmp_path, boundary)
    project = tmp_path / sample_folder / "realapp"
    _write(project, "pyproject.toml", identity)
    path = _write(project, "app/service.py")
    expected = "profiling" if sample_folder == "benchmarks" else "example"
    assert advice_source_context(_advice(path), tmp_path) == expected
    for scan_root in (project, project / "app"):
        assert advice_source_context(_advice(path), scan_root) is None
        assert (
            advice_source_context(_advice(path.relative_to(scan_root)), scan_root)
            is None
        )


@pytest.mark.parametrize("boundary", ["git-directory", "git-file", "archive"])
def test_nested_app_own_examples_still_remain_optional(tmp_path, boundary):
    _checkout(tmp_path, boundary)
    project = tmp_path / "examples/realapp"
    _write(project, "pyproject.toml", '[project]\nname = "realapp"\n')
    path = _write(project, "examples/demo.py")
    for scan_root in (tmp_path, project, project / "examples"):
        assert advice_source_context(_advice(path), scan_root) == "example"


@pytest.mark.parametrize("module", ["bench", "examples", "docs_src"])
@pytest.mark.parametrize("scan_subdir", [".", "src"])
def test_nested_app_shipping_evidence_survives_sample_context_merge(
    tmp_path, module, scan_subdir
):
    _checkout(tmp_path, "git-directory")
    project = tmp_path / "examples/realapp"
    _write(project, "pyproject.toml", '[project]\nname = "realapp"\n')
    _write(project, "src/shop/__init__.py", "")
    path = _write(project, f"src/shop/{module}/service.py")
    assert advice_source_context(_advice(path), project / scan_subdir) is None


@pytest.mark.parametrize(
    "metadata",
    [
        "[project]\n",
        '[project]\nname = ""\n',
        '[project]\nname = ["realapp"]\n',
        '[project]\nname = "not a project identity"\n',
        '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n',
        "not valid TOML [",
    ],
)
def test_marker_without_parsed_project_identity_does_not_override_checkout_samples(
    tmp_path, metadata
):
    _checkout(tmp_path, "git-directory")
    project = tmp_path / "examples/realapp"
    _write(project, "pyproject.toml", metadata)
    path = _write(project, "app/service.py")
    assert advice_source_context(_advice(path), project) == "example"


def test_shipped_testing_api_keeps_checkout_test_anchor_with_nested_manifest(tmp_path):
    _checkout(tmp_path, "git-directory")
    _write(tmp_path, "widget/pyproject.toml", '[project]\nname = "widget"\n')
    path = _write(tmp_path, "widget/test/client.py")
    for root in (tmp_path, tmp_path / "widget", path.parent):
        assert advice_source_context(_advice(path), root) is None


def test_nested_project_does_not_override_checkout_pytest_collection(tmp_path):
    _checkout(tmp_path, "git-directory")
    _write(
        tmp_path,
        "pyproject.toml",
        '[project]\nname = "workspace"\n'
        "[tool.pytest.ini_options]\n"
        'testpaths = ["examples/realapp/app"]\npython_files = ["*.py"]\n',
    )
    project = tmp_path / "examples/realapp"
    _write(project, "pyproject.toml", '[project]\nname = "realapp"\n')
    path = _write(project, "app/service.py", "def test_process():\n    assert True\n")
    for scan_root in (tmp_path, project, project / "app"):
        assert advice_source_context(_advice(path), scan_root) == "test"


def test_nested_project_does_not_override_vendor_provenance(tmp_path):
    _checkout(tmp_path, "git-directory")
    project = tmp_path / "examples/realapp"
    _write(project, "pyproject.toml", '[project]\nname = "realapp"\n')
    path = _write(project, "copied/parser.py")
    _write(
        project,
        "copied/README.md",
        "This directory is copied from https://upstream.invalid/project.\n",
    )
    _write(project, "copied/LICENSE", "Copyright upstream. Permission granted.\n")
    assert advice_source_context(_advice(path), project) == "vendored"


def test_symlink_project_metadata_does_not_override_sample_context(tmp_path):
    _checkout(tmp_path, "git-directory")
    project = tmp_path / "examples/realapp"
    path = _write(project, "app/service.py")
    manifest = _write(tmp_path, "other.toml", '[project]\nname = "realapp"\n')
    (project / "pyproject.toml").symlink_to(manifest)
    assert advice_source_context(_advice(path), project) is None


def test_nested_scope_cannot_widen_scan_boundary_or_follow_source_symlinks(tmp_path):
    _checkout(tmp_path, "git-directory")
    project = tmp_path / "examples/realapp"
    _write(project, "pyproject.toml", '[project]\nname = "realapp"\n')
    path = _write(project, "app/service.py")
    outside = _write(tmp_path, "production.py")
    (project / "app/link.py").symlink_to(outside)
    assert advice_source_context(_advice(outside), project) is None
    assert advice_source_context(_advice("../../production.py"), project) is None
    assert advice_source_context(_advice(project / "app/link.py"), project) is None
    assert advice_source_context(_advice(path), project / "app") is None


def test_source_rewrite_invalidates_project_identity(tmp_path):
    _checkout(tmp_path, "git-directory")
    project = tmp_path / "examples/realapp"
    manifest = _write(project, "pyproject.toml", '[project]\nname = "realapp"\n')
    path = _write(project, "app/service.py")
    assert advice_source_context(_advice(path), project) is None
    assert write_text_no_symlink(manifest, "[project]\n")
    assert advice_source_context(_advice(path), project) == "example"


def test_project_metadata_and_source_are_never_executed(tmp_path):
    _checkout(tmp_path, "git-directory")
    project = tmp_path / "examples/realapp"
    _write(project, "pyproject.toml", '[project]\nname = "realapp"\n')
    _write(project, "setup.py", "raise AssertionError('do not execute metadata')\n")
    path = _write(
        project, "app/service.py", "raise AssertionError('do not execute source')\n"
    )
    assert advice_source_context(_advice(path), project) is None
