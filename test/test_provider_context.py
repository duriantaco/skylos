"""External-provider exemptions require conservative local-path evidence."""

from pathlib import Path
from importlib.machinery import all_suffixes

import pytest

from skylos.rules.quality._provider_context import project_local_provider


_PROVIDERS = ("click", "gettext", "operator", "sqlalchemy", "pydantic", "pandas")


@pytest.mark.parametrize("module", _PROVIDERS)
@pytest.mark.parametrize("layout", ["{module}.py", "{module}", "src/{module}.py", "src/{module}"])
def test_local_module_or_package_cannot_prove_an_external_contract(tmp_path, module, layout):
    provider = tmp_path / layout.format(module=module)
    provider.parent.mkdir(parents=True, exist_ok=True)
    if provider.suffix:
        provider.write_text("raise AssertionError('provider code must not execute')\n")
    else:
        provider.mkdir()
    assert project_local_provider(module, tmp_path / "consumer.py", tmp_path)


@pytest.mark.parametrize("module", _PROVIDERS)
@pytest.mark.parametrize("relative", ["consumer.py", "src/app/consumer.py"])
def test_absent_local_provider_preserves_external_import_evidence(tmp_path, module, relative):
    filename = tmp_path / relative
    filename.parent.mkdir(parents=True, exist_ok=True)
    assert not project_local_provider(module, filename, tmp_path)


@pytest.mark.parametrize("module", _PROVIDERS)
def test_source_directory_provider_is_checked_without_importing(tmp_path, module):
    package = tmp_path / "app"
    package.mkdir()
    (package / f"{module}.py").write_text("raise AssertionError('not executed')\n")
    assert project_local_provider(module, package / "consumer.py", tmp_path)


@pytest.mark.parametrize("suffix", [value for value in all_suffixes() if value != ".py"])
@pytest.mark.parametrize("directory", ["", "src"])
def test_bytecode_and_native_provider_files_are_metadata_only(tmp_path, suffix, directory):
    provider = tmp_path / directory / f"gettext{suffix}"
    provider.parent.mkdir(parents=True, exist_ok=True)
    provider.write_bytes(b"inert provider fixture; never load this file")
    assert project_local_provider("gettext", tmp_path / "consumer.py", tmp_path)


@pytest.mark.parametrize("module", _PROVIDERS)
def test_package_itself_as_scan_root_is_a_local_provider(tmp_path, module):
    root = tmp_path / module
    root.mkdir()
    (root / "__init__.py").write_text("raise AssertionError('not executed')\n")
    assert project_local_provider(module, root / "consumer.py", root)


@pytest.mark.parametrize("module", _PROVIDERS)
def test_project_folder_name_alone_is_not_a_local_package_proof(tmp_path, module):
    root = tmp_path / module
    root.mkdir()
    assert not project_local_provider(module, root / "consumer.py", root)


@pytest.mark.parametrize("module", _PROVIDERS)
def test_ast_only_provider_evidence_retains_compatibility(module):
    assert not project_local_provider(module)


@pytest.mark.parametrize("module", ["", "../click", "click/inner", "click.inner", "/click", "for", "a\\b", None, 1])
def test_invalid_provider_identifiers_are_rejected_before_path_access(module, monkeypatch):
    def metadata_must_not_be_read(path, *args, **kwargs):
        raise AssertionError("invalid provider reached a filesystem probe")

    monkeypatch.setattr(Path, "lstat", metadata_must_not_be_read)
    assert project_local_provider(module, "/project/consumer.py", "/project")


@pytest.mark.parametrize("entry", ["gettext.py", "gettext", "src"])
def test_symlinked_provider_or_search_path_is_unknown(tmp_path, entry):
    (tmp_path / entry).symlink_to(tmp_path / "absent-target")
    assert project_local_provider("gettext", tmp_path / "consumer.py", tmp_path)


def test_outside_root_and_unavailable_paths_preserve_uncertainty(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    assert project_local_provider("operator", tmp_path / "consumer.py", root)
    assert project_local_provider("operator", root / "consumer.py", root / "missing")
