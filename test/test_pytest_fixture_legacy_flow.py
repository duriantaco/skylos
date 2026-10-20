"""Provider proof preserves existing builtin flow under unsupported syntax.

The same fallback never grants ownership to new custom/factory contexts.
"""

import ast

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.danger.danger_fs.path_flow import scan
from test.test_pytest_fixture_path_provenance import _rules, _scan


def _unversioned(tmp_path, source, *, filename="test_storage.py", files=None):
    path = tmp_path / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    for relative, text in (files or {}).items():
        dependency = tmp_path / relative
        dependency.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(dependency, text)
    assert write_text_no_symlink(path, source)
    rows = []
    scan(ast.parse(source), path, rows)
    return rows


def test_nested_definition_and_standard_join_preserve_legacy_builtin(tmp_path):
    source = 'import os\nimport pytest\ndef test_write(tmpdir):\n    def callback(*args, **kwargs):\n        raise TimeoutError\n    path = os.path.join(tmpdir, "document.txt")\n    with open(path, "w") as output:\n        output.write("fixture")\n'
    assert not _rules(_scan(tmp_path, source))


def test_readonly_path_wrapper_and_nested_definition_preserve_legacy_flow(tmp_path):
    source = 'import pytest\ndef test_write(tmp_path):\n    first = tmp_path.resolve() / "first"\n    first.mkdir()\n    (first / "document").write_text("fixture")\n    def callback():\n        return service()\n    second = tmp_path.resolve() / "second"\n    second.mkdir()\n    (second / "document").write_text("fixture")\n'
    assert not _rules(_scan(tmp_path, source))


def test_unsupported_branch_uses_existing_builtin_taint_flow(tmp_path):
    source = 'import pytest\ndef test_write(tmp_path, enabled):\n    if enabled:\n        (tmp_path / "namespace").mkdir()\n    (tmp_path / "document").write_text("fixture")\n'
    assert not _rules(_scan(tmp_path, source))


def test_rebinding_inside_branch_still_keeps_attacker_input_visible(tmp_path):
    source = 'from pathlib import Path\nimport pytest\ndef test_write(tmp_path, enabled):\n    if enabled:\n        tmp_path = Path(input())\n    (tmp_path / "document").write_text("fixture")\n'
    assert "SKY-D324" in _rules(_scan(tmp_path, source))


def test_untrusted_join_component_still_keeps_warning(tmp_path):
    source = 'import os\nimport pytest\ndef test_write(tmpdir):\n    def callback():\n        pass\n    path = os.path.join(tmpdir, input())\n    with open(path, "w") as output:\n        output.write("fixture")\n'
    assert "SKY-D324" in _rules(_scan(tmp_path, source))


def test_nested_definition_executes_mutating_default_expression(tmp_path):
    source = 'import pytest\ndef test_write(tmp_path):\n    path = tmp_path / "document"\n    def callback(value=path.symlink_to(input())):\n        pass\n    path.write_text("fixture")\n'
    assert "SKY-D324" in _rules(_scan(tmp_path, source))


def test_deferred_annotation_does_not_execute_nested_path_expression(tmp_path):
    source = 'from __future__ import annotations\nimport pytest\ndef test_write(tmp_path):\n    path = tmp_path / "document"\n    def callback(value: path.symlink_to(input())):\n        pass\n    path.write_text("fixture")\n'
    assert not _rules(_scan(tmp_path, source))


def test_custom_provider_keeps_strict_proof_across_readonly_wrapper(tmp_path):
    source = 'import pytest\n@pytest.fixture\ndef prepared(tmp_path):\n    return tmp_path\ndef test_write(prepared):\n    target = prepared.resolve() / "document"\n    target.write_text("fixture")\n'
    assert "SKY-D215" in _rules(_scan(tmp_path, source))


def test_standard_join_does_not_trust_overridden_builtin_provider(tmp_path):
    source = 'from pathlib import Path\nimport os\nimport pytest\n@pytest.fixture\ndef tmpdir():\n    return Path(input())\ndef test_write(tmpdir):\n    def callback():\n        pass\n    with open(os.path.join(tmpdir, "document"), "w") as output:\n        output.write("fixture")\n'
    assert "SKY-D324" in _rules(_scan(tmp_path, source))


def test_unversioned_default_collection_preserves_legacy_builtin(tmp_path):
    source = (
        'def test_write(tmp_path):\n    (tmp_path / "document").write_text("fixture")\n'
    )
    assert not _rules(_unversioned(tmp_path, source))


@pytest.mark.parametrize(
    "source, filename, files",
    [
        (
            'def save(tmp_path):\n    (tmp_path / "document").write_text("fixture")\n',
            "service.py",
            {},
        ),
        (
            'import pytest\n@pytest.fixture\ndef tmp_path():\n    return external_path\ndef test_write(tmp_path):\n    (tmp_path / "document").write_text("fixture")\n',
            "test_storage.py",
            {},
        ),
        (
            'def test_write(tmp_path):\n    (tmp_path / "document").write_text("fixture")\n',
            "tests/test_storage.py",
            {
                "conftest.py": "import pytest\n@pytest.fixture\ndef tmp_path():\n    return external_path\n"
            },
        ),
        (
            'import pytest\n@pytest.fixture\ndef prepared(tmp_path):\n    return tmp_path / "document"\ndef test_write(prepared):\n    prepared.write_text("fixture")\n',
            "test_storage.py",
            {},
        ),
        (
            'def test_write(tmp_path_factory):\n    (tmp_path_factory.mktemp("directory") / "document").write_text("fixture")\n',
            "test_storage.py",
            {},
        ),
    ],
)
def test_unversioned_context_keeps_lookalikes_and_new_extensions(
    tmp_path, source, filename, files
):
    symbol = "test_write"
    if filename == "service.py":
        symbol = "save"
    assert "SKY-D324" in _rules(
        _unversioned(tmp_path, source, filename=filename, files=files), symbol
    )
