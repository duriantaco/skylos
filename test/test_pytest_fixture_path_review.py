"""Independent controls for path-provider and escaped-directory evidence."""

import pytest

from test.test_pytest_fixture_path_provenance import _rules, _scan


@pytest.mark.parametrize(
    "mutation",
    [
        "mutate([tmp_path])",
        "registry = [tmp_path]\n    mutate(registry)",
        "mutate(directory={'root': tmp_path})",
    ],
)
def test_temp_directory_container_escape_retains_warning(tmp_path, mutation):
    # New custom-provider evidence is strict. The legacy builtin escape blind
    # spot remains explicit below; absence of an alarm is not safety proof.
    source = (
        "import pytest\n@pytest.fixture\ndef prepared(tmp_path):\n    return tmp_path\n"
        + "def test_write(prepared):\n    "
        + mutation.replace("tmp_path", "prepared")
        + '\n    (prepared / "file").write_text("x")\n'
        + "def test_builtin(tmp_path):\n    "
        + mutation
        + '\n    (tmp_path / "file").write_text("x")\n'
    )
    rows = _scan(tmp_path, source)
    assert "SKY-D324" in _rules(rows)
    assert not _rules(rows, "test_builtin")


def test_local_pathlib_provider_does_not_prove_fixture_constructor(tmp_path):
    source = (
        "import pytest\nfrom pathlib import Path\n"
        "@pytest.fixture\ndef prepared(tmp_path):\n    return Path(tmp_path)\n"
        'def test_write(prepared):\n    prepared.write_text("x")\n'
    )
    provider = "def Path(value):\n    return external_path\n"
    rows = _scan(tmp_path, source, files={"pathlib.py": provider})
    assert "SKY-D324" in _rules(rows)


def test_escaped_constructor_does_not_prove_fixture_return(tmp_path):
    source = (
        "import pytest\nfrom pathlib import Path\n"
        "configure(Path)\n"
        "@pytest.fixture\ndef prepared(tmp_path):\n    return Path(tmp_path)\n"
        'def test_write(prepared):\n    prepared.write_text("x")\n'
    )
    assert "SKY-D324" in _rules(_scan(tmp_path, source))


@pytest.mark.parametrize(
    "escape",
    [
        "configure(importlib.util)",
        "registry = [importlib.util]\nconfigure(registry)",
    ],
)
def test_escaped_find_spec_provider_is_not_metadata_only(tmp_path, escape):
    source = 'import pytest\n@pytest.fixture\ndef prepared(tmp_path):\n    return tmp_path / "file"\ndef test_write(prepared):\n    prepared.write_text("x")\ndef test_builtin(tmp_path):\n    (tmp_path / "file").write_text("x")\n'
    application = (
        "import importlib.util\n" + escape + "\n"
        "def locate(name):\n"
        "    spec = importlib.util.find_spec(name)\n"
        "    return spec.origin\n"
    )
    rows = _scan(tmp_path, source, files={"application.py": application})
    assert "SKY-D324" in _rules(rows)
    assert not _rules(rows, "test_builtin")


def test_pytest_call_hook_can_replace_resolved_fixture_argument(tmp_path):
    source = 'import pytest\ndef test_write(tmp_path):\n    (tmp_path / "file").write_text("x")\n'
    hook = (
        "def pytest_pyfunc_call(pyfuncitem):\n"
        "    pyfuncitem.funcargs['tmp_path'] = external_path\n"
    )
    rows = _scan(tmp_path, source, files={"tests/conftest.py": hook})
    assert "SKY-D324" in _rules(rows)
