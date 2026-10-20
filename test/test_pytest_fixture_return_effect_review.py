"""A returned helper call must still account for mutation of a temp path."""

from test.test_pytest_fixture_path_provenance import _rules, _scan


def test_returned_opaque_mutator_invalidates_caller_directory_proof(tmp_path):
    source = (
        "import pytest\n"
        "@pytest.fixture\ndef prepared(tmp_path):\n    return tmp_path\n"
        "def prepare(path):\n"
        "    return mutate(path)\n"
        "def test_write(prepared):\n"
        "    prepare(prepared)\n"
        '    (prepared / "file").write_text("x")\n'
        "def test_builtin(tmp_path):\n"
        "    prepare(tmp_path)\n"
        '    (tmp_path / "file").write_text("x")\n'
    )
    rows = _scan(tmp_path, source)
    assert "SKY-D324" in _rules(rows)
    # Existing builtin opaque-call behavior is preserved, not proven safe.
    assert not _rules(rows, "test_builtin")


def test_pytest_default_argument_does_not_receive_named_fixture(tmp_path):
    source = (
        "import pytest\n"
        "@pytest.fixture\ndef prepared(tmp_path):\n"
        '    return tmp_path / "file"\n'
        "def test_write(prepared=outside_path):\n"
        '    prepared.write_text("x")\n'
    )
    assert "SKY-D324" in _rules(_scan(tmp_path, source))


def test_unproved_constructor_return_can_mutate_owned_argument(tmp_path):
    source = (
        "import pytest\nfrom pathlib import Path\n"
        "configure(Path)\n"
        "@pytest.fixture\ndef prepared(tmp_path):\n    return tmp_path\n"
        "def prepare(path):\n"
        "    return Path(path)\n"
        "def test_write(prepared):\n"
        "    prepare(prepared)\n"
        '    (prepared / "file").write_text("x")\n'
        "def test_builtin(tmp_path):\n"
        "    prepare(tmp_path)\n"
        '    (tmp_path / "file").write_text("x")\n'
    )
    rows = _scan(tmp_path, source)
    assert "SKY-D324" in _rules(rows)
    assert not _rules(rows, "test_builtin")
