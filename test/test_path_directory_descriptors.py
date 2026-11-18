"""Directory-only descriptors are not file-content read operations."""

import pytest

from skylos.rules.danger.danger import scan_ctx
from test.fixture_paths import write_fixture


def _scan(
    tmp_path,
    flags,
    *,
    before="",
    arguments="path",
    extra="",
    operation="os.fsync(descriptor)",
):
    source = (
        "import os\n"
        + extra
        + before
        + "\n@app.get('/read')\n"
        + f"def read_directory({arguments}):\n"
        + f"    descriptor = os.open(path, {flags})\n"
        + "    try:\n"
        + f"        {operation}\n"
        + "    finally:\n"
        + "        os.close(descriptor)\n"
    )
    path = tmp_path / "app.py"
    write_fixture(tmp_path, (path).relative_to(tmp_path), source, overwrite=True)
    return {row["rule_id"] for row in scan_ctx(tmp_path, [path])}


@pytest.mark.parametrize(
    "flags, extra",
    [
        ("os.O_RDONLY | os.O_DIRECTORY", ""),
        ("os.O_DIRECTORY | os.O_RDONLY | os.O_CLOEXEC", ""),
        (
            "READ_ONLY | DIRECTORY",
            "from os import O_RDONLY as READ_ONLY, O_DIRECTORY as DIRECTORY\n",
        ),
    ],
)
def test_proven_directory_descriptor_has_no_file_read_finding(tmp_path, flags, extra):
    rules = _scan(tmp_path, flags, extra=extra)

    assert "SKY-D325" not in rules
    # O_DIRECTORY restricts the object type; it does not contain the path.
    assert "SKY-D215" in rules


@pytest.mark.parametrize(
    "flags",
    [
        "os.O_RDONLY",
        "os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0)",
        "os.O_RDONLY | os.O_DIRECTORY | extra_flags",
        "os.O_RDONLY | flags.O_DIRECTORY",
    ],
)
def test_unknown_or_file_capable_flags_keep_file_read_finding(tmp_path, flags):
    rules = _scan(
        tmp_path,
        flags,
        arguments="path, extra_flags, flags",
        operation="os.read(descriptor, 4097)",
    )

    assert "SKY-D325" in rules


@pytest.mark.parametrize(
    "before, arguments",
    [
        ("os.O_DIRECTORY = 0\n", "path"),
        ("os.O_RDONLY = replacement\n", "path"),
        ("setattr(os, 'O_DIRECTORY', 0)\n", "path"),
        ("", "path, os"),
        ("os.open = other_open\n", "path"),
    ],
)
def test_directory_spelling_does_not_prove_an_untampered_provider(
    tmp_path, before, arguments
):
    rules = _scan(
        tmp_path,
        "os.O_RDONLY | os.O_DIRECTORY",
        before=before,
        arguments=arguments,
    )

    assert "SKY-D325" in rules


def test_imported_provider_mutation_keeps_file_read_finding(tmp_path):
    write_fixture(
        tmp_path,
        (tmp_path / "patch_flags.py").relative_to(tmp_path),
        "import os\nos.O_DIRECTORY = 0\n",
        overwrite=True,
    )

    rules = _scan(
        tmp_path, "os.O_RDONLY | os.O_DIRECTORY", extra="import patch_flags\n"
    )

    assert "SKY-D325" in rules


def test_shadowed_imported_flag_is_not_a_directory_guarantee(tmp_path):
    rules = _scan(
        tmp_path,
        "READ_ONLY | DIRECTORY",
        arguments="path, DIRECTORY",
        extra="from os import O_RDONLY as READ_ONLY, O_DIRECTORY as DIRECTORY\n",
    )

    assert "SKY-D325" in rules


def test_project_provider_named_os_is_not_a_directory_guarantee(tmp_path):
    write_fixture(
        tmp_path,
        (tmp_path / "os.py").relative_to(tmp_path),
        "O_RDONLY = 0\nO_DIRECTORY = 0\n",
        overwrite=True,
    )

    rules = _scan(tmp_path, "os.O_RDONLY | os.O_DIRECTORY")

    assert "SKY-D325" in rules


def test_write_flags_keep_existing_write_check(tmp_path):
    rules = _scan(tmp_path, "os.O_WRONLY | os.O_DIRECTORY")

    assert "SKY-D324" in rules


_IDENTITY_READER = """def current_owner():
    query = getattr(os, 'geteuid', None)
    return int(query()) if query is not None else None
"""


@pytest.mark.parametrize(
    ("flags", "operation", "expected"),
    [
        ("os.O_RDONLY", "os.read(descriptor, 16)", {"SKY-D325"}),
        ("os.O_WRONLY", "os.write(descriptor, b'entry')", {"SKY-D324"}),
        ("os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0)", "os.fsync(descriptor)", set()),
    ],
)
def test_optional_native_identity_reader_preserves_descriptor_effects(
    tmp_path, flags, operation, expected
):
    rules = _scan(tmp_path, flags, extra=_IDENTITY_READER, operation=operation)
    assert rules & {"SKY-D324", "SKY-D325"} == expected
    assert "SKY-D215" in rules


@pytest.mark.parametrize(
    "mutation",
    [
        "import os\nos.O_RDONLY = os.O_RDWR\n",
        "import os\nos.geteuid = unknown_query\n",
        "import builtins\nbuiltins.getattr = unknown_getter\n",
        "import builtins\nbuiltins.int = unknown_converter\n",
    ],
)
def test_optional_identity_reader_with_imported_provider_writes_stays_reviewable(
    tmp_path, mutation
):
    write_fixture(tmp_path, "prepare.py", mutation, overwrite=True)
    rules = _scan(
        tmp_path,
        "os.O_RDONLY",
        extra="import prepare\n" + _IDENTITY_READER,
        operation="os.read(descriptor, 16)",
    )
    assert {"SKY-D324", "SKY-D325"} <= rules


@pytest.mark.parametrize(
    "reader",
    [
        _IDENTITY_READER.replace("int(query())", "register(query)"),
        _IDENTITY_READER.replace("int(query())", "query"),
        _IDENTITY_READER.replace("os, 'geteuid'", "os, field"),
        _IDENTITY_READER.replace("os, 'geteuid'", "os, '__getattribute__'"),
        _IDENTITY_READER.replace("getattr(os", "lookup(os"),
    ],
)
def test_optional_lookup_with_unproven_receiver_or_callable_escape_keeps_warning(
    tmp_path, reader
):
    rules = _scan(
        tmp_path, "os.O_RDONLY", extra=reader, operation="os.read(descriptor, 16)"
    )
    assert {"SKY-D324", "SKY-D325"} <= rules
