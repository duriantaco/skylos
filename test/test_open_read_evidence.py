"""A '+' mode is not evidence that the opened handle's contents are read."""

import ast
import textwrap

import pytest

from skylos.rules.danger.danger_fs.open_read_evidence import UpdateHandleReads
from skylos.rules.danger.danger_fs.path_flow import scan
from test.fixture_paths import write_fixture


def _observed(source):
    tree = ast.parse(textwrap.dedent(source))
    calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            calls.append(node)
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "open":
            calls.append(node)
    calls.sort(key=lambda call: (call.lineno, call.col_offset))
    assert calls
    return UpdateHandleReads(tree).observed(calls[0])


@pytest.mark.parametrize(
    "method", ["read", "read1", "readline", "readlines", "readinto", "readinto1"]
)
def test_immediate_read_uses_exact_opened_handle(method):
    assert _observed(f"def operate(path): return open(path, 'r+').{method}()")


@pytest.mark.parametrize(
    "body",
    [
        "return handle.read()",
        "alias = handle\nreturn alias.readline()",
        "for row in handle:\n    pass",
        "rows = [row for row in handle]",
        "return list(handle)",
        "return next(handle)",
        "return next(iter(handle))",
    ],
)
def test_direct_local_single_binding_read_and_iteration(body):
    source = "def operate(path):\n    handle = open(path, 'a+b')\n" + textwrap.indent(
        body, "    "
    )
    assert _observed(source)


@pytest.mark.parametrize(
    "body",
    ["handle.read()", "alias = handle\nalias.read()", "for row in handle:\n    pass"],
)
def test_with_as_binding_and_exact_aliases_are_observed(body):
    source = (
        "def operate(path):\n    with open(path, 'r+b') as handle:\n"
        + textwrap.indent(body, "        ")
    )
    assert _observed(source)


@pytest.mark.parametrize(
    "body",
    [
        "handle.truncate(100)",
        "handle.write(b'payload')",
        "handle.seek(0)\nhandle.flush()\nhandle.fileno()",
        "other.read()",
        "handle = other\nhandle.read()",
        "handle = other if condition else handle\nhandle.read()",
        "def nested():\n    return handle.read()",
        "class Reader:\n    def read(self): return handle.read()",
        "callback = lambda: handle.read()",
        "rows = (row for row in handle)",
        "consume(handle)",
        "return handle",
    ],
)
def test_capacity_unrelated_receivers_rebinding_and_uncalled_scopes_are_not_reads(body):
    source = "def operate(path):\n    handle = open(path, 'a+b')\n" + textwrap.indent(
        body, "    "
    )
    assert not _observed(source)


def test_with_handle_read_after_context_exit_is_not_a_live_read():
    assert not _observed(
        "def operate(path):\n    with open(path, 'r+') as handle:\n        handle.write('data')\n    return handle.read()"
    )


def test_ordinary_consumer_name_is_not_assumed_to_be_a_builtin_reader():
    assert not _observed(
        "def list(value): return value\ndef operate(path):\n    handle = open(path, 'r+')\n    return list(handle)"
    )


def test_attribute_stored_open_handle_does_not_invent_downstream_reads():
    assert not _observed(
        "def operate(self, path):\n    self.handle = open(path, 'a+')\n    return self.handle"
    )


def test_bound_path_open_can_be_read_through_its_own_handle():
    assert _observed(
        "def operate(path):\n    with path.open('r+b') as handle:\n        return handle.read()"
    )


def _rules(tmp_path, body, mode="r+b"):
    source = (
        "def operate(path, other):\n    with open(path, '"
        + mode
        + "') as handle:\n"
        + textwrap.indent(body, "        ")
    )
    write_fixture(tmp_path, "pyproject.toml", "[project]\nname = 'observed-read'\n")
    path = write_fixture(tmp_path, "service.py", source)
    findings = []
    scan(ast.parse(source), path, findings)
    result = set()
    for row in findings:
        if row.get("symbol") == "operate":
            result.add(row["rule_id"])
    return result


def test_update_mode_write_only_operation_preserves_existing_write_checks(tmp_path):
    assert _rules(tmp_path, "handle.truncate(100)") == {"SKY-D215", "SKY-D324"}


def test_update_mode_actual_handle_read_retains_read_and_write_checks(tmp_path):
    assert _rules(tmp_path, "return handle.read()") == {
        "SKY-D215",
        "SKY-D324",
        "SKY-D325",
    }


def test_update_mode_unrelated_reader_does_not_add_read_claim(tmp_path):
    assert _rules(tmp_path, "return other.read()") == {"SKY-D215", "SKY-D324"}


def test_readonly_mode_keeps_existing_read_check_without_consumption(tmp_path):
    assert _rules(tmp_path, "return handle", mode="rb") == {"SKY-D215", "SKY-D325"}


def _source_rules(tmp_path, source):
    source = textwrap.dedent(source)
    write_fixture(
        tmp_path, "pyproject.toml", "[project]\nname = 'mode-read-coverage'\n"
    )
    path = write_fixture(tmp_path, "service.py", source)
    findings = []
    scan(ast.parse(source), path, findings)
    result = set()
    for row in findings:
        if row.get("symbol") == "operate":
            result.add(row["rule_id"])
    return result


@pytest.mark.parametrize(
    "source",
    [
        """
        def operate(path, other):
            mode = 'r+'
            handle = open(path, mode)
            content = handle.read()
            handle = other
            return content
        """,
        """
        def operate(path, other):
            mode = 'r+'
            with open(path, mode) as handle:
                content = handle.read()
                handle = other
                return content
        """,
        """
        def operate(path):
            mode = 'r+'
            handle = open(path, mode)
            def read_contents():
                return handle.read()
            return read_contents()
        """,
        """
        def read_contents(handle):
            return handle.read()
        def operate(path):
            mode = 'r+'
            handle = open(path, mode)
            return read_contents(handle)
        """,
        """
        def operate(path):
            mode = 'r+'
            return open(path, mode)
        """,
        """
        def operate(path, text):
            original = 'r+' if text else 'w+'
            mode = original
            return open(path, mode)
        """,
        """
        def operate(path, text):
            return open(path, 'r+' if text else 'w+')
        """,
    ],
)
def test_resolved_update_modes_preserve_reads_beyond_exact_handle_model(
    tmp_path, source
):
    assert _source_rules(tmp_path, source) == {
        "SKY-D215",
        "SKY-D324",
        "SKY-D325",
    }


@pytest.mark.parametrize("mode", ["'r+'", "'w+'", "'a+'"])
def test_literal_update_mode_without_read_keeps_existing_write_checks(tmp_path, mode):
    source = "def operate(path):\n    return open(path, " + mode + ")\n"
    assert _source_rules(tmp_path, source) == {"SKY-D215", "SKY-D324"}


def test_resolved_pure_write_alias_still_removes_default_read_noise(tmp_path):
    source = """
    def operate(path, text):
        original = 'w' if text else 'wb'
        mode = original
        return open(path, mode)
    """
    assert _source_rules(tmp_path, source) == {"SKY-D215", "SKY-D324"}
