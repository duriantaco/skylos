"""Nested native layout fields retain their actual class declaration owner."""

import json
import textwrap

import pytest

from skylos.analyzer import analyze
from test.fixture_paths import write_fixture


def _scan(tmp_path, source):
    write_fixture(
        tmp_path,
        "paths.py",
        textwrap.dedent(source).lstrip(),
        overwrite=True,
    )
    result = json.loads(analyze(str(tmp_path), conf=60, grep_verify=True))
    assert not result.get("analysis_errors")
    return result


def _variables(result, simple_name):
    return {
        row.get("full_name") or row["name"]
        for row in result.get("unused_variables", [])
        if row.get("simple_name") == simple_name
    }


@pytest.mark.parametrize(
    ("imports", "base", "field_type", "pointer"),
    [
        ("import ctypes", "ctypes.Structure", "ctypes.c_uint32", "ctypes.POINTER"),
        ("import ctypes", "ctypes.Union", "ctypes.c_uint32", "ctypes.POINTER"),
        (
            "import ctypes as native",
            "native.Structure",
            "native.c_uint32",
            "native.POINTER",
        ),
        (
            "from ctypes import Structure as Native, c_uint32, POINTER",
            "Native",
            "c_uint32",
            "POINTER",
        ),
    ],
)
def test_nested_native_layout_keeps_only_the_documented_field(
    tmp_path, imports, base, field_type, pointer
):
    result = _scan(
        tmp_path,
        f"""
        def build_pointer():
            {imports}
            class ACL({base}):
                _fields_ = [("count", {field_type})]
                unused_note = 3
            return {pointer}(ACL)

        pointer_type = build_pointer()
        """,
    )

    assert not _variables(result, "_fields_")
    assert _variables(result, "unused_note")


def test_nested_plain_structure_does_not_supply_a_native_layout_contract(tmp_path):
    result = _scan(
        tmp_path,
        """
        class Structure:
            pass

        def build_pointer():
            class ACL(Structure):
                _fields_ = [("count", int)]
            return ACL

        pointer_type = build_pointer()
        """,
    )

    assert _variables(result, "_fields_")


def test_function_local_fields_inside_a_native_class_remain_reported(tmp_path):
    result = _scan(
        tmp_path,
        """
        import ctypes

        class ACL(ctypes.Structure):
            _fields_ = [("count", ctypes.c_uint32)]

            def get_value(self):
                _fields_ = object()
                return 0

        print(ACL().get_value())
        """,
    )

    assert _variables(result, "_fields_") == {"paths.ACL.get_value._fields_"}


def test_module_native_layout_retains_the_existing_contract(tmp_path):
    result = _scan(
        tmp_path,
        """
        import ctypes

        class ACL(ctypes.Structure):
            _fields_ = [("count", ctypes.c_uint32)]

        pointer_type = ctypes.POINTER(ACL)
        """,
    )

    assert not _variables(result, "_fields_")


def test_array_does_not_supply_a_structure_fields_contract(tmp_path):
    result = _scan(
        tmp_path,
        """
        def build_array():
            import ctypes
            class Buffer(ctypes.Array):
                _type_ = ctypes.c_char
                _length_ = 1
                _fields_ = [("count", ctypes.c_uint32)]
            return Buffer

        array_type = build_array()
        """,
    )

    assert _variables(result, "_fields_")


def test_class_body_global_write_is_not_a_native_layout_field(tmp_path):
    result = _scan(
        tmp_path,
        """
        def build_pointer():
            import ctypes
            class ACL(ctypes.Structure):
                global _fields_
                _fields_ = [("count", ctypes.c_uint32)]
            return ctypes.POINTER(ACL)

        pointer_type = build_pointer()
        """,
    )

    assert _variables(result, "_fields_") == {"paths._fields_"}
