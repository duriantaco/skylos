import json

import pytest

from skylos.analyzer import analyze


def _unused(tmp_path, source):
    (tmp_path / "Types.cs").write_text(source)
    result = json.loads(
        analyze(str(tmp_path), conf=0, grep_verify=False, grep_cache=False)
    )
    return {item["full_name"] for item in result.get("unused_classes", [])}


def test_explicit_static_receiver_preserves_type_without_method_body(tmp_path):
    unused = _unused(
        tmp_path,
        "namespace Demo; internal static class Native { public static extern void Ping(); } "
        "internal static class Dormant { public static extern void Ping(); } "
        "public class Entry { public void Run() { Native.Ping(); } }",
    )
    assert "Demo.Native" not in unused
    assert "Demo.Dormant" in unused


def test_explicit_generated_member_read_preserves_exact_partial_type(tmp_path):
    unused = _unused(
        tmp_path,
        "namespace Demo; internal static partial class Banner {} "
        "internal static partial class Dormant {} "
        "public class Entry { public object Run() { return Banner.Generated; } }",
    )
    assert "Demo.Banner" not in unused
    assert "Demo.Dormant" in unused


def test_nested_static_receiver_preserves_container_without_unused_sibling(tmp_path):
    unused = _unused(
        tmp_path,
        "namespace Demo; internal static class Outer { "
        "internal static class Inner { public static extern void Ping(); } "
        "internal static class Dormant {} } "
        "public class Entry { public void Run() { Outer.Inner.Ping(); } }",
    )
    assert "Demo.Outer" not in unused
    assert "Demo.Outer.Inner" not in unused
    assert "Demo.Outer.Dormant" in unused


@pytest.mark.parametrize(
    "member",
    ["private Remote Helper = new();", "private Remote Helper { get; } = new();"],
)
def test_value_member_shadow_does_not_activate_same_named_static_type(tmp_path, member):
    unused = _unused(
        tmp_path,
        "namespace Demo; internal static class Helper { public static void Ping() {} } "
        "public class Remote { public void Ping() {} } "
        f"public class Entry {{ {member} public void Run() {{ Helper.Ping(); }} }}",
    )
    assert "Demo.Helper" in unused
