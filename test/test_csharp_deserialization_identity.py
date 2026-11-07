"""D233 requires the real formatter/settings provider, not just its spelling."""

import json
from dataclasses import replace

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.visitors.languages.csharp.danger import (
    _file_context,
    _json_settings_type,
    scan_danger,
)


FORMATTER_CASES = [
    ("native", "", "new BinaryFormatter()", "CRITICAL"),
    (
        "native_alias",
        "using F = System.Runtime.Serialization.Formatters.Binary.BinaryFormatter;",
        "new F()",
        "CRITICAL",
    ),
    (
        "native_namespace_alias",
        "using F = System.Runtime.Serialization.Formatters.Binary;",
        "new F.BinaryFormatter()",
        "CRITICAL",
    ),
    (
        "local_class",
        "class BinaryFormatter { public object Deserialize(object input) => new object(); }",
        "new BinaryFormatter()",
        None,
    ),
    (
        "local_alias",
        "using BinaryFormatter = PlainReader; class PlainReader { public object Deserialize(object input) => new object(); }",
        "new BinaryFormatter()",
        None,
    ),
    (
        "local_inherited",
        "class PlainReader { public object Deserialize(object input) => new object(); } class BinaryFormatter : PlainReader {}",
        "new BinaryFormatter()",
        None,
    ),
    (
        "explicit_native_with_local",
        "class BinaryFormatter { public object Deserialize(object input) => new object(); }",
        "new global::System.Runtime.Serialization.Formatters.Binary.BinaryFormatter()",
        "CRITICAL",
    ),
    (
        "counterfeit_namespace",
        "namespace System.Runtime.Serialization.Formatters.Binary { class BinaryFormatter { public object Deserialize(object input) => new object(); } }",
        "new global::System.Runtime.Serialization.Formatters.Binary.BinaryFormatter()",
        None,
    ),
    (
        "qualified_whitespace",
        "",
        "new global::System . Runtime . Serialization . Formatters . Binary . BinaryFormatter()",
        "CRITICAL",
    ),
]


def _formatter_source(prefix, expression):
    return (
        prefix
        + "\n"
        + """public class ImportController : Controller {
 public object Load() {
  var formatter = """
        + expression
        + ";\n  return formatter.Deserialize(Request.Body); // sink\n }\n}\n"
    )


@pytest.mark.parametrize(
    "name,prefix,expression,severity",
    FORMATTER_CASES,
    ids=[row[0] for row in FORMATTER_CASES],
)
def test_formatter_provider_identity(name, prefix, expression, severity):
    source = _formatter_source(prefix, expression)
    assert [
        (row["rule_id"], row["line"], row["severity"])
        for row in scan_danger("App.cs", source)
    ] == ([("SKY-D233", 5, severity)] if severity else [])


SETTINGS_CASES = [
    ("native_all", "", "JsonSerializerSettings", "TypeNameHandling.All", "HIGH"),
    ("native_none", "", "JsonSerializerSettings", "TypeNameHandling.None", None),
    ("native_number", "", "JsonSerializerSettings", "(TypeNameHandling)1", "HIGH"),
    ("native_zero", "", "JsonSerializerSettings", "(TypeNameHandling)00", None),
    (
        "native_alias",
        "using Options = Newtonsoft.Json.JsonSerializerSettings; using Handling = Newtonsoft.Json.TypeNameHandling;",
        "Options",
        "Handling.All",
        "HIGH",
    ),
    (
        "local_settings",
        "class JsonSerializerSettings { public TypeNameHandling TypeNameHandling { get; set; } }",
        "JsonSerializerSettings",
        "TypeNameHandling.All",
        None,
    ),
    (
        "local_property",
        "class DisplayOptions { public TypeNameHandling TypeNameHandling { get; set; } }",
        "DisplayOptions",
        "TypeNameHandling.All",
        None,
    ),
    (
        "local_enum",
        "enum TypeNameHandling { None, All } class DisplayOptions { public TypeNameHandling TypeNameHandling { get; set; } }",
        "DisplayOptions",
        "TypeNameHandling.All",
        None,
    ),
    (
        "explicit_native_with_local",
        "class JsonSerializerSettings { public object TypeNameHandling { get; set; } }",
        "global::Newtonsoft.Json.JsonSerializerSettings",
        "global::Newtonsoft.Json.TypeNameHandling.All",
        "HIGH",
    ),
    (
        "native_derived",
        "class CustomOptions : Newtonsoft.Json.JsonSerializerSettings {}",
        "CustomOptions",
        "TypeNameHandling.All",
        "HIGH",
    ),
    (
        "native_derived_alias",
        "using NativeOptions = Newtonsoft.Json.JsonSerializerSettings; class CustomOptions : NativeOptions {}",
        "CustomOptions",
        "TypeNameHandling.All",
        "HIGH",
    ),
    (
        "derived_shadow_property",
        "class CustomOptions : Newtonsoft.Json.JsonSerializerSettings { public new TypeNameHandling TypeNameHandling { get; set; } }",
        "CustomOptions",
        "TypeNameHandling.All",
        None,
    ),
    (
        "qualified_whitespace",
        "",
        "global::Newtonsoft . Json . JsonSerializerSettings",
        "global::Newtonsoft . Json . TypeNameHandling . All",
        "HIGH",
    ),
]


@pytest.mark.parametrize(
    "name,prefix,owner,value,severity",
    SETTINGS_CASES,
    ids=[row[0] for row in SETTINGS_CASES],
)
def test_type_name_handling_initializer_targets_the_actual_provider(
    name, prefix, owner, value, severity
):
    source = (
        prefix
        + "\npublic class Factory {\n public object Build() {\n  return new "
        + owner
        + " { TypeNameHandling = "
        + value
        + " }; // sink\n }\n}\n"
    )
    assert [
        (row["rule_id"], row["line"], row["severity"])
        for row in scan_danger("App.cs", source)
    ] == ([("SKY-D233", 4, severity)] if severity else [])


@pytest.mark.parametrize(
    "owner,severity", [("JsonSerializerSettings", "HIGH"), ("DisplayOptions", None)]
)
def test_type_name_handling_assignment_checks_receiver_type(owner, severity):
    source = (
        """class DisplayOptions { public object TypeNameHandling { get; set; } }
public class Factory {
 public object Build() {
  var options = new """
        + owner
        + "();\n  options.TypeNameHandling = TypeNameHandling.All; // sink\n  return options;\n }\n}\n"
    )
    assert [
        (row["rule_id"], row["line"], row["severity"])
        for row in scan_danger("App.cs", source)
    ] == ([("SKY-D233", 5, severity)] if severity else [])


def test_target_typed_settings_initializer_retains_warning():
    source = "JsonSerializerSettings settings = new() { TypeNameHandling = TypeNameHandling.All };\n"
    assert [
        (row["rule_id"], row["line"], row["severity"])
        for row in scan_danger("App.cs", source)
    ] == [("SKY-D233", 1, "HIGH")]


@pytest.mark.parametrize("hidden", [False, True])
def test_deep_settings_inheritance_uses_the_whole_type_index(hidden):
    # Exercise source-parser metadata without making the unrelated controller
    # inheritance scanner parse thousands of synthetic classes.
    context = _file_context(
        "class RootOptions : Newtonsoft.Json.JsonSerializerSettings {}"
    )
    template = context.classes_by_name["RootOptions"]
    if hidden:
        template.member_types["TypeNameHandling"] = {"TypeNameHandling"}
    parent = template.name
    for index in range(1500):
        name = f"DerivedOptions{index}"
        context.classes_by_name[name] = replace(
            template, name=name, bases=(parent,), raw_bases=(parent,), member_types={}
        )
        parent = name
    assert _json_settings_type(parent, context) is not hidden


@pytest.mark.parametrize("local,severity", [(False, "HIGH"), (True, None)])
def test_simple_type_resolver_provider_identity(local, severity):
    prefix = (
        "class JavaScriptSerializer { public JavaScriptSerializer(object resolver) {} } class SimpleTypeResolver {}\n"
        if local
        else "\n"
    )
    source = (
        prefix
        + "var serializer = new JavaScriptSerializer(new SimpleTypeResolver()); // sink\n"
    )
    assert [
        (row["rule_id"], row["line"], row["severity"])
        for row in scan_danger("App.cs", source)
    ] == ([("SKY-D233", 2, severity)] if severity else [])


@pytest.mark.parametrize("unsafe", [False, True])
def test_formatter_identity_survives_native_listing_and_gate(tmp_path, unsafe):
    prefix = (
        ""
        if unsafe
        else "class BinaryFormatter { public object Deserialize(object input) => new object(); }"
    )
    (tmp_path / "App.cs").write_text(_formatter_source(prefix, "new BinaryFormatter()"))
    result = json.loads(analyze(str(tmp_path), enable_danger=True, grep_verify=False))
    assert result["analysis_summary"]["languages"] == {"C#": 1}
    assert result["analysis_summary"]["total_files"] == 1
    assert not result.get("analysis_errors")
    findings = result.get("danger", [])
    assert [(row["rule_id"], row["line"], row["severity"]) for row in findings] == (
        [("SKY-D233", 5, "CRITICAL")] if unsafe else []
    )
    assert all(row["listing"]["listed"] for row in findings)
    passed, _ = check_gate(result, {"gate": {"max_security": 0, "max_high": 0}})
    assert passed is not unsafe
