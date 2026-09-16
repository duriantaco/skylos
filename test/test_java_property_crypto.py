"""Java property-backed crypto fixtures are parsed, never compiled or executed."""

from pathlib import Path

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.visitors.languages.java import scan_java_file


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text)


def _scan(
    tmp_path,
    body,
    *,
    resource="algorithm=MD5\nstrong=SHA-256\n",
    imports="",
    suffix="",
    fields="",
):
    caller = tmp_path / "src" / "main" / "java" / "demo" / "App.java"
    _write(
        caller,
        f"""package demo;
{imports}
class App {{
  {fields}
  void digest(boolean flag, String resourceName) throws Exception {{
    {body}
  }}
}}
{suffix}
""",
    )
    if resource is not None:
        _write(
            tmp_path / "src" / "main" / "resources" / "crypto.properties",
            resource,
        )
    return [
        finding
        for finding in scan_java_file(str(caller), {})[7]
        if finding["rule_id"] in {"SKY-D207", "SKY-D208"}
    ]


def _load(*, type_name="java.util.Properties", resource='"crypto.properties"'):
    return f"""{type_name} config = new {type_name}();
config.load(this.getClass().getClassLoader().getResourceAsStream({resource}));
"""


def _digest(
    expression='config.getProperty("algorithm")', receiver="java.security.MessageDigest"
):
    return f"String algorithm = {expression}; {receiver}.getInstance(algorithm);"


@pytest.mark.parametrize(
    "algorithm,rule_id",
    [("MD5", "SKY-D207"), ("SHA-1", "SKY-D208"), ("SHA1", "SKY-D208")],
)
@pytest.mark.parametrize("qualified", [False, True])
def test_java_properties_resource_algorithm_reaches_digest(
    tmp_path, algorithm, rule_id, qualified
):
    imports = (
        ""
        if qualified
        else "import java.util.Properties; import java.security.MessageDigest;"
    )
    type_name = "java.util.Properties" if qualified else "Properties"
    receiver = "java.security.MessageDigest" if qualified else "MessageDigest"
    findings = _scan(
        tmp_path,
        _load(type_name=type_name) + _digest(receiver=receiver),
        imports=imports,
        resource=f"algorithm={algorithm}\n",
    )
    assert [finding["rule_id"] for finding in findings] == [rule_id]
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["file"].endswith("/demo/App.java")


def test_java_properties_strong_algorithm_does_not_warn(tmp_path):
    assert _scan(tmp_path, _load() + _digest(), resource="algorithm=SHA-256\n") == []


def test_java_properties_keys_are_not_interchangeable(tmp_path):
    assert _scan(tmp_path, _load() + _digest('config.getProperty("strong")')) == []


@pytest.mark.parametrize("resource", [None, "different=SHA-256\n"])
def test_java_properties_missing_value_does_not_invent_algorithm(tmp_path, resource):
    assert _scan(tmp_path, _load() + _digest(), resource=resource) == []


def test_java_properties_existing_value_overrides_fallback(tmp_path):
    assert (
        _scan(
            tmp_path,
            _load() + _digest('config.getProperty("strong", "MD5")'),
        )
        == []
    )


def test_java_properties_known_missing_key_uses_fallback(tmp_path):
    findings = _scan(
        tmp_path,
        _load() + _digest('config.getProperty("absent", "MD5")'),
    )
    assert [finding["rule_id"] for finding in findings] == ["SKY-D207"]


@pytest.mark.parametrize(
    "resource_expression", ['"missing.properties"', "resourceName"]
)
def test_java_properties_unknown_load_does_not_assume_fallback(
    tmp_path, resource_expression
):
    assert (
        _scan(
            tmp_path,
            _load(resource=resource_expression)
            + _digest('config.getProperty("algorithm", "MD5")'),
        )
        == []
    )


def test_java_properties_failed_later_load_discards_stale_value(tmp_path):
    assert (
        _scan(
            tmp_path,
            _load()
            + "config.load(this.getClass().getClassLoader().getResourceAsStream(resourceName));"
            + _digest(),
        )
        == []
    )


def test_java_properties_literal_digest_is_not_reported_twice(tmp_path):
    findings = _scan(tmp_path, 'java.security.MessageDigest.getInstance("MD5");')
    assert [finding["rule_id"] for finding in findings] == ["SKY-D207"]


def test_java_properties_constant_algorithm_variable_is_supported(tmp_path):
    findings = _scan(tmp_path, _digest('"MD5"'))
    assert [finding["rule_id"] for finding in findings] == ["SKY-D207"]


def test_java_properties_alias_reads_same_resource(tmp_path):
    findings = _scan(
        tmp_path,
        _load()
        + "java.util.Properties alias = config;"
        + _digest('alias.getProperty("algorithm")'),
    )
    assert [finding["rule_id"] for finding in findings] == ["SKY-D207"]


@pytest.mark.parametrize(
    "mutation",
    [
        'alias.setProperty("algorithm", "SHA-256");',
        'alias.put("algorithm", "SHA-256");',
        'alias.remove("algorithm");',
        "alias.clear();",
        "mutate(alias);",
        "alias.load(this.getClass().getClassLoader().getResourceAsStream(resourceName));",
    ],
)
def test_java_properties_alias_mutation_does_not_keep_stale_algorithm(
    tmp_path, mutation
):
    assert (
        _scan(
            tmp_path,
            _load() + "java.util.Properties alias = config;" + mutation + _digest(),
        )
        == []
    )


def test_java_properties_reassignment_does_not_keep_previous_resource(tmp_path):
    assert _scan(tmp_path, _load() + "config = unknown();" + _digest()) == []


def test_java_properties_reassigned_alias_does_not_change_original(tmp_path):
    findings = _scan(
        tmp_path,
        _load()
        + "java.util.Properties alias = config; alias = new java.util.Properties();"
        + 'alias.setProperty("algorithm", "SHA-256");'
        + _digest(),
    )
    assert [finding["rule_id"] for finding in findings] == ["SKY-D207"]


def test_java_properties_branch_mutation_does_not_keep_stale_value(tmp_path):
    assert (
        _scan(
            tmp_path,
            _load()
            + 'if (flag) { config.setProperty("algorithm", "SHA-256"); }'
            + _digest(),
        )
        == []
    )


def test_java_properties_identical_branch_values_remain_known(tmp_path):
    findings = _scan(
        tmp_path,
        _load()
        + 'if (flag) { config.setProperty("algorithm", "MD5"); }'
        + 'else { config.setProperty("algorithm", "MD5"); }'
        + _digest(),
    )
    assert [finding["rule_id"] for finding in findings] == ["SKY-D207"]


def test_java_properties_unknown_branch_load_does_not_keep_stale_value(tmp_path):
    assert (
        _scan(
            tmp_path,
            _load()
            + "if (flag) { config.load(this.getClass().getClassLoader().getResourceAsStream(resourceName)); }"
            + _digest(),
        )
        == []
    )


@pytest.mark.parametrize(
    "imports,suffix",
    [
        ("import other.Properties;", ""),
        ("", "class Properties {}"),
        ("import java.util.Properties;", "class Properties {}"),
    ],
)
def test_java_properties_impostor_type_does_not_supply_algorithm(
    tmp_path, imports, suffix
):
    assert (
        _scan(
            tmp_path,
            _load(type_name="Properties") + _digest(),
            imports=imports,
            suffix=suffix,
        )
        == []
    )


@pytest.mark.parametrize(
    "imports,suffix",
    [
        ("import other.MessageDigest;", ""),
        ("", "class MessageDigest {}"),
        ("import java.security.MessageDigest;", "class MessageDigest {}"),
    ],
)
def test_java_properties_impostor_digest_does_not_get_new_variable_finding(
    tmp_path, imports, suffix
):
    assert (
        _scan(
            tmp_path,
            _digest('"MD5"', receiver="MessageDigest"),
            imports=imports,
            suffix=suffix,
        )
        == []
    )


def test_java_properties_unrelated_resource_method_is_not_classloader(tmp_path):
    assert (
        _scan(
            tmp_path,
            "java.util.Properties config = new java.util.Properties();"
            + 'config.load(unrelated.getResourceAsStream("crypto.properties"));'
            + _digest(),
        )
        == []
    )


def test_java_properties_resource_cache_is_scan_local(tmp_path):
    body = _load() + _digest()
    assert len(_scan(tmp_path, body, resource="algorithm=MD5\n")) == 1
    assert _scan(tmp_path, body, resource="algorithm=SHA-256\n") == []


def test_java_properties_cast_alias_mutation_does_not_keep_stale_value(tmp_path):
    assert (
        _scan(
            tmp_path,
            _load()
            + "java.util.Properties alias = (java.util.Properties) config;"
            + 'alias.setProperty("algorithm", "SHA-256");'
            + _digest(),
        )
        == []
    )


def test_java_properties_array_initializer_escape_discards_stale_value(tmp_path):
    assert (
        _scan(
            tmp_path,
            _load() + "Object[] box = {config}; mutate(box);" + _digest(),
        )
        == []
    )


def test_java_properties_if_condition_mutation_discards_stale_value(tmp_path):
    assert (
        _scan(
            tmp_path,
            _load()
            + 'if (config.setProperty("algorithm", "SHA-256") != null) {}'
            + _digest(),
        )
        == []
    )


def test_java_properties_nested_fallback_mutation_precedes_getter(tmp_path):
    assert (
        _scan(
            tmp_path,
            _load()
            + 'java.security.MessageDigest.getInstance(config.getProperty("algorithm", mutate(config)));',
        )
        == []
    )


def test_java_properties_impostor_digest_reassignment_still_shadows_type(tmp_path):
    assert (
        _scan(
            tmp_path,
            "OtherDigest MessageDigest = new OtherDigest(); MessageDigest = unknown();"
            + _digest('"MD5"', receiver="MessageDigest"),
            imports="import java.security.MessageDigest;",
            suffix="class OtherDigest { Object getInstance(String name) { return null; } }",
        )
        == []
    )


def test_java_properties_impostor_digest_field_shadows_type(tmp_path):
    assert (
        _scan(
            tmp_path,
            _digest('"MD5"', receiver="MessageDigest"),
            imports="import java.security.MessageDigest;",
            fields="OtherDigest MessageDigest;",
            suffix="class OtherDigest { Object getInstance(String name) { return null; } }",
        )
        == []
    )


def test_java_properties_values_never_choose_general_control_flow(tmp_path):
    findings = _scan(
        tmp_path,
        _load()
        + 'String configured = config.getProperty("algorithm");'
        + "if (configured.charAt(0) == 'M') {"
        + 'String algorithm = "SHA-1"; java.security.MessageDigest.getInstance(algorithm);'
        + "} else {"
        + 'String algorithm = "MD5"; java.security.MessageDigest.getInstance(algorithm);'
        + "}",
    )
    assert {finding["rule_id"] for finding in findings} == {"SKY-D207", "SKY-D208"}


def test_java_properties_compound_assignment_is_not_plain_replacement(tmp_path):
    assert (
        _scan(
            tmp_path,
            'String algorithm = "SHA-"; algorithm += "MD5";'
            + "java.security.MessageDigest.getInstance(algorithm);",
        )
        == []
    )


def test_java_properties_constructor_defaults_are_not_erased_by_clear(tmp_path):
    assert (
        _scan(
            tmp_path,
            "java.util.Properties defaults = new java.util.Properties();"
            + 'defaults.setProperty("algorithm", "SHA-256");'
            + "java.util.Properties config = new java.util.Properties(defaults);"
            + "config.clear();"
            + _digest('config.getProperty("algorithm", "MD5")'),
        )
        == []
    )
