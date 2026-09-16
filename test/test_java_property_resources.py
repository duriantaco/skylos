"""Static Java property-resource parsing; no fixture code is executed."""

from pathlib import Path

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.visitors.languages.java import properties


def _write(path: Path, text: str, *, encoding="utf-8") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text, encoding=encoding)
    return path


@pytest.fixture
def project(tmp_path):
    caller = _write(
        tmp_path / "src/main/java/example/app/Example.java",
        "package example.app; class Example {}",
    )
    resources = tmp_path / "src/main/resources"
    resources.mkdir()
    return caller, resources


def _resolver(project):
    return properties.JavaPropertyResources(str(project[0]), "example.app")


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", {}),
        (" \t\f\n# comment\n ! comment\r\n", {}),
        ("algorithm=MD5", {"algorithm": "MD5"}),
        ("algorithm : SHA-256", {"algorithm": "SHA-256"}),
        ("algorithm\tSHA-256", {"algorithm": "SHA-256"}),
        (" bare ", {"bare": ""}),
        ("=value", {"": "value"}),
        ("algorithm= SHA-256  ", {"algorithm": "SHA-256  "}),
        ("a==:\nb: =:", {"a": "=:", "b": "=:"}),
        ("a=first\na=last", {"a": "last"}),
        ("a=one\rb=two\r\nc=three\n", {"a": "one", "b": "two", "c": "three"}),
        ("a=one\f two\x85three", {"a": "one\f two\x85three"}),
        ("a=one#not-comment!", {"a": "one#not-comment!"}),
        (r"\#key=value", {"#key": "value"}),
        (r"\!key=value", {"!key": "value"}),
        (r"a\ b\:\==\ value", {"a b:=": " value"}),
        (r"key=\t\r\n\f\b\z\'\"\\", {"key": "\t\r\n\fbz'\"\\"}),
        (r"\u0061lgorithm=\u004dD5", {"algorithm": "MD5"}),
        (r"a=\u00e9\u0041", {"a": "éA"}),
        (r"a=\123", {"a": "123"}),
        ("algorithm=M\\\n   D5", {"algorithm": "MD5"}),
        ("algorithm=M\\\r\n\tD\\\r\f5", {"algorithm": "MD5"}),
        ("algorithm=M\\\n#D5", {"algorithm": "M#D5"}),
        ("algorithm=M\\\n!D5", {"algorithm": "M!D5"}),
        ("a=one\\\\\nb=two", {"a": "one\\", "b": "two"}),
        ("a=one\\\\\\\n two", {"a": "one\\two"}),
        ("a=one\\\n\nb=two", {"a": "one", "b": "two"}),
        ("# ignored\\\na=value", {"a": "value"}),
        ("a=value\\", {"a": "value"}),
        ("a=value\\\n", {"a": "value"}),
        ("\\", {"": ""}),
        ("\\\n", {"": ""}),
    ],
)
def test_properties_load_input_stream_semantics(text, expected):
    assert properties._parse_properties(text) == expected


@pytest.mark.parametrize("escape", [r"\u", r"\u123", r"\u12xz", r"\uu0041"])
def test_malformed_escape_rejects_entire_map(escape):
    assert properties._parse_properties("algorithm=MD5\ninvalid=" + escape) is None


def test_exact_root_relative_resource(project):
    _write(project[1] / "settings/crypto.properties", "algorithm=MD5")
    assert _resolver(project).load("settings/crypto.properties") == {"algorithm": "MD5"}


def test_input_stream_uses_latin1_not_utf8(project):
    _write(project[1] / "crypto.properties", "name=café", encoding="latin-1")
    assert _resolver(project).load("crypto.properties") == {"name": "café"}


def test_missing_resource_distinct_from_valid_empty_file(project):
    _write(project[1] / "empty.properties", "# nothing here\n")
    resolver = _resolver(project)
    assert resolver.load("empty.properties") == {}
    assert resolver.load("missing.properties") is None


def test_test_source_set_does_not_read_main_resources(tmp_path):
    caller = _write(
        tmp_path / "src/test/java/example/Example.java",
        "package example; class Example {}",
    )
    _write(tmp_path / "src/main/resources/crypto.properties", "algorithm=MD5")
    resolver = properties.JavaPropertyResources(str(caller), "example")
    assert resolver.load("crypto.properties") is None
    _write(tmp_path / "src/test/resources/crypto.properties", "algorithm=SHA-256")
    assert properties.JavaPropertyResources(str(caller), "example").load(
        "crypto.properties"
    ) == {"algorithm": "SHA-256"}


def test_default_package_requires_direct_java_root(tmp_path):
    caller = _write(tmp_path / "src/main/java/Example.java", "class Example {}")
    _write(tmp_path / "src/main/resources/crypto.properties", "algorithm=MD5")
    assert properties.JavaPropertyResources(str(caller), "").load(
        "crypto.properties"
    ) == {"algorithm": "MD5"}


@pytest.mark.parametrize(
    "name",
    [
        "",
        "/crypto.properties",
        "../crypto.properties",
        "a/../crypto.properties",
        "./crypto.properties",
        "a//crypto.properties",
        "a/./crypto.properties",
        "a\\crypto.properties",
        "C:/crypto.properties",
        "file:crypto.properties",
        "crypto.properties\0",
        "crypto.properties/",
    ],
)
def test_invalid_resource_names_never_read(project, monkeypatch, name):
    def forbidden_read(*args, **kwargs):
        pytest.fail("invalid resource name reached filesystem reader")

    monkeypatch.setattr(properties, "read_project_text_no_symlink", forbidden_read)
    assert _resolver(project).load(name) is None


@pytest.mark.parametrize(
    "package", ["wrong.app", "example", "", ".example.app", "example..app", "../app"]
)
def test_package_must_match_caller_directory(project, package):
    _write(project[1] / "crypto.properties", "algorithm=MD5")
    assert (
        properties.JavaPropertyResources(str(project[0]), package).load(
            "crypto.properties"
        )
        is None
    )


@pytest.mark.parametrize(
    "layout",
    [
        "java/example",
        "src/java/example",
        "src/custom/java/example",
        "source/main/java/example",
    ],
)
def test_nonconventional_layout_remains_unknown(tmp_path, layout):
    caller = _write(
        tmp_path / layout / "Example.java", "package example; class Example {}"
    )
    _write(tmp_path / "resources/crypto.properties", "algorithm=MD5")
    assert (
        properties.JavaPropertyResources(str(caller), "example").load(
            "crypto.properties"
        )
        is None
    )


@pytest.mark.parametrize("marker", properties._PROJECT_MARKERS)
def test_resource_cannot_cross_nested_project(project, marker):
    _write(project[1] / "nested/crypto.properties", "algorithm=MD5")
    _write(project[1] / "nested" / marker, "")
    assert _resolver(project).load("nested/crypto.properties") is None


@pytest.mark.parametrize(
    "location",
    [
        "src",
        "src/main",
        "src/main/java",
        "src/main/java/example",
        "src/main/java/example/app",
    ],
)
def test_caller_cannot_cross_nested_project(project, tmp_path, location):
    _write(project[1] / "crypto.properties", "algorithm=MD5")
    _write(tmp_path / location / "pom.xml", "<project />")
    assert _resolver(project).load("crypto.properties") is None


def test_module_root_project_marker_is_allowed(project, tmp_path):
    _write(project[1] / "crypto.properties", "algorithm=MD5")
    _write(tmp_path / "pom.xml", "<project />")
    assert _resolver(project).load("crypto.properties") == {"algorithm": "MD5"}


def test_symlink_resource_file_is_rejected(project, tmp_path):
    outside = _write(tmp_path / "outside.properties", "algorithm=MD5")
    (project[1] / "crypto.properties").symlink_to(outside)
    assert _resolver(project).load("crypto.properties") is None


def test_symlink_resource_parent_is_rejected(project, tmp_path):
    outside = _write(tmp_path / "outside/crypto.properties", "algorithm=MD5")
    (project[1] / "nested").symlink_to(outside.parent, target_is_directory=True)
    assert _resolver(project).load("nested/crypto.properties") is None


def test_symlink_resource_root_is_rejected(tmp_path):
    caller = _write(tmp_path / "src/main/java/Example.java", "class Example {}")
    outside = _write(tmp_path / "outside/crypto.properties", "algorithm=MD5")
    (tmp_path / "src/main/resources").symlink_to(
        outside.parent, target_is_directory=True
    )
    assert (
        properties.JavaPropertyResources(str(caller), "").load("crypto.properties")
        is None
    )


def test_symlink_caller_file_is_rejected(project):
    alias = project[0].with_name("Alias.java")
    alias.symlink_to(project[0])
    _write(project[1] / "crypto.properties", "algorithm=MD5")
    assert (
        properties.JavaPropertyResources(str(alias), "example.app").load(
            "crypto.properties"
        )
        is None
    )


def test_symlink_caller_package_directory_is_rejected(project):
    alias = project[0].parent.parent / "alias"
    alias.symlink_to(project[0].parent, target_is_directory=True)
    _write(project[1] / "crypto.properties", "algorithm=MD5")
    assert (
        properties.JavaPropertyResources(
            str(alias / "Example.java"), "example.alias"
        ).load("crypto.properties")
        is None
    )


def test_resource_directory_is_not_a_file(project):
    (project[1] / "crypto.properties").mkdir()
    assert _resolver(project).load("crypto.properties") is None


def test_resource_cannot_cross_nested_git_directory(project):
    _write(project[1] / "nested/crypto.properties", "algorithm=MD5")
    (project[1] / "nested/.git").mkdir()
    assert _resolver(project).load("nested/crypto.properties") is None


def test_malformed_resource_has_no_partial_constants(project):
    _write(project[1] / "crypto.properties", "algorithm=MD5\ninvalid=\\u123")
    assert _resolver(project).load("crypto.properties") is None


def test_unreadable_resource_remains_unknown(project, monkeypatch):
    _write(project[1] / "crypto.properties", "algorithm=MD5")

    def unavailable_reader(*args, **kwargs):
        raise OSError("unavailable")

    monkeypatch.setattr(properties, "read_project_text_no_symlink", unavailable_reader)
    assert _resolver(project).load("crypto.properties") is None


def test_missing_caller_cannot_select_resources(project):
    _write(project[1] / "crypto.properties", "algorithm=MD5")
    caller = project[0].with_name("Missing.java")
    assert (
        properties.JavaPropertyResources(str(caller), "example.app").load(
            "crypto.properties"
        )
        is None
    )


def test_negative_lookups_are_cached_and_consume_file_budget(project, monkeypatch):
    monkeypatch.setattr(properties, "MAX_PROPERTY_FILES", 1)
    resolver = _resolver(project)
    assert resolver.load("missing.properties") is None
    _write(project[1] / "missing.properties", "algorithm=MD5")
    assert resolver.load("missing.properties") is None
    assert not resolver.limit_reached
    assert resolver.load("other.properties") is None
    assert resolver.limit_reached


def test_success_cache_is_scan_local_and_returns_independent_maps(project):
    path = _write(project[1] / "crypto.properties", "algorithm=MD5")
    resolver = _resolver(project)
    first = resolver.load("crypto.properties")
    first["algorithm"] = "changed"
    _write(path, "algorithm=SHA-256")
    assert resolver.load("crypto.properties") == {"algorithm": "MD5"}
    assert _resolver(project).load("crypto.properties") == {"algorithm": "SHA-256"}


@pytest.mark.parametrize("delta", [-1, 0])
def test_file_byte_limit_boundary(project, monkeypatch, delta):
    text = "algorithm=MD5"
    _write(project[1] / "crypto.properties", text)
    monkeypatch.setattr(properties, "MAX_PROPERTY_FILE_BYTES", len(text) + delta)
    expected = None if delta < 0 else {"algorithm": "MD5"}
    assert _resolver(project).load("crypto.properties") == expected


def test_total_byte_limit_prevents_another_read(project, monkeypatch):
    text = "algorithm=MD5"
    _write(project[1] / "first.properties", text)
    _write(project[1] / "second.properties", text)
    monkeypatch.setattr(properties, "MAX_PROPERTY_TOTAL_BYTES", len(text))
    reads = []
    original_reader = properties.read_project_text_no_symlink

    def recording_reader(*args, **kwargs):
        reads.append(args)
        return original_reader(*args, **kwargs)

    monkeypatch.setattr(properties, "read_project_text_no_symlink", recording_reader)
    resolver = _resolver(project)
    assert resolver.load("first.properties") == {"algorithm": "MD5"}
    assert resolver.load("second.properties") is None
    assert len(reads) == 1
    assert resolver.limit_reached


@pytest.mark.parametrize(
    ("limit", "value", "text"),
    [
        ("MAX_PROPERTY_ENTRIES", 1, "a=one\na=two"),
        ("MAX_PROPERTY_COMPONENT_CHARS", 2, "a=one"),
        ("MAX_PROPERTY_COMPONENT_CHARS", 2, "long=x"),
        ("MAX_PROPERTY_LOGICAL_LINE_CHARS", 5, "a=lo\\\nng"),
        ("MAX_PROPERTY_NATURAL_LINES", 2, "# one\n# two\na=x"),
    ],
)
def test_parser_budgets_reject_partial_maps(monkeypatch, limit, value, text):
    monkeypatch.setattr(properties, limit, value)
    assert properties._parse_properties(text) is None


@pytest.mark.parametrize(
    "limit",
    ["MAX_RESOURCE_NAME_CHARS", "MAX_RESOURCE_SEGMENTS", "MAX_CALLER_ANCESTORS"],
)
def test_resource_lookup_budgets_remain_unknown(project, monkeypatch, limit):
    _write(project[1] / "nested/crypto.properties", "algorithm=MD5")
    monkeypatch.setattr(properties, limit, 1)
    assert _resolver(project).load("nested/crypto.properties") is None
