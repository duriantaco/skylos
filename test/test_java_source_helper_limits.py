"""Bounded helper resolution tests; Java fixture data is never executed."""

from pathlib import Path

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.visitors.languages.java import source_helpers
from skylos.visitors.languages.java.core import JAVA_LANG, _get_parser


@pytest.fixture
def source_root(tmp_path):
    root = tmp_path / "src" / "main" / "java"
    (root / "example" / "app").mkdir(parents=True)
    (root / "example" / "helpers").mkdir()
    return root


def _write(path: Path, source: str) -> Path:
    assert write_text_no_symlink(path, source)
    return path


def _helper_source(
    *, name="Carrier", package="example.helpers", expression="request.getParameter(key)"
):
    declaration = f"package {package};" if package else ""
    return f"""{declaration}
import javax.servlet.http.HttpServletRequest;
public class {name} {{
  private HttpServletRequest request;
  public String value(String key) {{ return {expression}; }}
}}
"""


def _helper(root, *, name="Carrier", expression="request.getParameter(key)"):
    source = _helper_source(name=name, expression=expression)
    _write(root / "example" / "helpers" / f"{name}.java", source)
    return source


def _resolver(
    root,
    *,
    package="example.app",
    imports="import example.helpers.Carrier;",
    path=None,
):
    declaration = f"package {package};" if package else ""
    source = f"{declaration}\n{imports}\nclass App {{}}\n".encode("utf-8")
    caller = path or root / "example" / "app" / "App.java"
    _write(caller, source.decode("utf-8"))
    root_node = _get_parser(JAVA_LANG).parse(source).root_node
    return source_helpers.JavaSourceHelpers(root_node, str(caller), source)


def test_helper_source_file_byte_limit(source_root, monkeypatch):
    source = _helper(source_root)
    resolver = _resolver(source_root)
    monkeypatch.setattr(
        source_helpers, "MAX_HELPER_SOURCE_BYTES", len(source.encode("utf-8")) - 1
    )
    assert resolver.summary("Carrier", "value", 1) is None


def test_helper_source_file_byte_limit_accepts_exact_boundary(source_root, monkeypatch):
    source = _helper(source_root)
    resolver = _resolver(source_root)
    monkeypatch.setattr(
        source_helpers, "MAX_HELPER_SOURCE_BYTES", len(source.encode("utf-8"))
    )
    assert resolver.summary("Carrier", "value", 1).returns_request_source


def test_helper_total_byte_limit_stops_before_another_read(source_root, monkeypatch):
    first_source = _helper(source_root, name="First")
    _helper(source_root, name="Second")
    resolver = _resolver(source_root)
    monkeypatch.setattr(
        source_helpers, "MAX_HELPER_TOTAL_BYTES", len(first_source.encode("utf-8"))
    )
    reads = []
    original_reader = source_helpers.read_project_text_no_symlink

    def recording_reader(root, candidate, **kwargs):
        reads.append(candidate)
        return original_reader(root, candidate, **kwargs)

    monkeypatch.setattr(
        source_helpers, "read_project_text_no_symlink", recording_reader
    )
    assert resolver.summary("example.helpers.First", "value", 1).returns_request_source
    assert resolver.summary("example.helpers.Second", "value", 1) is None
    assert len(reads) == 1
    assert resolver.limit_reached


def test_negative_lookups_consume_file_budget_but_cache_hits_do_not(
    source_root, monkeypatch
):
    _helper(source_root)
    resolver = _resolver(source_root)
    monkeypatch.setattr(source_helpers, "MAX_HELPER_FILES", 1)
    assert resolver.summary("example.helpers.Missing", "value", 1) is None
    assert resolver.summary("example.helpers.Missing", "value", 1) is None
    assert not resolver.limit_reached
    assert resolver.summary("Carrier", "value", 1) is None
    assert resolver.limit_reached


@pytest.mark.parametrize("limit", ["MAX_HELPER_METHODS", "MAX_HELPER_FIELDS"])
def test_helper_member_limits_reject_partial_summary(source_root, monkeypatch, limit):
    _helper(source_root)
    resolver = _resolver(source_root)
    monkeypatch.setattr(source_helpers, limit, 0)
    assert resolver.summary("Carrier", "value", 1) is None


def test_helper_node_limit_rejects_partial_summary(source_root, monkeypatch):
    _helper(source_root)
    resolver = _resolver(source_root)
    monkeypatch.setattr(source_helpers, "MAX_HELPER_NODES", 1)
    assert resolver.summary("Carrier", "value", 1) is None


def test_caller_import_limit_disables_external_resolution(source_root, monkeypatch):
    _helper(source_root)
    monkeypatch.setattr(source_helpers, "MAX_HELPER_IMPORTS", 0)
    resolver = _resolver(source_root)
    assert resolver.summary("Carrier", "value", 1) is None


def test_helper_parent_directory_symlink_is_not_followed(source_root, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    _write(outside / "Carrier.java", _helper_source(package="example.linked"))
    (source_root / "example" / "linked").symlink_to(outside, target_is_directory=True)
    resolver = _resolver(source_root, imports="import example.linked.Carrier;")
    assert resolver.summary("Carrier", "value", 1) is None


def test_default_package_resolves_exact_same_directory(source_root):
    _write(source_root / "Carrier.java", _helper_source(package=""))
    resolver = _resolver(
        source_root, package="", imports="", path=source_root / "App.java"
    )
    assert resolver.summary("Carrier", "value", 1).returns_request_source


def test_default_package_does_not_search_parent_directories(source_root):
    _write(source_root.parent / "Carrier.java", _helper_source(package=""))
    resolver = _resolver(
        source_root, package="", imports="", path=source_root / "App.java"
    )
    assert resolver.summary("Carrier", "value", 1) is None


def test_caller_package_must_match_source_layout(source_root):
    _helper(source_root)
    resolver = _resolver(source_root, package="unrelated.app")
    assert resolver.summary("Carrier", "value", 1) is None


def test_conflicting_explicit_imports_are_unresolved(source_root):
    _helper(source_root)
    resolver = _resolver(
        source_root,
        imports="import example.helpers.Carrier; import unrelated.Carrier;",
    )
    assert resolver.summary("Carrier", "value", 1) is None


def test_duplicate_identical_import_does_not_create_ambiguity(source_root):
    _helper(source_root)
    resolver = _resolver(
        source_root,
        imports="import example.helpers.Carrier; import example.helpers.Carrier;",
    )
    assert resolver.summary("Carrier", "value", 1).returns_request_source


def test_helper_class_name_must_match_requested_type(source_root):
    _write(
        source_root / "example" / "helpers" / "Carrier.java",
        _helper_source(name="Unrelated"),
    )
    assert _resolver(source_root).summary("Carrier", "value", 1) is None


def test_duplicate_helper_class_names_are_not_used(source_root):
    _write(
        source_root / "example" / "helpers" / "Carrier.java",
        _helper_source() + "\nclass Carrier {}\n",
    )
    assert _resolver(source_root).summary("Carrier", "value", 1) is None


def test_wildcard_import_does_not_guess_helper_package(source_root):
    _helper(source_root)
    resolver = _resolver(source_root, imports="import example.helpers.*;")
    assert resolver.summary("Carrier", "value", 1) is None
    assert resolver.summary(
        "example.helpers.Carrier", "value", 1
    ).returns_request_source


def test_static_import_is_not_reinterpreted_as_top_level_type(source_root):
    _write(
        source_root / "example" / "app" / "Carrier.java",
        _helper_source(package="example.app"),
    )
    resolver = _resolver(
        source_root, imports="import static example.helpers.Outer.Carrier;"
    )
    assert resolver.summary("Carrier", "value", 1) is None


def test_external_safe_summary_is_not_returned_as_safety_proof(source_root):
    _helper(source_root, expression='"fixed"')
    assert _resolver(source_root).summary("Carrier", "value", 1) is None


def test_argument_only_flow_is_left_to_normal_call_fallback(source_root):
    _helper(source_root, expression="key")
    assert _resolver(source_root).summary("Carrier", "value", 1) is None


def test_summary_cache_is_local_to_one_resolver(source_root):
    _helper(source_root)
    resolver = _resolver(source_root)
    original = resolver.summary("Carrier", "value", 1)
    assert original.returns_request_source
    _helper(source_root, expression='"fixed"')
    assert resolver.summary("Carrier", "value", 1) is original
    assert _resolver(source_root).summary("Carrier", "value", 1) is None


@pytest.mark.parametrize("source_first", [True, False])
def test_same_arity_external_overloads_are_unresolved(source_root, source_first):
    source_method = "String value(String key) { return request.getParameter(key); }"
    safe_method = 'String value(Integer key) { return "fixed"; }'
    methods = (
        [source_method, safe_method] if source_first else [safe_method, source_method]
    )
    _write(
        source_root / "example" / "helpers" / "Carrier.java",
        """package example.helpers;
import javax.servlet.http.HttpServletRequest;
class Carrier {
  private HttpServletRequest request;
"""
        + "\n".join(methods)
        + "\n}\n",
    )
    assert _resolver(source_root).summary("Carrier", "value", 1) is None


def test_different_arity_external_overloads_remain_separate(source_root):
    _write(
        source_root / "example" / "helpers" / "Carrier.java",
        """package example.helpers;
import javax.servlet.http.HttpServletRequest;
class Carrier {
  private HttpServletRequest request;
  String value(String key) { return request.getParameter(key); }
  String value() { return "fixed"; }
}
""",
    )
    resolver = _resolver(source_root)
    assert resolver.summary("Carrier", "value", 1).returns_request_source
    assert resolver.summary("Carrier", "value", 0) is None


@pytest.mark.parametrize(
    "marker",
    [".git", "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle.kts"],
)
def test_package_ancestry_cannot_escape_project_boundary(tmp_path, marker):
    project = tmp_path / "project"
    caller_dir = project / "example" / "app"
    caller_dir.mkdir(parents=True)
    _write(project / marker, "local project marker\n")
    outside_helpers = tmp_path / "example" / "helpers"
    outside_helpers.mkdir(parents=True)
    _write(outside_helpers / "Carrier.java", _helper_source())
    resolver = _resolver(
        project,
        package="project.example.app",
        path=caller_dir / "App.java",
    )
    assert resolver.summary("Carrier", "value", 1) is None


def test_git_directory_anchors_valid_nonconventional_source_root(tmp_path):
    project = tmp_path / "project"
    (project / ".git").mkdir(parents=True)
    (project / "example" / "app").mkdir(parents=True)
    (project / "example" / "helpers").mkdir()
    _helper(project)
    assert _resolver(project).summary("Carrier", "value", 1).returns_request_source


def test_nearest_nested_project_boundary_wins(tmp_path):
    project = tmp_path / "outer"
    nested = project / "nested"
    (project / ".git").mkdir(parents=True)
    (nested / "example" / "app").mkdir(parents=True)
    (project / "example" / "helpers").mkdir(parents=True)
    _write(nested / "pom.xml", "<project />\n")
    _helper(project)
    resolver = _resolver(nested, package="nested.example.app")
    assert resolver.summary("Carrier", "value", 1) is None


@pytest.mark.parametrize("source_set", ["main", "test"])
def test_package_ancestry_cannot_escape_conventional_source_root(tmp_path, source_set):
    project = tmp_path / "project"
    if source_set == "main":
        source = project / "src" / "main" / "java"
    else:
        source = project / "src" / "test" / "java"
    (source / "example" / "app").mkdir(parents=True)
    (project / ".git").mkdir()
    (project / "src" / "example" / "helpers").mkdir(parents=True)
    _write(project / "src" / "example" / "helpers" / "Carrier.java", _helper_source())
    resolver = _resolver(source, package=f"{source_set}.java.example.app")
    assert resolver.summary("Carrier", "value", 1) is None


def test_unanchored_package_cannot_search_other_packages(tmp_path):
    source = tmp_path / "unanchored"
    (source / "example" / "app").mkdir(parents=True)
    (source / "example" / "helpers").mkdir()
    _helper(source)
    resolver = _resolver(source)
    assert resolver.summary("Carrier", "value", 1) is None
    assert resolver.summary("example.helpers.Carrier", "value", 1) is None


def test_unanchored_package_can_resolve_exact_sibling(tmp_path):
    source = tmp_path / "unanchored"
    (source / "example" / "app").mkdir(parents=True)
    _write(
        source / "example" / "app" / "Carrier.java",
        _helper_source(package="example.app"),
    )
    resolver = _resolver(source, imports="")
    assert resolver.summary("Carrier", "value", 1).returns_request_source


def test_default_package_does_not_search_nested_packages(source_root):
    _helper(source_root)
    resolver = _resolver(
        source_root,
        package="",
        imports="import example.helpers.Carrier;",
        path=source_root / "App.java",
    )
    assert resolver.summary("Carrier", "value", 1) is None


def test_source_boundary_lookup_is_bounded(source_root, monkeypatch):
    _helper(source_root)
    monkeypatch.setattr(source_helpers, "MAX_SOURCE_ROOT_ANCESTORS", 1)
    resolver = _resolver(source_root)
    assert resolver.summary("Carrier", "value", 1) is None


@pytest.mark.parametrize("marker", [".git", "pom.xml"])
def test_imported_helpers_cannot_cross_into_nested_project(source_root, marker):
    _helper(source_root)
    _write(source_root / "example" / "helpers" / marker, "nested project marker\n")
    assert _resolver(source_root).summary("Carrier", "value", 1) is None
