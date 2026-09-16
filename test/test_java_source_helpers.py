"""Source-backed Java helper analysis; fixture code is parsed, never executed."""

from pathlib import Path

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.visitors.languages.java import scan_java_file
from skylos.visitors.languages.java.core import JAVA_LANG, _get_parser
from skylos.visitors.languages.java.flow import JavaFlowState, JavaSecurityFlowAnalyzer


@pytest.fixture
def source_root(tmp_path):
    root = tmp_path / "src" / "main" / "java"
    (root / "demo" / "app").mkdir(parents=True)
    (root / "demo" / "helpers").mkdir()
    (root / "other").mkdir()
    return root


def _write(path: Path, source: str) -> Path:
    assert write_text_no_symlink(path, source)
    return path


def _helper(root, *, package="demo.helpers", expression="request.getParameter(key)"):
    return _write(
        root / "demo" / "helpers" / "Carrier.java",
        f"""package {package};
import javax.servlet.http.HttpServletRequest;
public class Carrier {{
  private HttpServletRequest request;
  public Carrier(HttpServletRequest request) {{ this.request = request; }}
  public String value(String key) {{ return {expression}; }}
}}
""",
    )


def _caller(
    root,
    *,
    type_name="Carrier",
    imports="import demo.helpers.Carrier;",
    setup=None,
    suffix="",
):
    if setup is None:
        setup = f"{type_name} carrier = new {type_name}(request);"
    return _write(
        root / "demo" / "app" / "App.java",
        f"""package demo.app;
import javax.servlet.http.*;
{imports}
class App {{
  void render(HttpServletRequest request, HttpServletResponse response) throws Exception {{
    {setup}
    response.getWriter().print(carrier.value("display"));
  }}
}}
{suffix}
""",
    )


def _xss(path):
    return [
        finding
        for finding in scan_java_file(str(path), {})[7]
        if finding["rule_id"] == "SKY-D226"
    ]


@pytest.mark.parametrize(
    "type_name,imports",
    [("Carrier", "import demo.helpers.Carrier;"), ("demo.helpers.Carrier", "")],
)
def test_external_source_helper_reaches_findings(source_root, type_name, imports):
    _helper(source_root)
    caller = _caller(source_root, type_name=type_name, imports=imports)
    findings = _xss(caller)
    assert len(findings) == 1
    assert findings[0]["file"] == str(caller)
    assert findings[0]["severity"] == "HIGH"


def test_same_package_source_helper_reaches_findings(source_root):
    _write(
        source_root / "demo" / "app" / "Carrier.java",
        """package demo.app;
import javax.servlet.http.HttpServletRequest;
class Carrier {
  private HttpServletRequest request;
  Carrier(HttpServletRequest request) { this.request = request; }
  String value(String key) { return request.getParameter(key); }
}
""",
    )
    assert len(_xss(_caller(source_root, imports=""))) == 1


def test_external_safe_accessor_is_not_inferred_from_name(source_root):
    _helper(source_root, expression='"fixed"')
    assert _xss(_caller(source_root)) == []


def test_unknown_external_source_is_not_inferred_from_constructor(source_root):
    assert _xss(_caller(source_root)) == []


def test_mismatched_helper_package_is_not_rebound(source_root):
    _helper(source_root, package="other")
    assert _xss(_caller(source_root)) == []


def test_fully_qualified_type_does_not_borrow_another_import(source_root):
    _helper(source_root)
    _write(
        source_root / "other" / "Carrier.java",
        """package other;
class Carrier {
  Carrier(Object source) {}
  String value(String key) { return "fixed"; }
}
""",
    )
    assert _xss(_caller(source_root, type_name="other.Carrier")) == []


def test_local_type_shadows_imported_source_helper(source_root):
    _helper(source_root)
    caller = _caller(
        source_root,
        suffix='class Carrier { Carrier(Object source) {} String value(String key) { return "fixed"; } }',
    )
    assert _xss(caller) == []


def test_qualified_external_type_does_not_borrow_safe_local_summary(source_root):
    _helper(source_root)
    caller = _caller(
        source_root,
        type_name="demo.helpers.Carrier",
        imports="",
        suffix='class Carrier { Carrier(Object source) {} String value(String key) { return "fixed"; } }',
    )
    assert len(_xss(caller)) == 1


def test_alias_preserves_exact_helper_identity(source_root):
    _helper(source_root)
    caller = _caller(
        source_root,
        setup="Carrier original = new Carrier(request); Carrier carrier = original;",
    )
    assert len(_xss(caller)) == 1


def test_reassignment_does_not_keep_stale_helper_identity(source_root):
    _helper(source_root)
    caller = _caller(
        source_root,
        setup="Carrier carrier = new Carrier(request); carrier = unknown();",
    )
    assert _xss(caller) == []


def test_helper_source_cache_does_not_survive_another_scan(source_root):
    _helper(source_root)
    caller = _caller(source_root)
    assert len(_xss(caller)) == 1
    _helper(source_root, expression='"fixed"')
    assert _xss(caller) == []


def test_helper_source_is_not_loaded_from_symlink(source_root, tmp_path):
    outside = _write(
        tmp_path / "External.java",
        """package demo.helpers;
import javax.servlet.http.HttpServletRequest;
public class Carrier {
  private HttpServletRequest request;
  public String value(String key) { return request.getParameter(key); }
}
""",
    )
    (source_root / "demo" / "helpers" / "Carrier.java").symlink_to(outside)
    assert _xss(_caller(source_root)) == []


def test_helper_parse_error_is_not_used_as_source_evidence(source_root):
    _write(
        source_root / "demo" / "helpers" / "Carrier.java",
        "package demo.helpers; class Carrier {",
    )
    assert _xss(_caller(source_root)) == []


@pytest.mark.parametrize(
    "body",
    [
        'String result = "fixed"; if (input.length() > 1) { result = input; } return result;',
        "java.util.List<String> items = new java.util.ArrayList<>(); items.add(input); return items.get(0);",
        'java.util.Map<String, String> items = new java.util.HashMap<>(); items.put("key", input); return items.get("key");',
        'java.util.List<String> items = new java.util.ArrayList<>(); items.add("fixed"); items.add(input); items.remove(0); return items.get(0);',
        'String result = input; if (input.length() > 1) { result = "fixed"; return "fixed"; } return result;',
    ],
)
def test_local_helper_summary_preserves_branch_and_collection_effects(
    source_root, body
):
    caller = _write(
        source_root / "demo" / "app" / "App.java",
        f"""package demo.app;
import javax.servlet.http.*;
class App {{
  String transform(String input) {{ {body} }}
  void render(HttpServletRequest request, HttpServletResponse response) throws Exception {{
    response.getWriter().print(transform(request.getParameter("display")));
  }}
}}
""",
    )
    assert len(_xss(caller)) == 1


@pytest.mark.parametrize(
    "body",
    [
        'String result = "fixed"; if (false) { result = input; } return result;',
        'String result = input; if (true) { result = "fixed"; } return result;',
        'java.util.List<String> items = new java.util.ArrayList<>(); items.add(input); items.remove(0); items.add("fixed"); return items.get(0);',
        'java.util.Map<String, String> items = new java.util.HashMap<>(); items.put("key", input); items.put("key", "fixed"); return items.get("key");',
        'java.util.Map<String, String> items = new java.util.HashMap<>(); items.put("other", input); items.put("key", "fixed"); return items.get("key");',
        'String result = "fixed"; if (input.length() > 1) { result = input; return "fixed"; } return result;',
        'String result = "fixed"; if (input.length() > 1) { result = input; throw new IllegalArgumentException(); } return result;',
        'String result = "fixed"; if (true) { result = input; return "fixed"; } return result;',
    ],
)
def test_local_helper_summary_keeps_safe_branches_and_collection_entries(
    source_root, body
):
    caller = _write(
        source_root / "demo" / "app" / "App.java",
        f"""package demo.app;
import javax.servlet.http.*;
class App {{
  String transform(String input) {{ {body} }}
  void render(HttpServletRequest request, HttpServletResponse response) throws Exception {{
    response.getWriter().print(transform(request.getParameter("display")));
  }}
}}
""",
    )
    assert _xss(caller) == []


@pytest.mark.parametrize(
    "tainted_names,expected",
    [({"carrier"}, True), ({"argument"}, True), (set(), False)],
)
def test_external_argument_only_helper_preserves_fallback_taint(
    source_root, tainted_names, expected
):
    _helper(source_root, expression="key")
    source = """package demo.app;
import demo.helpers.Carrier;
class App {
  String forward(Carrier carrier, String argument) {
    return carrier.value(argument);
  }
}
"""
    caller = _write(source_root / "demo" / "app" / "App.java", source)
    source_bytes = source.encode("utf-8")
    root_node = _get_parser(JAVA_LANG).parse(source_bytes).root_node
    analyzer = JavaSecurityFlowAnalyzer(root_node, str(caller), source_bytes)
    call = next(
        node
        for node in analyzer._iter_nodes(root_node)
        if node.type == "method_invocation"
    )
    state = JavaFlowState(
        tainted_vars=tainted_names,
        object_types={"carrier": "Carrier"},
        source_types={"carrier": "demo.helpers.Carrier"},
    )
    assert analyzer._method_call_facts(call, state).tainted is expected
