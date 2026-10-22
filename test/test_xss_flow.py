from __future__ import annotations

import ast
import textwrap
import pytest

import skylos.rules.danger.danger_web.xss_flow as xss


def _find_rule(findings, rule_id):
    for f in findings:
        if f.get("rule_id") == rule_id:
            return True
    return False


def test_qualified_name_from_call_simple():
    node = ast.parse("foo(1)").body[0].value
    assert isinstance(node, ast.Call)
    assert xss._qualified_name_from_call(node) == "foo"


def test_qualified_name_from_call_chain():
    node = ast.parse("a.b.c(1)").body[0].value
    assert isinstance(node, ast.Call)
    assert xss._qualified_name_from_call(node) == "a.b.c"


@pytest.mark.parametrize(
    "expr, expect",
    [
        ('f"hi {x}"', True),
        ('"a" + x', True),
        ('"<b>%s</b>" % x', True),
        ('"<b>{}</b>".format(x)', True),
        ('"plain"', False),
    ],
)
def test_is_interpolated_string(expr, expect):
    node = ast.parse(expr).body[0].value
    assert xss._is_interpolated_string(node) is expect


def test_const_str_value():
    assert xss._const_str_value(ast.parse('"hello"').body[0].value) == "hello"
    assert xss._const_str_value(ast.parse("123").body[0].value) is None


@pytest.mark.parametrize(
    "expr, expect",
    [
        ('"<b>hi</b>"', True),
        ('"nope"', False),
    ],
)
def test_const_contains_html(expr, expect):
    node = ast.parse(expr).body[0].value
    assert xss._const_contains_html(node) is expect


@pytest.mark.parametrize(
    "call_expr, expect",
    [
        ("Markup(user)", True),
        ('Markup(f"<b>{user}</b>")', True),
        ('Markup("<b>ok</b>")', False),
    ],
)
def test_rule_sky_d226(call_expr, expect):
    findings = []
    tree = ast.parse(f"def f(user):\n    return {call_expr}\n")
    xss.scan(tree, "x.py", findings)
    assert _find_rule(findings, "SKY-D226") is expect


def test_rule_sky_d226_mark_safe():
    findings = []
    tree = ast.parse("def f(user):\n    return mark_safe(user)\n")
    xss.scan(tree, "x.py", findings)
    assert _find_rule(findings, "SKY-D226") is True


@pytest.mark.parametrize(
    "tmpl, expect",
    [
        ('"hello |safe"', True),
        ('"{% autoescape false %}hi"', True),
        ('"{{ x }}"', False),
        ("tmpl", False),
    ],
)
def test_rule_sky_d227(tmpl, expect):
    findings = []
    tree = ast.parse(f"def f(tmpl):\n    return render_template_string({tmpl})\n")
    xss.scan(tree, "x.py", findings)
    assert _find_rule(findings, "SKY-D227") is expect


@pytest.mark.parametrize(
    "ret_expr, expect",
    [
        ('f"<b>{user}</b>"', True),
        ('f"hello {user}"', False),
        ('"<b>" + user + "</b>"', True),
        ('"<b>{}</b>".format(user)', True),
        ('"plain {}".format(user)', False),
        ('"<b>ok</b>" + clean', False),
    ],
)
def test_rule_sky_d228(ret_expr, expect):
    findings = []
    tree = ast.parse(f"def f(user):\n    return {ret_expr}\n")
    xss.scan(tree, "x.py", findings)
    assert _find_rule(findings, "SKY-D228") is expect


def test_rule_sky_d228_html_plus_local_clean_is_not_flagged():
    findings = []
    tree = ast.parse("def f(user):\n    clean = 'ok'\n    return '<b>ok</b>' + clean\n")
    xss.scan(tree, "x.py", findings)
    assert _find_rule(findings, "SKY-D228") is False


def test_scan_does_not_raise_on_exception(monkeypatch, capsys):
    class Boom(xss._XSSFlowChecker):
        def visit(self, node):
            raise RuntimeError("boom")

    monkeypatch.setattr(xss, "_XSSFlowChecker", Boom)

    findings = []
    tree = ast.parse("x = 1\n")
    xss.scan(tree, "x.py", findings)

    err = capsys.readouterr().err
    assert "XSS analysis failed for x.py" in err


def _scan_src(src: str):
    findings = []
    tree = ast.parse(src)
    xss.scan(tree, "x.py", findings)
    return findings


def _has_rule(findings, rule_id):
    for f in findings:
        if f.get("rule_id") == rule_id:
            return True
    return False


def test_rule_sky_d226_qualified_name_module_markup_flags():
    findings = _scan_src("def f(user):\n    return jinja2.Markup(user)\n")
    assert _has_rule(findings, "SKY-D226") is True


def test_rule_sky_d226_markup_with_local_const_is_not_flagged():
    findings = _scan_src("def f():\n    clean = 'ok'\n    return Markup(clean)\n")
    assert _has_rule(findings, "SKY-D226") is False


def test_rule_sky_d226_markup_interpolated_string_with_local_const_not_flagged():
    findings = _scan_src(
        "def f():\n    clean = 'ok'\n    return Markup(f\"<b>{clean}</b>\")\n"
    )
    assert _has_rule(findings, "SKY-D226") is False


def test_rule_sky_d226_markup_interpolated_string_with_taint_flags():
    findings = _scan_src('def f(user):\n    return Markup(f"<b>{user}</b>")\n')
    assert _has_rule(findings, "SKY-D226") is True


def test_rule_sky_d227_safe_filter_case_insensitive_flags():
    findings = _scan_src("def f():\n    return render_template_string('hello |SAFE')\n")
    assert _has_rule(findings, "SKY-D227") is True


def test_rule_sky_d227_autoescape_false_case_insensitive_flags():
    findings = _scan_src(
        "def f():\n    return render_template_string('{% AutoEscape False %}hi')\n"
    )
    assert _has_rule(findings, "SKY-D227") is True


def test_rule_sky_d228_fstring_html_with_local_not_tainted_not_flagged():
    findings = _scan_src("def f():\n    x = 'ok'\n    return f\"<b>{x}</b>\"\n")
    assert _has_rule(findings, "SKY-D228") is False


def test_rule_sky_d228_percent_format_html_with_taint_flags():
    findings = _scan_src("def f(user):\n    return '<b>%s</b>' % user\n")
    assert _has_rule(findings, "SKY-D228") is True


def test_rule_sky_d228_nested_binop_html_deeper_still_flags():
    findings = _scan_src("def f(user):\n    return '<b>' + ('x' + user)\n")
    assert _has_rule(findings, "SKY-D228") is True


def test_rule_sky_d228_nested_binop_html_on_right_still_flags():
    findings = _scan_src("def f(user):\n    return ('x' + user) + '</b>'\n")
    assert _has_rule(findings, "SKY-D228") is True


def test_rule_sky_d228_format_base_in_variable_not_detected_current_limitation():
    findings = _scan_src(
        "def f(user):\n    tmpl = '<b>{}</b>'\n    return tmpl.format(user)\n"
    )
    assert _has_rule(findings, "SKY-D228") is False


def test_llm_protocol_tags_are_not_html():
    # agent-pr-bench real-10: '</search>' delimits a model action, not markup.
    src = (
        "def postprocess_response(response: str) -> str:\n"
        "    if '</search>' in response:\n"
        "        return response.split('</search>')[0] + '</search>'\n"
        "    return '<answer>' + response + '</answer>'\n"
    )
    assert not [f for f in _scan_src(src) if f["rule_id"] == "SKY-D228"]


def test_html_tag_concatenation_still_flags():
    src = "def page(name):\n    return '<h1>' + name + '</h1>'\n"
    assert [f for f in _scan_src(src) if f["rule_id"] == "SKY-D228"]


def test_escape_imported_by_name_still_reports_in_url_attributes():
    findings = _scan_src(
        "from html import escape\n"
        "from django.utils.safestring import mark_safe\n"
        "def f(user):\n"
        "    return mark_safe('<a href=\"' + escape(user) + '\">x</a>')\n"
    )
    assert _find_rule(findings, "SKY-D226")


@pytest.mark.parametrize("call", ["bleach.linkify(user)", "cgi.escape(user)"])
def test_linkify_and_cgi_escape_are_not_xss_sanitizers(call):
    findings = _scan_src(
        "import bleach, cgi\n"
        "from django.utils.safestring import mark_safe\n"
        "def f(user):\n"
        f"    return mark_safe('<p title=\"' + {call} + '\">x</p>')\n"
    )
    assert _find_rule(findings, "SKY-D226")


def _d228(src: str):
    findings = _scan_src(textwrap.dedent(src))
    return [f for f in findings if f["rule_id"] == "SKY-D228"]


_ESCAPE_HELPER = """
    from html import escape

    def _e(value, default=""):
        return escape(str(value if value is not None else default))
"""


def test_escape_helper_in_element_text_is_not_reported():
    src = _ESCAPE_HELPER + """
    def slide(data):
        return f'<h1 class="t">{_e(data.get("title", "x"))}</h1>'
    """
    assert _d228(src) == []


def test_aliased_module_escape_behind_a_conditional_is_not_reported():
    src = """
    import html as html_lib

    def _escape_html(text):
        return html_lib.escape(text) if text else ""

    def render(result):
        return f'<div class="ai">{_escape_html(str(result.error))}</div>'
    """
    assert _d228(src) == []


def test_markupsafe_escape_helper_marked_safe_is_not_reported():
    src = """
    from markupsafe import Markup, escape

    def esc(value):
        return escape(value)

    def render(user):
        return Markup(f"<b>{esc(user)}</b>")
    """
    assert not [f for f in _scan_src(textwrap.dedent(src)) if f["rule_id"] == "SKY-D226"]


@pytest.mark.parametrize(
    "helper",
    [
        "def _e(value):\n        return str(value)\n",
        "def _e(value):\n        escape(value)\n        return value\n",
        "def _e(value, other=''):\n        return escape(other) + value\n",
        "def _e(value):\n        return escape(value) if value else value\n",
        "def _e(value):\n        if value:\n            return escape(value)\n        return value\n",
        "def _e(value):\n        safe = escape(value)\n        safe = value\n        return safe\n",
        "def _e(value):\n        parts = [escape(value)]\n        parts.append(value)\n        return ''.join(parts)\n",
        "def _e(value):\n        parts = []\n        alias = parts\n        alias.append(value)\n        return ''.join(parts)\n",
        "def _e(value):\n        escape = str\n        return escape(value)\n",
        "def _e(value):\n        return html.unescape(escape(value))\n",
        "def _e(value):\n        try:\n            return escape(value)\n        except Exception as exc:\n            return f'{exc}'\n",
    ],
)
def test_helper_that_does_not_escape_its_input_still_reports(helper):
    src = (
        "import html\nfrom html import escape\n\n"
        + textwrap.indent(textwrap.dedent("    " + helper), "")
        + "\ndef page(user):\n    return f'<p>{_e(user)}</p>'\n"
    )
    assert _d228(src)


def test_escape_helper_rebound_later_still_reports():
    src = _ESCAPE_HELPER + """
    _e = str

    def page(user):
        return f"<p>{_e(user)}</p>"
    """
    assert _d228(src)


def test_escape_helper_defined_twice_still_reports():
    src = _ESCAPE_HELPER + """
    def _e(value, default=""):
        return str(value)

    def page(user):
        return f"<p>{_e(user)}</p>"
    """
    assert _d228(src)


def test_decorated_escape_helper_still_reports():
    src = """
    from html import escape

    @register
    def _e(value):
        return escape(value)

    def page(user):
        return f"<p>{_e(user)}</p>"
    """
    assert _d228(src)


def test_escape_rebound_at_module_level_still_reports():
    src = """
    from html import escape
    escape = lambda value: value

    def _e(value):
        return escape(value)

    def page(user):
        return f"<p>{_e(user)}</p>"
    """
    assert _d228(src)


def test_escape_imported_from_an_unknown_module_still_reports():
    src = """
    from mylib.text import escape

    def _e(value):
        return escape(value)

    def page(user):
        return f"<p>{_e(user)}</p>"
    """
    assert _d228(src)


def test_star_import_makes_escape_helper_untrusted():
    src = _ESCAPE_HELPER + """
    from helpers import *

    def page(user):
        return f"<p>{_e(user)}</p>"
    """
    assert _d228(src)


def test_escape_helper_called_with_star_args_still_reports():
    src = _ESCAPE_HELPER + """
    def page(*args):
        return f"<p>{_e(*args)}</p>"
    """
    assert _d228(src)


def test_helper_default_that_reads_request_still_reports():
    src = """
    def label(value, prefix=request.args["p"]):
        return prefix + str(value)

    def page():
        return f"<p>{label(1)}</p>"
    """
    assert _d228(src)


def test_helper_that_reads_request_itself_is_reported():
    src = """
    def current_name():
        return request.args["name"]

    def page():
        return f"<p>{current_name()}</p>"
    """
    assert _d228(src)


_URL_HELPER = """
    from html import escape

    def _safe_url(url, default="#"):
        if url and str(url).strip().lower().startswith(("http://", "https://", "#", "/")):
            return escape(str(url), quote=True)
        return default
"""


def test_url_helper_with_scheme_allowlist_in_href_is_not_reported():
    src = _URL_HELPER + """
    def cta(data):
        return f'<a href="{_safe_url(data.get("url", "#"))}" class="btn">Go</a>'
    """
    assert _d228(src) == []


def test_url_guard_by_early_return_is_not_reported():
    src = """
    import html

    def link(url):
        if not url.startswith(("https://", "/")):
            return "<span>bad link</span>"
        return f'<a href="{html.escape(url)}">open</a>'
    """
    assert _d228(src) == []


def test_url_helper_passing_its_raw_default_through_still_reports():
    src = _URL_HELPER + """
    def cta(data):
        return f'<a href="{_safe_url(data.get("url"), data.get("fallback"))}">Go</a>'
    """
    assert _d228(src)


@pytest.mark.parametrize(
    "guard",
    [
        "True",
        "not url.startswith('javascript:')",
        "url.startswith(('http', 'j'))",
        "url.startswith(('https://', 'data:'))",
        "other.startswith('https://')",
        "url.startswith('/') or other",
        "url.lstrip('j').startswith('a')",
        "url.startswith('https://', 1)",
    ],
)
def test_url_escape_without_a_real_scheme_allowlist_still_reports(guard):
    src = f"""
    import html

    def link(url, other):
        if {guard}:
            return f'<a href="{{html.escape(url)}}">open</a>'
        return ""
    """
    findings = _d228(src)
    assert findings
    assert "URL attribute" in findings[0]["message"]


def test_url_reassigned_after_the_guard_still_reports():
    src = """
    import html

    def link(url, other):
        if url.startswith("https://"):
            url = other
            return f'<a href="{html.escape(url)}">open</a>'
        return ""
    """
    assert _d228(src)


def test_scheme_guard_does_not_cover_a_script_src():
    src = """
    import html

    def script_tag(url):
        if url.startswith("https://"):
            return f'<script src="{html.escape(url)}"></script>'
        return ""
    """
    assert _d228(src)


@pytest.mark.parametrize(
    "template",
    [
        '<button onclick="go({html.escape(user)})">x</button>',
        "<script>var name = '{html.escape(user)}';</script>",
        '<div style="color: {html.escape(user)}">x</div>',
        "<p><input value={html.escape(user)}></p>",
        '<p title="{html.escape(user, quote=False)}">x</p>',
        '<p title="{bleach.clean(user)}">x</p>',
        '<a href="{markupsafe.escape(user)}">x</a>',
        '<iframe srcdoc="{html.escape(user)}"></iframe>',
        "<{html.escape(user)}>x</b>",
    ],
)
def test_escaped_value_in_a_context_escaping_does_not_cover_still_reports(template):
    src = f"""
    import html, bleach, markupsafe

    def page(user):
        return f'''{template}'''
    """
    assert _d228(src)


@pytest.mark.parametrize(
    "template",
    [
        "<p>{html.escape(user)}</p>",
        '<p title="{html.escape(user)}">x</p>',
        "<p title='{markupsafe.escape(user)}'>x</p>",
        '<a href="/users/{html.escape(user)}">x</a>',
        '<a href="https://example.com/?q={html.escape(user)}">x</a>',
        "<p>{bleach.clean(user)}</p>",
        "<textarea>{html.escape(user)}</textarea>",
        "<!-- {html.escape(user)} --><p>x</p>",
        "<script>var n = 1;</script><p>{html.escape(user)}</p>",
    ],
)
def test_escaped_value_in_text_or_a_quoted_attribute_is_not_reported(template):
    src = f"""
    import html, bleach, markupsafe

    def page(user):
        return f'''{template}'''
    """
    assert _d228(src) == []


@pytest.mark.parametrize(
    "ret_expr",
    [
        "f'<td>{len(user)}</td><td>{int(user)}</td><td>{float(user)}</td>'",
        "f'<td>{user:d}</td><td>{user:.2f}</td><td>{user:>8,.1%}</td>'",
        "'<td>%d</td><td>%5.1f</td>' % (user, user)",
        "'<td>{:d}</td><td>{n:x}</td>'.format(user, n=user)",
    ],
)
def test_values_converted_to_numbers_are_not_reported(ret_expr):
    src = f"""
    def cell(user):
        return {ret_expr}
    """
    assert _d228(src) == []


def test_value_converted_to_a_number_before_use_is_not_reported():
    src = """
    def cell(user):
        count = int(user)
        return f"<td>{count}</td>"
    """
    assert _d228(src) == []


@pytest.mark.parametrize(
    "params, ret_expr",
    [
        ("user: int", "f'<p>{user}</p>'"),
        ("batch_num: int, total: int", "f'<b>[{batch_num}/{total}]</b>'"),
        ('total: "int"', "f'<td>{total}</td>'"),
        ("opt: Optional[float]", "f'<td>{opt}</td>'"),
        ("opt: int | None", "f'<td>{opt}</td>'"),
    ],
)
def test_number_annotations_alone_are_no_proof(params, ret_expr):
    src = f"""
    from typing import Optional

    def cell({params}):
        return {ret_expr}
    """
    assert _d228(src)


def test_number_annotated_helper_parameter_is_no_proof():
    src = """
    def label(count: int):
        return str(count)

    def page(user):
        return f"<p>{label(user)}</p>"
    """
    assert _d228(src)


@pytest.mark.parametrize(
    "ret_expr",
    [
        "f'<b>{label}</b>'",
        "f'<b>{either}</b>'",
        "f'<b>{loose}</b>'",
        "f'<td>{user:>8}</td>'",
        "f'<td>{user:c}</td>'",
        "f'<td>{user!r:d}</td>'",
        "'<td>%s</td>' % user",
        "'<td>%c</td>' % user",
        "'<td>{:s}</td>'.format(user)",
        "'<td>{name}</td>'.format(name=user)",
        "f'<td>{round(user)}</td>'",
        "f'<td>{abs(user)}</td>'",
    ],
)
def test_values_that_can_carry_html_still_report(ret_expr):
    src = f"""
    from typing import Union

    def cell(user, label: str, either: Union[int, str], loose: "int | str"):
        return {ret_expr}
    """
    assert _d228(src)


def test_number_annotated_parameter_reassigned_from_text_still_reports():
    src = """
    def cell(count: int, label):
        count = label
        return f"<td>{count}</td>"
    """
    assert _d228(src)


def test_rebound_int_is_not_a_number_proof():
    src = """
    def int(value):
        return value

    def cell(user):
        return f"<td>{int(user)}</td>"
    """
    assert _d228(src)


def test_qualified_escape_in_href_is_now_reported():
    src = """
    import html

    def link(url):
        return '<a href="' + html.escape(url) + '">x</a>'
    """
    findings = _d228(src)
    assert findings
    assert "scheme allowlist" in findings[0]["message"]


def test_unescaped_markdown_link_html_is_still_reported():
    src = """
    import re

    def to_html(text):
        html = text.replace("<", "&lt;").replace(">", "&gt;")
        html = re.sub(r"\\[([^\\]]+)\\]\\(([^)]+)\\)", r'<a href="\\2">\\1</a>', html)
        return f"<html><body>{html}</body></html>"
    """
    assert _d228(src)


def test_mark_safe_of_raw_helper_output_still_reports():
    src = """
    from markupsafe import Markup

    def shout(value):
        return value.upper()

    def render(user):
        return Markup(shout(user))
    """
    assert [f for f in _scan_src(textwrap.dedent(src)) if f["rule_id"] == "SKY-D226"]


@pytest.mark.parametrize(
    "helper",
    [
        "def _e(value):\n        return escape(value)\n",
        "def _e(value):\n        safe = escape(value)\n        return safe\n",
        "def _e(value):\n        if not value:\n            return ''\n        return escape(value)\n",
        "def _e(value):\n        parts = [escape(value)]\n        parts.append(escape(value))\n        return ''.join(parts)\n",
        "def _e(value):\n        return html.escape(str(value)).replace('\\n', '<br>')\n",
    ],
)
def test_helper_that_escapes_its_input_is_not_reported(helper):
    src = (
        "import html\nfrom html import escape\n\n"
        + textwrap.dedent("    " + helper)
        + "\ndef page(user):\n    return f'<p>{_e(user)}</p>'\n"
    )
    assert _d228(src) == []


@pytest.mark.parametrize(
    "guard",
    [
        "url.startswith(('https://', '/'))",
        "url.strip().lower().startswith('https://')",
        "(url.startswith('https://') and other) or url.startswith('/')",
    ],
)
def test_url_escape_behind_a_scheme_allowlist_is_not_reported(guard):
    src = f"""
    import html

    def link(url, other):
        if {guard}:
            return f'<a href="{{html.escape(url)}}">open</a>'
        return ""
    """
    assert _d228(src) == []


def test_script_src_with_a_fixed_origin_is_not_reported():
    src = """
    import html

    def script_tag(name):
        return f'<script src="https://cdn.example.com/{html.escape(name)}"></script>'
    """
    assert _d228(src) == []


def test_helper_escaping_each_item_it_joins_is_not_reported():
    src = """
    from html import escape

    def _join(items):
        return ", ".join(escape(item) for item in items)

    def page(tags):
        return f"<p>{_join(tags)}</p>"
    """
    assert _d228(src) == []


@pytest.mark.parametrize(
    "body",
    [
        'return ", ".join(item for item in items)',
        'return ", ".join(escape(label) + item for label, item in items)',
        "return str([escape(item) for item in items])",
    ],
)
def test_helper_joining_unescaped_items_still_reports(body):
    src = f"""
    from html import escape

    def _join(items):
        {body}

    def page(tags):
        return f'<p title="{{_join(tags)}}">x</p>'
    """
    assert _d228(src)


@pytest.mark.parametrize(
    "func",
    [
        "def page(user, html):\n        return f'<p>{html.escape(user)}</p>'\n",
        "def page(user, factory):\n        html = factory()\n        return f'<p>{html.escape(user)}</p>'\n",
        "def page(user, escape=str):\n        return f'<p>{escape(user)}</p>'\n",
    ],
)
def test_escape_name_bound_to_something_else_still_reports(func):
    src = "import html\nfrom html import escape\n\n" + textwrap.dedent("    " + func)
    assert _d228(src)


def test_qualified_escape_without_a_visible_import_is_still_trusted():
    src = "def page(user):\n    return f'<p>{html.escape(user)}</p>'\n"
    assert _d228(src) == []


@pytest.mark.parametrize(
    "template",
    [
        '<iframe src="{html.escape(url)}"></iframe>',
        '<form action="{html.escape(url)}"><p>x</p></form>',
        '<object data="{html.escape(url)}"><p>x</p></object>',
        '<base href="{html.escape(url)}"><p>x</p>',
        '<p><svg><a xlink:href="{html.escape(url)}">x</a></svg></p>',
    ],
)
def test_escaped_url_a_browser_follows_or_loads_still_reports(template):
    src = f"""
    import html

    def page(url):
        return f'''{template}'''
    """
    assert _d228(src)


@pytest.mark.parametrize(
    "template",
    [
        '<p><img src="{html.escape(url)}" alt="x"></p>',
        '<p><video poster="{html.escape(url)}"></video></p>',
        '<blockquote cite="{html.escape(url)}">x</blockquote>',
    ],
)
def test_escaped_url_in_a_media_or_metadata_attribute_is_not_reported(template):
    src = f"""
    import html

    def page(url):
        return f'''{template}'''
    """
    assert _d228(src) == []


def _url_rules(src: str):
    findings = _scan_src(textwrap.dedent(src))
    matching = []
    for finding in findings:
        if finding["rule_id"] in ("SKY-D226", "SKY-D228"):
            matching.append(finding)
    return matching


_URL_CHECKER = """
    import re
    import markupsafe

    _HTTP_URL_RE = re.compile(r"https?://\\S+", re.IGNORECASE)

    def _normalize_http_url(value):
        if not isinstance(value, str):
            return None
        normalized = value.strip()
        if not _HTTP_URL_RE.fullmatch(normalized):
            return None
        return normalized
"""

_URL_CELL = """
    class UrlColumn:
        async def render_cell(self, value, request):
            normalized = _normalize_http_url(value)
            if normalized is None:
                return markupsafe.escape(value)
            escaped = markupsafe.escape(normalized)
            return markupsafe.Markup(f'<a href="{escaped}">{escaped}</a>')
"""


def test_url_checked_by_a_regex_helper_is_not_reported():
    assert _url_rules(_URL_CHECKER + _URL_CELL) == []


@pytest.mark.parametrize(
    "old, new",
    [
        ("https?://", "[a-z]+://"),
        ("https?://", "(https?://)?"),
        (".fullmatch(normalized)", ".search(normalized)"),
        (".fullmatch(normalized)", ".fullmatch(value)"),
        (".fullmatch(normalized)", ".match(normalized, 3)"),
        ("        return None\n        normalized", "        return value\n        normalized"),
        ("            return None\n        return normalized", "            return 'javascript:void(0)'\n        return normalized"),
        ("        return normalized", "        normalized = value\n        return normalized"),
        ("    def _normalize_http_url", "    @staticmethod\n    def _normalize_http_url"),
        ("    import re\n", "    import re\n    re = object()\n"),
    ],
)
def test_url_helper_without_a_real_scheme_check_still_reports(old, new):
    checker = _URL_CHECKER.replace(old, new)
    assert checker != _URL_CHECKER
    assert _url_rules(checker + _URL_CELL)


def test_url_pattern_rebound_at_module_level_still_reports():
    assert _url_rules(_URL_CHECKER + "\n    _HTTP_URL_RE = re.compile('.*')\n" + _URL_CELL)


def test_url_helper_shadowed_in_the_caller_still_reports():
    cell = _URL_CELL.replace(
        "            normalized = _normalize_http_url(value)",
        "            _normalize_http_url = str\n            normalized = _normalize_http_url(value)",
    )
    assert _url_rules(_URL_CHECKER + cell)


def test_deep_url_helper_chain_keeps_later_unsafe_sinks(capsys):
    source = textwrap.dedent(_URL_CHECKER)
    previous = "_normalize_http_url"
    for index in range(350):
        name = f"check{index}"
        source += f"\ndef {name}(url):\n    return {previous}(url)\n"
        previous = name
    source += (
        f"\ndef render(url):\n    checked = {previous}(url)\n"
        "    return markupsafe.Markup(f'<a href=\"{markupsafe.escape(checked)}\">x</a>')\n"
        "\ndef vulnerable(user):\n    return markupsafe.Markup(user)\n"
    )
    sink_line = len(source.splitlines())
    assert any(row["line"] == sink_line for row in _url_rules(source))
    assert "maximum recursion depth" not in capsys.readouterr().err


@pytest.mark.parametrize(
    "guard",
    [
        "re.match(r'https?://', url)",
        "re.fullmatch(r'https?://\\S+', url, flags=re.I | re.ASCII)",
        "re.search(r'^(?:https?://|/)', url)",
        "re.match(r'https?://', url) is not None",
        "not re.match(r'https?://', url) is None",
        "re.compile(r'(?i)https://').match(url.strip())",
        "re.match(r'(?ui:httpſ://)', url, re.ASCII)",
        "re.match(r'(?ai:javaſcript):', url)",
    ],
)
def test_url_behind_a_regex_scheme_allowlist_is_not_reported(guard):
    src = f"""
    import re
    from markupsafe import Markup, escape

    def link(url):
        if {guard}:
            return Markup(f'<a href="{{escape(url)}}">x</a>')
        return ""
    """
    assert _url_rules(src) == []


@pytest.mark.parametrize(
    "guard",
    [
        "re.search(r'https?://', url)",
        "re.search(r'^https?://', url, re.M)",
        "re.match(r'https?://', url) is None",
        "re.match(r'.*', url)",
        "re.match(r'(?:https?|data):', url)",
        "re.match(r'https?://|', url)",
        "re.fullmatch(r'https?://\\S+', url, flags)",
        "re.match(pattern, url)",
        "url.startswith('https://') is not None",
        "re.match(r'(?ui:javaſcript):', url, re.ASCII)",
        "re.match(r'(?u:javaſcript):', url, re.ASCII | re.I)",
    ],
)
def test_url_behind_a_regex_that_lets_scripts_through_still_reports(guard):
    src = f"""
    import re
    from markupsafe import Markup, escape

    def link(url, flags, pattern):
        if {guard}:
            return Markup(f'<a href="{{escape(url)}}">x</a>')
        return ""
    """
    assert _url_rules(src)
