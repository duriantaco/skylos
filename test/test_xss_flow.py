from __future__ import annotations

import ast
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
        ("tmpl", False),  # not a const literal
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
    findings = _scan_src(
        "def f(user):\n"
        "    return jinja2.Markup(user)\n"
    )
    assert _has_rule(findings, "SKY-D226") is True


def test_rule_sky_d226_markup_with_local_const_is_not_flagged():
    findings = _scan_src(
        "def f():\n"
        "    clean = 'ok'\n"
        "    return Markup(clean)\n"
    )
    assert _has_rule(findings, "SKY-D226") is False


def test_rule_sky_d226_markup_interpolated_string_flags_even_if_local():
    findings = _scan_src(
        "def f():\n"
        "    clean = 'ok'\n"
        "    return Markup(f\"<b>{clean}</b>\")\n"
    )
    assert _has_rule(findings, "SKY-D226") is True


def test_rule_sky_d227_safe_filter_case_insensitive_flags():
    findings = _scan_src(
        "def f():\n"
        "    return render_template_string('hello |SAFE')\n"
    )
    assert _has_rule(findings, "SKY-D227") is True


def test_rule_sky_d227_autoescape_false_case_insensitive_flags():
    findings = _scan_src(
        "def f():\n"
        "    return render_template_string('{% AutoEscape False %}hi')\n"
    )
    assert _has_rule(findings, "SKY-D227") is True


def test_rule_sky_d228_fstring_html_with_local_not_tainted_not_flagged():
    findings = _scan_src(
        "def f():\n"
        "    x = 'ok'\n"
        "    return f\"<b>{x}</b>\"\n"
    )
    assert _has_rule(findings, "SKY-D228") is False


def test_rule_sky_d228_percent_format_html_with_taint_flags():
    findings = _scan_src(
        "def f(user):\n"
        "    return '<b>%s</b>' % user\n"
    )
    assert _has_rule(findings, "SKY-D228") is True


def test_rule_sky_d228_nested_binop_html_deeper_still_flags():
    findings = _scan_src(
        "def f(user):\n"
        "    return '<b>' + ('x' + user)\n"
    )
    assert _has_rule(findings, "SKY-D228") is True


def test_rule_sky_d228_nested_binop_html_on_right_still_flags():
    findings = _scan_src(
        "def f(user):\n"
        "    return ('x' + user) + '</b>'\n"
    )
    assert _has_rule(findings, "SKY-D228") is True


def test_rule_sky_d228_format_base_in_variable_not_detected_current_limitation():
    findings = _scan_src(
        "def f(user):\n"
        "    tmpl = '<b>{}</b>'\n"
        "    return tmpl.format(user)\n"
    )
    assert _has_rule(findings, "SKY-D228") is False
