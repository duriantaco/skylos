from __future__ import annotations

import ast

import pytest

from skylos.rules.danger.danger_web import xss_flow


def _scan(source):
    findings = []
    xss_flow.scan(ast.parse(source), "example.py", findings)
    return [f for f in findings if f["rule_id"] in {"SKY-D226", "SKY-D228"}]


@pytest.mark.parametrize(
    ("imports", "escape"),
    [
        ("from markupsafe import escape", "escape"),
        ("from markupsafe import escape as e", "e"),
        ("import markupsafe as ms", "ms.escape"),
        ("import markupsafe as html", "html.escape"),
        ("from markupsafe import Markup", "Markup.escape"),
        ("from html import escape as e", "e"),
    ],
)
@pytest.mark.parametrize(
    "template", ["<span>{value}</span>", '<p title="{value}">x</p>']
)
def test_proven_escape_imports_keep_their_html_text_and_attribute_context(
    imports, escape, template
):
    expression = "{" + escape + "(repr(obj))}"
    source = f"{imports}\ndef render(obj):\n    return f'{template.format(value=expression)}'\n"
    assert _scan(source) == []


@pytest.mark.parametrize(
    "template",
    [
        '<a href="{escape(obj)}">x</a>',
        "<script>{escape(obj)}</script>",
        '<p onclick="{escape(obj)}">x</p>',
    ],
)
def test_an_escape_does_not_prove_uncovered_html_contexts_safe(template):
    source = (
        "from markupsafe import escape, Markup\ndef render(obj):\n"
        + f"    return Markup(f'{template}')\n"
    )
    assert [(f["rule_id"], f["symbol"]) for f in _scan(source)] == [
        ("SKY-D226", "render")
    ]


@pytest.mark.parametrize(
    "prefix",
    [
        "from wrong import escape",
        "from markupsafe import escape\nescape = str",
        "import markupsafe\nmarkupsafe.escape = str\nfrom markupsafe import escape",
        "import markupsafe as ms\nms.escape = str\nfrom markupsafe import escape",
        "from unittest.mock import patch\nfrom markupsafe import escape\npatch('markupsafe.escape', str).start()",
    ],
)
def test_wrong_or_replaced_imported_provider_keeps_the_xss_finding(prefix):
    source = f"{prefix}\ndef render(obj):\n    return f'<span>{{escape(obj)}}</span>'\n"
    assert [(f["rule_id"], f["symbol"]) for f in _scan(source)] == [
        ("SKY-D228", "render")
    ]


@pytest.mark.parametrize(
    "prefix",
    [
        "from wrong import html",
        "from wrong import markupsafe as html",
        "import html\nhtml.escape = str",
        "from unittest.mock import patch\nimport html\npatch('html.escape', str).start()",
        "from unittest.mock import patch as p\nimport html\np.object(html, 'escape', str).start()",
        "import html\nglobals()['html'] = replacement",
        "import html\nhtml.__dict__['escape'] = str",
    ],
)
def test_qualified_spelling_does_not_override_actual_provider_or_mutation(prefix):
    source = (
        prefix + "\ndef render(obj):\n    return f'<span>{html.escape(obj)}</span>'\n"
    )
    assert [(f["rule_id"], f["symbol"]) for f in _scan(source)] == [
        ("SKY-D228", "render")
    ]


def test_provider_alias_uses_the_actual_escaping_options():
    source = "import html as markupsafe\ndef render(obj):\n    return f'<p title=\"{markupsafe.escape(obj, quote=False)}\">x</p>'\n"
    assert [(f["rule_id"], f["symbol"]) for f in _scan(source)] == [
        ("SKY-D228", "render")
    ]


@pytest.mark.parametrize(
    "consumer", ["lambda value: str(value)", "lambda value: install(value)"]
)
def test_frame_namespace_consumers_remain_uncertain(consumer):
    source = (
        "import sys\nfrom markupsafe import escape\n"
        f"reader = {consumer}\n"
        "def debug_snapshot():\n    return reader(sys._getframe(1).f_locals)\n"
        "def render(obj):\n    return f'<span>{escape(obj)}</span>'\n"
    )
    assert [(f["rule_id"], f["symbol"]) for f in _scan(source)] == [
        ("SKY-D228", "render")
    ]


@pytest.mark.parametrize(
    "reader",
    [
        "str(value)",
        "install(value)",
        "getattr(value, 'install')()",
        "value['install']()",
    ],
)
def test_source_known_methods_do_not_prove_frame_namespace_effects_safe(reader):
    source = (
        "import sys\nimport html\nfrom plugin import install\n"
        "class Snapshot:\n"
        "    def entries(self, mapping):\n"
        "        return [(key, self.reader(value)) for key, value in mapping.items()]\n"
        "    def reader(self, value):\n"
        f"        return {reader}\n"
        "def debug_snapshot():\n"
        "    snapshot = Snapshot()\n"
        "    return snapshot.entries(sys._getframe(1).f_locals)\n"
        "def render(obj):\n"
        "    return f'<span>{html.escape(obj)}</span>'\n"
    )
    assert [(f["rule_id"], f["symbol"]) for f in _scan(source)] == [
        ("SKY-D228", "render")
    ]


@pytest.mark.parametrize("unsafe", [False, True])
def test_actual_provider_resolution_preserves_raw_identity_listing_and_gate(unsafe):
    from skylos.core.gatekeeper import check_gate
    from skylos.reporting.listing import listed_result

    prefix = "from wrong import html\n" if unsafe else "import html\n"
    source = (
        prefix
        + "def render(obj):\n    return Markup(f'<span>{html.escape(obj)}</span>')\n"
    )
    findings = _scan(source)
    result = {"danger": findings}
    assert listed_result(result).get("danger", []) == findings
    if unsafe:
        [finding] = findings
        assert (
            finding["rule_id"],
            finding["file"],
            finding["line"],
            finding["symbol"],
            finding["severity"],
            finding["message"],
        ) == (
            "SKY-D226",
            "example.py",
            3,
            "render",
            "CRITICAL",
            "Possible XSS: untrusted content marked safe",
        )
    else:
        assert findings == []
    assert check_gate(result, {"gate": {"max_high": 0, "max_security": 0}})[0] is (
        not unsafe
    )
