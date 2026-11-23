"""SKY-D226: ``Markup``/``mark_safe`` over HTML that no request value can
inject markup into is not reported; request-controlled content still is."""

from pathlib import Path

from skylos.rules.danger.danger import scan_ctx

_HEADER = """\
import html
from flask import Flask, request, render_template, render_template_string, url_for
from markupsafe import Markup, escape
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import get_lexer_by_name
from django.utils.safestring import mark_safe

app = Flask(__name__)
MODULE_FORMATTER = HtmlFormatter(linenos=True)

"""


def _marked_safe_lines(tmp_path: Path, body: str) -> list[int]:
    path = tmp_path / "views.py"
    path.write_text(_HEADER + body, encoding="utf-8")
    offset = _HEADER.count("\n")
    return sorted(
        f["line"] - offset
        for f in scan_ctx(tmp_path, [path])
        if f["rule_id"] == "SKY-D226"
    )


def test_safe_html_producers_are_not_reported(tmp_path):
    body = """\
@app.route("/a")
def view():
    name = request.args["name"]
    lexer = get_lexer_by_name("python")
    formatter = HtmlFormatter(cssclass="code")
    parts = [
        Markup("<b>static</b>"),
        Markup(render_template("part.html", name=name)),
        mark_safe(render_template(["a.html", "b.htm"], name=name)),
        Markup(f'<a href="{url_for("view", q=name)}">x</a>'),
        Markup("<div>{}</div>".format(url_for("static", filename=name))),
        Markup("<b>%s</b>" % escape(name)),
        mark_safe(f"<p>{html.escape(name)}</p>" + render_template("x.html", n=name)),
        Markup(highlight(name, lexer, HtmlFormatter())),
        Markup(highlight(name, lexer, formatter)),
        Markup(highlight(code=name, lexer=lexer, formatter=MODULE_FORMATTER)),
    ]
    return "".join(parts)
"""
    assert _marked_safe_lines(tmp_path, body) == []


def test_request_content_marked_safe_is_still_reported(tmp_path):
    body = """\
@app.route("/b")
def view():
    name = request.args["name"]
    lexer = get_lexer_by_name("python")
    parts = [
        Markup(name),
        mark_safe(f"<p>{name}</p>"),
        Markup(render_template_string(name)),
        Markup(render_template(name)),
        Markup(render_template("notes.txt", name=name)),
        Markup(f"<p>{url_for('view')}</p>{name}"),
        Markup(f"<a href='{url_for('view', q=name)}'>x</a>"),
        Markup(f'<a href="{url_for("view", q=name, _external=True)}">x</a>'),
        Markup(highlight(name, lexer, HtmlFormatter(title=name))),
        Markup(highlight(name, lexer, SomeFormatter())),
        mark_safe(escape(name) + name),
    ]
    return "".join(parts)
"""
    assert _marked_safe_lines(tmp_path, body) == list(range(6, 17))


def test_local_lookalike_render_template_is_not_trusted(tmp_path):
    path = tmp_path / "local.py"
    path.write_text(
        "from flask import request\n"
        "from markupsafe import Markup\n\n"
        "def render_template(name, **ctx):\n"
        "    return ctx['body']\n\n"
        "@app.route('/c')\n"
        "def view():\n"
        "    return Markup(render_template('x.html', body=request.args['b']))\n",
        encoding="utf-8",
    )
    lines = [
        f["line"] for f in scan_ctx(tmp_path, [path]) if f["rule_id"] == "SKY-D226"
    ]
    assert lines == [9]


def test_module_that_configures_autoescape_keeps_render_template_findings(tmp_path):
    path = tmp_path / "noescape.py"
    path.write_text(
        "from flask import Flask, request, render_template\n"
        "from markupsafe import Markup\n\n"
        "app = Flask(__name__)\n"
        "app.jinja_env.autoescape = False\n\n"
        "@app.route('/d')\n"
        "def view():\n"
        "    return Markup(render_template('x.html', body=request.args['b']))\n",
        encoding="utf-8",
    )
    lines = [
        f["line"] for f in scan_ctx(tmp_path, [path]) if f["rule_id"] == "SKY-D226"
    ]
    assert lines == [9]
