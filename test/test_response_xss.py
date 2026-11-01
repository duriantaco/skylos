"""SKY-D228 for Flask and Django views that return request data in an HTML
response without escaping it, through the production analyzer."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from test.fixture_paths import write_fixture

FLASK = (
    "from flask import Flask, Response, jsonify, make_response, request\n"
    "import html\n"
    "import markupsafe\n"
    "app = Flask(__name__)\n"
)
PLAIN_FLASK = (
    "from flask import Flask, Response, make_response, request\napp = Flask(__name__)\n"
)
DJANGO = (
    "from django.http import HttpResponse, JsonResponse\n"
    "from django.utils.html import escape\n"
)


def _analyze(tmp_path, monkeypatch, source, name="app.py", modules=()):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    write_fixture(tmp_path, name, source)
    for module_name, text in modules:
        write_fixture(tmp_path, module_name, text)
    write_fixture(tmp_path, "pyproject.toml", '[project]\nname="views"\n')
    result = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            enable_sca=False,
            grep_verify=False,
            grep_cache=False,
            all_advice=False,
        )
    )
    assert not result.get("analysis_errors")
    return result


def _reported_lines(result, symbol=None):
    return sorted(
        f["line"]
        for f in result.get("danger", [])
        if f["rule_id"] == "SKY-D228" and symbol in (None, f["symbol"])
    )


def _listed_lines(result, symbol="search"):
    return sorted(
        f["line"]
        for f in result.get("danger", [])
        if f["rule_id"] == "SKY-D228"
        and f["listing"]["listed"]
        and f["symbol"] == symbol
    )


def _line(source, text):
    return next(
        number
        for number, line in enumerate(source.splitlines(), start=1)
        if text in line
    )


def _view(body, prefix=FLASK, rule="/search"):
    return prefix + f"@app.route('{rule}')\ndef search():\n" + body


REPORTED = {
    "f-string": "    q = request.args.get('q', '')\n    return f'Results for {q}'\n",
    "direct return": "    return request.args.get('q')\n",
    "concatenation": "    return 'Results for ' + request.form['q']\n",
    "format": "    return 'Results for {}'.format(request.cookies.get('q'))\n",
    "percent": "    return 'Results for %s' % (request.headers.get('X-Q'),)\n",
    "slice": "    q = request.args['q']\n    return 'Results ' + q[1:-1]\n",
    "augmented": "    out = ''\n    out += request.values.get('q', '')\n    return out\n",
    "status tuple": "    return f\"bad value {request.args['q']}\", 400\n",
    "make_response": "    return make_response('Results ' + request.args['q'])\n",
    "explicit text/html": (
        "    return Response(request.args['q'], mimetype='text/html')\n"
    ),
    "unrelated header": (
        "    resp = make_response(request.args['q'])\n"
        "    resp.headers['X-Frame-Options'] = 'DENY'\n"
        "    resp.set_cookie('seen', '1', secure=True, httponly=True)\n"
        "    return resp\n"
    ),
    "attacker mimetype": (
        "    return Response(request.args['q'], mimetype=request.args['type'])\n"
    ),
    "value in body and header": (
        "    v = request.args['q']\n"
        "    return make_response((f'saved {v}', {'X-Value': v}))\n"
    ),
    "loop over form keys": (
        "    name = ''\n"
        "    for key in request.form.keys():\n"
        "        name = key\n"
        "        break\n"
        "    return 'got ' + name\n"
    ),
    "match capture": (
        "    match request.args.get('m', ''):\n"
        "        case 'fixed':\n"
        "            out = 'fixed'\n"
        "        case other:\n"
        "            out = other\n"
        "    return out\n"
    ),
    "try handler sees the tainted state": (
        "    v = 'x'\n"
        "    try:\n"
        "        v = request.args['q']\n"
        "        v = 'y'\n"
        "        int(v)\n"
        "    except ValueError:\n"
        "        return f'bad {v}', 400\n"
        "    return 'ok'\n"
    ),
    "nested state inside a try body reaches the handler": (
        "    v = 'x'\n"
        "    try:\n"
        "        if request.args.get('raw'):\n"
        "            v = request.args['q']\n"
        "            v = 'y'\n"
        "            int(v)\n"
        "    except ValueError:\n"
        "        return f'bad {v}', 400\n"
        "    return 'ok'\n"
    ),
    "replace of ordinary text": (
        "    return 'Results ' + request.args['q'].replace(' ', '_').strip()\n"
    ),
    "base64 round trip": (
        "    import base64\n"
        "    raw = base64.b64encode(request.args['q'].encode('utf-8'))\n"
        "    return 'got ' + base64.b64decode(raw).decode('utf-8')\n"
    ),
    "url decoding": (
        "    from urllib.parse import unquote_plus\n"
        "    return 'got ' + unquote_plus(request.query_string.decode())\n"
    ),
    "json.loads then subscript": (
        "    import json\n"
        "    data = json.loads(request.get_data(as_text=True))\n"
        "    return f\"name {data['name']}\"\n"
    ),
    "json body": "    data = request.get_json()\n    return 'name: ' + str(data['name'])\n",
    "bytes body": "    return request.get_data()\n",
    "type=str conversion": "    return 'n ' + request.args.get('n', type=str)\n",
}


@pytest.mark.parametrize("body", list(REPORTED.values()), ids=list(REPORTED))
def test_flask_view_reflecting_request_data_as_html_is_reported(
    tmp_path, monkeypatch, body
):
    source = _view(body, prefix=PLAIN_FLASK)
    assert "<" not in source and "markup" not in source.lower()
    result = _analyze(tmp_path, monkeypatch, source)
    assert _reported_lines(result) == [_line(source, "    return ")]
    finding = next(f for f in result["danger"] if f["rule_id"] == "SKY-D228")
    assert finding["severity"] == "HIGH"
    assert finding["listing"]["listed"] is True
    assert finding["symbol"] == "search"
    assert finding["metadata"]["security_evidence"]["source"]
    passed, _ = check_gate(result, {"gate": {"max_high": 0}})
    assert passed is False


QUIET = {
    "html.escape": "    q = html.escape(request.args.get('q', ''))\n    return f'Results {q}'\n",
    "markupsafe.escape": (
        "    return 'Results ' + markupsafe.escape(request.args['q'])\n"
    ),
    "Markup.escape": (
        "    from markupsafe import Markup\n"
        "    return 'Results ' + Markup.escape(request.args['q'])\n"
    ),
    "helper that escapes": None,
    "jsonify": "    return jsonify(q=request.args.get('q'))\n",
    "dict body": "    return {'q': request.args.get('q')}\n",
    "unknown call result": "    return lookup(request.args['q'])\n",
    "text/plain mimetype": (
        "    return Response(request.args['q'], mimetype='text/plain')\n"
    ),
    "json content type": (
        "    return Response(request.args['q'], content_type='application/json')\n"
    ),
    "content type set later": (
        "    resp = make_response(request.args['q'])\n"
        "    resp.headers['Content-Type'] = 'text/plain'\n"
        "    return resp\n"
    ),
    "content type set through an alias": (
        "    resp = make_response(request.args['q'])\n"
        "    other = resp\n"
        "    other.mimetype = 'text/plain'\n"
        "    return resp\n"
    ),
    "plain header in a tuple": (
        "    return request.args['q'], 200, {'Content-Type': 'text/plain'}\n"
    ),
    "headers only": (
        "    v = request.args['q']\n"
        "    return make_response(('saved', {'X-Value': v}))\n"
    ),
    "int conversion": "    return f\"page {int(request.args['n'])}\"\n",
    "type=int": "    return f\"page {request.args.get('n', 1, type=int)}\"\n",
    "request metadata": ("    return f'{request.method} from {request.remote_addr}'\n"),
    "overwritten value": (
        "    q = request.args['q']\n    q = 'fixed'\n    return f'{q}'\n"
    ),
    "clean dict key": (
        "    d = {}\n"
        "    d['user'] = request.args['q']\n"
        "    d['shown'] = 'ok'\n"
        "    return 'v ' + d['shown']\n"
    ),
    "string copy before the tainted append": (
        "    s = ''\n"
        "    c = s\n"
        "    s += request.args['q']\n"
        "    c += 'ok'\n"
        "    return 'v ' + c\n"
    ),
    "template": (
        "    from flask import render_template\n"
        "    return render_template('page.html', q=request.args['q'])\n"
    ),
}
QUIET["helper that escapes"] = (
    "    return 'Results ' + show(request.args['q'])\n"
    "def show(value):\n"
    "    return html.escape(value)\n"
)


@pytest.mark.parametrize("body", list(QUIET.values()), ids=list(QUIET))
def test_escaped_non_html_or_non_text_responses_stay_quiet(tmp_path, monkeypatch, body):
    result = _analyze(tmp_path, monkeypatch, _view(body))
    assert _reported_lines(result) == []


CONTROLS = {
    "constant-looking value that is really tainted": (
        "    greeting = 'safe!'\n"
        "    greeting = request.args['name']\n"
        "    return greeting\n"
    ),
    "constant-looking dict key read after a tainted store": (
        "    d = {'shown': 'ok'}\n"
        "    d['shown'] = request.args['q']\n"
        "    return 'v ' + d['shown']\n"
    ),
    "guard that does not guard": (
        "    q = request.args.get('q', '')\n"
        "    if 'script' in q:\n"
        "        print('suspicious')\n"
        "    return f'Results {q}'\n"
    ),
    "branch that keeps the tainted value": (
        "    q = 'fixed'\n"
        "    if request.args.get('raw'):\n"
        "        q = request.args['q']\n"
        "    return f'{q}'\n"
    ),
    "alias of request": "    req = request\n    return 'Results ' + req.form['q']\n",
    "imported alias of request": None,
    "alias of a dict written after the copy": (
        "    d = {}\n"
        "    e = d\n"
        "    e['q'] = request.args['q']\n"
        "    return 'v ' + d['q']\n"
    ),
    "alias of a list extended in place": (
        "    items = []\n"
        "    view = items\n"
        "    items += [request.args['q']]\n"
        "    return ', '.join(view)\n"
    ),
    "wrapper function returning the tainted string": (
        "    return build()\ndef build():\n    return 'Hello ' + request.args['name']\n"
    ),
    "wrapper function passing its argument through": (
        "    return same(request.args['name'])\ndef same(value):\n    return value\n"
    ),
    "wrapper adding markup": (
        "    return wrap(request.args['q'])\ndef wrap(x):\n    return f'<b>{x}</b>'\n"
    ),
    "wrapper using str and strip": (
        "    return 'Hi ' + tidy(request.args['q'])\n"
        "def tidy(value):\n"
        "    return str(value).strip().lower()\n"
    ),
    "same-module pass-through chain": (
        "    return 'Hi ' + outer(request.args['q'])\n"
        "def inner(value):\n"
        "    return value.strip()\n"
        "def outer(value):\n"
        "    return inner(value)\n"
    ),
    "local function named escape": (
        "    return 'Results ' + escape(request.args['q'])\n"
        "def escape(value):\n"
        "    return value\n"
    ),
}
CONTROLS["imported alias of request"] = "    return 'Results ' + req.args['q']\n"


@pytest.mark.parametrize("body", list(CONTROLS.values()), ids=list(CONTROLS))
def test_must_still_report_controls(tmp_path, monkeypatch, body):
    prefix = FLASK
    if body == CONTROLS["imported alias of request"]:
        prefix = FLASK + "from flask import request as req\n"
    source = _view(body, prefix=prefix)
    result = _analyze(tmp_path, monkeypatch, source)
    assert _listed_lines(result) == [_line(source, "    return ")]


HIDDEN = {
    "unresolved imported helper": (
        "    from myproject.utils import escape_html\n"
        "    return 'Results ' + escape_html(request.args['q'])\n"
    ),
    "method on an unknown object": (
        "    wrapped = wrap(request)\n"
        "    value = wrapped.param('q')\n"
        "    return f'{value}'\n"
    ),
    "value stored into an unknown object": (
        "    store = Store()\n"
        "    store.put('k', request.args['q'])\n"
        "    return f\"{store.fetch('k')}\"\n"
    ),
    "configparser get": (
        "    import configparser\n"
        "    conf = configparser.ConfigParser()\n"
        "    conf.add_section('s')\n"
        "    conf.set('s', 'k', request.args['q'])\n"
        "    return f\"{conf.get('s', 'k')}\"\n"
    ),
}


READABLE = {
    "hand-written replace of markup": (
        "    q = request.args['q'].replace('&', '&amp;').replace('<', '&lt;')\n"
        "    return 'Results ' + q\n"
    ),
}


@pytest.mark.parametrize("body", list(READABLE.values()), ids=list(READABLE))
def test_readable_transforms_keep_request_data_listed(tmp_path, monkeypatch, body):
    source = _view(body)
    result = _analyze(tmp_path, monkeypatch, source)
    assert _listed_lines(result) == [_line(source, "    return ")]


@pytest.mark.parametrize("body", list(HIDDEN.values()), ids=list(HIDDEN))
def test_unresolved_transforms_stay_raw_and_gated_but_are_not_listed(
    tmp_path, monkeypatch, body
):
    source = _view(body)
    result = _analyze(tmp_path, monkeypatch, source)
    assert _reported_lines(result) == [_line(source, "    return ")]
    assert _listed_lines(result) == []
    finding = next(f for f in result["danger"] if f["rule_id"] == "SKY-D228")
    assert finding["severity"] == "HIGH"
    assert finding["low_risk_context"]["reason"] == "unresolved-transform"
    assert finding["listing"] == {
        "version": 1,
        "listed": False,
        "reason": "low-risk-context",
    }
    passed, _ = check_gate(result, {"gate": {"max_high": 0}})
    assert passed is False


@pytest.mark.parametrize(
    "prefix",
    [
        "html.escape = str\n",
        "setattr(html, 'escape', str)\n",
        "from unittest.mock import patch\npatch('html.escape', str).start()\n",
    ],
)
def test_replaced_escape_does_not_clear_request_data(tmp_path, monkeypatch, prefix):
    source = _view(
        "    return 'Results ' + html.escape(request.args['q'])\n",
        prefix=FLASK + prefix,
    )
    result = _analyze(tmp_path, monkeypatch, source)
    assert _reported_lines(result) == [_line(source, "    return ")]


@pytest.mark.parametrize(
    "rule, reported",
    [
        ("/hello/<name>", True),
        ("/hello/<string:name>", True),
        ("/files/<path:name>", True),
        ("/items/<int:name>", False),
        ("/items/<uuid:name>", False),
    ],
)
def test_route_parameters_follow_their_converter(tmp_path, monkeypatch, rule, reported):
    source = (
        FLASK
        + f"@app.get('{rule}')\ndef show(name):\n    return 'Hello ' + str(name)\n"
    )
    result = _analyze(tmp_path, monkeypatch, source)
    assert bool(_reported_lines(result)) is reported


def test_errorhandler_reflecting_the_path_is_reported(tmp_path, monkeypatch):
    source = (
        FLASK
        + "@app.errorhandler(404)\ndef missing(error):\n    return f'No page {request.path}', 404\n"
    )
    result = _analyze(tmp_path, monkeypatch, source)
    assert _reported_lines(result) == [_line(source, "    return ")]


def test_view_registered_inside_an_app_factory_is_reported(tmp_path, monkeypatch):
    source = (
        "from flask import request\n"
        "def init(app):\n"
        "    @app.route('/search', methods=['POST'])\n"
        "    def search():\n"
        "        page = ''\n"
        "        value = request.form.get('q')\n"
        "        if not value:\n"
        "            value = ''\n"
        "        page += f'You searched for {value}'\n"
        "        return page\n"
    )
    result = _analyze(tmp_path, monkeypatch, source)
    assert _reported_lines(result) == [_line(source, "        return page")]


@pytest.mark.parametrize(
    "source",
    [
        "from fastapi import FastAPI\nimport flask\napp = FastAPI()\n"
        "@app.get('/search')\ndef search(q: str):\n    return 'Results ' + q\n",
        FLASK + "def not_a_view():\n    return 'Results ' + request.args['q']\n",
        FLASK + "@app.route('/stream')\ndef stream():\n    yield request.args['q']\n",
    ],
    ids=["fastapi", "plain function", "generator"],
)
def test_non_views_and_json_frameworks_stay_quiet(tmp_path, monkeypatch, source):
    assert _reported_lines(_analyze(tmp_path, monkeypatch, source)) == []


DJANGO_CASES = [
    (
        "def search(request):\n"
        "    q = request.GET.get('q', '')\n"
        "    return HttpResponse(f'Results for {q}')\n",
        True,
    ),
    (
        "def search(request):\n"
        "    return HttpResponse('Hi ' + request.POST['name'], status=400)\n",
        True,
    ),
    (
        "from django.views import View\n"
        "class Search(View):\n"
        "    def get(self, *args):\n"
        "        return HttpResponse('Hi ' + self.request.GET['n'])\n",
        True,
    ),
    (
        "def search(request: 'HttpRequest'):\n"
        "    return HttpResponse('Hi ' + request.headers['X-Name'])\n",
        True,
    ),
    (
        "def search(request):\n"
        "    return HttpResponse('Hi ' + escape(request.GET['n']))\n",
        False,
    ),
    (
        "def search(request):\n    return JsonResponse({'q': request.GET.get('q')})\n",
        False,
    ),
    (
        "def search(request):\n"
        "    return HttpResponse(request.GET['q'], content_type='text/plain')\n",
        False,
    ),
    (
        "def search(request):\n"
        "    response = HttpResponse(request.GET['q'])\n"
        "    response['Content-Type'] = 'text/plain'\n"
        "    return response\n",
        False,
    ),
    (
        "def search(request):\n    return f\"Results {request.GET['q']}\"\n",
        False,
    ),
    (
        "def search(request):\n"
        "    return HttpResponse(f'Hello {request.user.username}')\n",
        False,
    ),
    (
        "def build(request: 'TranslateRequest'):\n"
        "    return HttpResponse('Hi ' + request.text)\n",
        False,
    ),
]


@pytest.mark.parametrize("body, reported", DJANGO_CASES)
def test_django_http_response_from_request_data(tmp_path, monkeypatch, body, reported):
    source = DJANGO + body
    result = _analyze(tmp_path, monkeypatch, source)
    expected = []
    if reported:
        expected = [_line(source, "return ")]
    assert _reported_lines(result) == expected


@pytest.mark.parametrize(
    "name, reported",
    [
        ("tests/test_views.py", False),
        ("views_test.py", False),
        ("latest/views.py", True),
    ],
)
def test_test_modules_are_not_reported(tmp_path, monkeypatch, name, reported):
    source = _view("    return request.args['q']\n")
    result = _analyze(tmp_path, monkeypatch, source, name=name)
    assert bool(_reported_lines(result)) is reported


def test_existing_literal_html_finding_is_not_duplicated(tmp_path, monkeypatch):
    source = _view("    return f\"<p>{request.args['q']}</p>\"\n")
    result = _analyze(tmp_path, monkeypatch, source)
    findings = [f for f in result["danger"] if f["rule_id"] == "SKY-D228"]
    assert [f["line"] for f in findings] == [_line(source, "    return ")]
    assert findings[0]["message"] == "XSS (HTML built from unescaped user input)"


def test_framework_is_decided_per_view_in_a_mixed_module(tmp_path, monkeypatch):
    source = (
        "from fastapi import FastAPI\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "api = FastAPI()\n"
        "@app.route('/page')\n"
        "def page():\n"
        "    return 'Hi ' + request.args['q']\n"
        "@api.get('/json')\n"
        "def data(q: str):\n"
        "    return 'Hi ' + q\n"
        "@app.get('/other/<name>')\n"
        "def other(name):\n"
        "    return 'Hi ' + name\n"
    )
    result = _analyze(tmp_path, monkeypatch, source)
    findings = [f for f in result["danger"] if f["rule_id"] == "SKY-D228"]
    assert sorted((f["symbol"], f["listing"]["listed"]) for f in findings) == [
        ("other", True),
        ("page", True),
    ]


def test_fastapi_import_alone_does_not_hide_a_flask_view(tmp_path, monkeypatch):
    source = (
        "from flask import Flask, request\n"
        "from fastapi import FastAPI\n"
        "app = Flask(__name__)\n"
        "@app.route('/q')\n"
        "def page():\n"
        "    return 'Hi ' + request.args['q']\n"
    )
    result = _analyze(tmp_path, monkeypatch, source)
    assert _listed_lines(result, symbol="page") == [_line(source, "    return ")]


PROJECT = (("myproject/__init__.py", ""),)
CROSS_MODULE = {
    "identity helper": (
        "from myproject.utils import identity\n",
        "identity(request.args['q'])",
        "def identity(value):\n    return value\n",
        True,
    ),
    "module attribute call": (
        "import myproject.utils\n",
        "myproject.utils.identity(request.args['q'])",
        "def identity(value):\n    return value\n",
        True,
    ),
    "relative import": (
        None,
        "identity(request.args['q'])",
        "def identity(value):\n    return value\n",
        True,
    ),
    "markup wrapper": (
        "from myproject.utils import bold\n",
        "bold(request.args['q'])",
        "def bold(value):\n    return f'<b>{value}</b>'\n",
        True,
    ),
    "pass-through helper chain": (
        "from myproject.utils import outer\n",
        "outer(request.args['q'])",
        "def inner(value):\n    return value\ndef outer(value):\n    return inner(value)\n",
        True,
    ),
    "chain through a second module": (
        "from myproject.utils import outer\n",
        "outer(request.args['q'])",
        "from myproject.text import tidy\ndef outer(value):\n    return tidy(value)\n",
        True,
    ),
    "chain deeper than three helpers": (
        "from myproject.utils import first\n",
        "first(request.args['q'])",
        "def fourth(v):\n    return v\n"
        "def third(v):\n    return fourth(v)\n"
        "def second(v):\n    return third(v)\n"
        "def first(v):\n    return second(v)\n",
        True,
    ),
    "mutually recursive helpers": (
        "from myproject.utils import ping\n",
        "ping(request.args['q'])",
        "def ping(v):\n    return pong(v)\ndef pong(v):\n    return ping(v)\n",
        True,
    ),
    "unresolvable module": (
        "from elsewhere.utils import identity\n",
        "identity(request.args['q'])",
        "def identity(value):\n    return value\n",
        False,
    ),
}


@pytest.mark.parametrize(
    "imports, call, helper, listed", list(CROSS_MODULE.values()), ids=list(CROSS_MODULE)
)
def test_project_helpers_are_summarised_across_modules(
    tmp_path, monkeypatch, imports, call, helper, listed
):
    name = "app.py"
    modules = [
        *PROJECT,
        ("myproject/utils.py", helper),
        ("myproject/text.py", "def tidy(value):\n    return value.strip()\n"),
    ]
    if imports is None:
        name = "myproject/views.py"
        imports = "from .utils import identity\n"
    source = (
        "from flask import Flask, request\n"
        + imports
        + "app = Flask(__name__)\n"
        + "@app.route('/search')\n"
        + "def search():\n"
        + f"    return 'Hi ' + {call}\n"
    )
    result = _analyze(tmp_path, monkeypatch, source, name=name, modules=modules)
    assert _reported_lines(result, symbol="search") == [_line(source, "    return ")]
    expected = []
    if listed:
        expected = [_line(source, "    return ")]
    assert _listed_lines(result, symbol="search") == expected


def test_project_helper_that_escapes_clears_the_value(tmp_path, monkeypatch):
    modules = [
        *PROJECT,
        (
            "myproject/utils.py",
            "import html\ndef show(value):\n    return html.escape(value)\n",
        ),
    ]
    source = (
        "from flask import Flask, request\n"
        "from myproject.utils import show\n"
        "app = Flask(__name__)\n"
        "@app.route('/search')\n"
        "def search():\n"
        "    return 'Hi ' + show(request.args['q'])\n"
    )
    result = _analyze(tmp_path, monkeypatch, source, modules=modules)
    assert _reported_lines(result, symbol="search") == []


FACTORY_CASES = [
    (
        "from flask import Flask, request\n"
        "from fastapi import FastAPI\n"
        "def init(app):\n"
        "    @app.route('/')\n"
        "    def page():\n"
        "        return 'Hi ' + request.args['q']\n"
        "    return app\n"
        "flask_app = init(Flask(__name__))\n"
        "api = FastAPI()\n",
        True,
    ),
    (
        "from flask import Flask, request\n"
        "from fastapi import FastAPI\n"
        "def init(app):\n"
        "    @app.get('/')\n"
        "    def page():\n"
        "        return 'Hi ' + request.args['q']\n"
        "    return app\n"
        "flask_app = init(Flask(__name__))\n",
        True,
    ),
    (
        "from flask import request\n"
        "from fastapi import FastAPI\n"
        "def init(app):\n"
        "    @app.get('/')\n"
        "    def page():\n"
        "        return 'Hi ' + request.args['q']\n"
        "    return app\n"
        "api = init(FastAPI())\n",
        False,
    ),
    (
        "from flask import request\n"
        "from fastapi import FastAPI\n"
        "def init(app):\n"
        "    @app.get('/')\n"
        "    def page():\n"
        "        return 'Hi ' + request.args['q']\n"
        "    return app\n",
        False,
    ),
    (
        "from flask import request\n"
        "from starlette.applications import Starlette\n"
        "app = Starlette()\n"
        "@app.route('/')\n"
        "def page(req):\n"
        "    return 'Hi ' + request.args['q']\n",
        False,
    ),
]


@pytest.mark.parametrize(
    "source, reported",
    FACTORY_CASES,
    ids=[
        "route via init(Flask())",
        "get via init(Flask())",
        "get via init(FastAPI())",
        "get on an unresolved receiver",
        "route on Starlette",
    ],
)
def test_app_factory_receivers_in_a_module_that_imports_fastapi(
    tmp_path, monkeypatch, source, reported
):
    result = _analyze(tmp_path, monkeypatch, source)
    expected = []
    if reported:
        expected = [_line(source, "        return ")]
    assert _listed_lines(result, symbol="page") == expected
    assert _reported_lines(result, symbol="page") == expected


DEEP_CHAINS = {
    "same-module chain past the budget": (
        (),
        "def d(x):\n    return x\n"
        "def c(x):\n    return d(x)\n"
        "def b(x):\n    return c(x)\n"
        "def a(x):\n    return b(x)\n",
        True,
    ),
    "chain past the budget across modules": (
        (
            (
                "myproject/one.py",
                "from myproject.two import b\ndef a(x):\n    return b(x)\n",
            ),
            (
                "myproject/two.py",
                "from myproject.three import c\ndef b(x):\n    return c(x.strip())\n",
            ),
            ("myproject/three.py", "from .four import d\ndef c(x):\n    return d(x)\n"),
            ("myproject/four.py", "def d(x):\n    return x\n"),
        ),
        "from myproject.one import a\n",
        True,
    ),
    "html.escape within the budget": (
        (),
        "import html\n"
        "def d(x):\n    return x\n"
        "def c(x):\n    return d(x)\n"
        "def b(x):\n    return c(html.escape(x))\n"
        "def a(x):\n    return b(x)\n",
        False,
    ),
    "markupsafe.escape within the budget across modules": (
        (
            (
                "myproject/one.py",
                "import markupsafe\nfrom myproject.two import b\n"
                "def a(x):\n    return b(markupsafe.escape(x))\n",
            ),
            (
                "myproject/two.py",
                "from myproject.three import c\ndef b(x):\n    return c(x)\n",
            ),
            ("myproject/three.py", "from .four import d\ndef c(x):\n    return d(x)\n"),
            ("myproject/four.py", "def d(x):\n    return x\n"),
        ),
        "from myproject.one import a\n",
        False,
    ),
}


@pytest.mark.parametrize(
    "modules, helpers, reported", list(DEEP_CHAINS.values()), ids=list(DEEP_CHAINS)
)
def test_helper_chains_past_the_depth_budget_stay_listed_unless_escaped(
    tmp_path, monkeypatch, modules, helpers, reported
):
    source = (
        "from flask import Flask, request\n"
        + helpers
        + "app = Flask(__name__)\n"
        + "@app.route('/')\n"
        + "def page():\n"
        + "    return 'Hi ' + a(request.args['q'])\n"
    )
    result = _analyze(tmp_path, monkeypatch, source, modules=[*PROJECT, *modules])
    expected = []
    if reported:
        expected = [_line(source, "    return 'Hi '")]
    assert _listed_lines(result, symbol="page") == expected
    assert _reported_lines(result, symbol="page") == expected


SHAPES = {
    "recursive list walker": (
        "def last(items, picked=''):\n"
        "    if items:\n"
        "        return last(items[1:], items[0])\n"
        "    return picked\n",
        "'Hi ' + last([request.args['q']])",
        True,
    ),
    "recursive dict walker": (
        "def walk(box):\n"
        "    if isinstance(box, dict):\n"
        "        return walk(box['value'])\n"
        "    return box\n",
        "'Hi ' + walk({'value': {'value': request.args['q']}})",
        True,
    ),
    "mixed arguments past the budget": (
        "def d(x, n):\n    return x\n"
        "def c(x, n):\n    return d(x, n)\n"
        "def b(x, n):\n    return c(x, n)\n"
        "def a(x):\n    return b(x, 0)\n",
        "a(request.args['q'])",
        True,
    ),
    "keyword and default arguments": (
        "def h(x, sep=', '):\n    return sep.join([x, 'end'])\n",
        "'Hi ' + h(x=request.args['q'])",
        True,
    ),
    "double-star call": (
        "def h(x, sep=', '):\n    return x\n",
        "'Hi ' + h(**{'x': request.args['q']})",
        True,
    ),
    "star parameters": (
        "def h(*parts):\n    return ' '.join(parts)\n",
        "'Hi ' + h(request.args['q'], 'x')",
        True,
    ),
    "starred call": (
        "def h(first, second):\n    return first\n",
        "'Hi ' + h(*[request.args['q'], 'x'])",
        True,
    ),
    "instance method": (
        "class Fmt:\n    def show(self, v):\n        return v\n",
        "'Hi ' + Fmt().show(request.args['q'])",
        True,
    ),
    "classmethod and staticmethod": (
        "class Fmt:\n"
        "    @classmethod\n"
        "    def show(cls, v):\n        return v\n"
        "    @staticmethod\n"
        "    def tidy(v):\n        return v.strip()\n",
        "'Hi ' + Fmt.show(Fmt.tidy(request.args['q']))",
        True,
    ),
    "object built from request data": (
        "class Box:\n"
        "    def __init__(self, value):\n        self.value = value\n"
        "    def get(self):\n        return self.value\n",
        "'Hi ' + Box(request.args['q']).get()",
        True,
    ),
    "wrapping decorator": (
        "import functools\n"
        "def deco(f):\n"
        "    @functools.wraps(f)\n"
        "    def wrapper(*a, **k):\n        return f(*a, **k)\n"
        "    return wrapper\n"
        "@deco\n"
        "def h(v):\n    return v\n",
        "'Hi ' + h(request.args['q'])",
        True,
    ),
    "functools.partial": (
        "import functools\ndef h(prefix, v):\n    return prefix + v\n",
        "functools.partial(h, 'Hi ')(request.args['q'])",
        True,
    ),
    "partial holding request data": (
        "from functools import partial\ndef h(v, suffix):\n    return v + suffix\n",
        "'Hi ' + partial(h, request.args['q'])('!')",
        True,
    ),
    "lambda": (
        "",
        "'Hi ' + (lambda v: v.strip())(request.args['q'])",
        True,
    ),
    "generator joined": (
        "def gen(v):\n    yield v\n    yield '!'\n",
        "'Hi ' + ''.join(gen(request.args['q']))",
        True,
    ),
    "try/except": (
        "def h(v):\n"
        "    try:\n        return v.encode().decode()\n"
        "    except ValueError:\n        return v\n",
        "'Hi ' + h(request.args['q'])",
        True,
    ),
    "early return": (
        "def h(v):\n    if not v:\n        return ''\n    return v\n",
        "'Hi ' + h(request.args['q'])",
        True,
    ),
    "f-string and format": (
        "def h(v):\n    return f'<{v}>' + '[{}]'.format(v)\n",
        "'Hi ' + h(request.args['q'])",
        True,
    ),
    "escape inside the budget": (
        "import html\ndef h(v):\n    return html.escape(v)\n",
        "'Hi ' + h(request.args['q'])",
        False,
    ),
    "helper returning len": (
        "def h(v):\n    return str(len(v))\n",
        "'Hi ' + h(request.args['q'])",
        False,
    ),
    "helper returning a constant": (
        "def h(v):\n    return 'fixed'\n",
        "'Hi ' + h(request.args['q'])",
        False,
    ),
    "helper returning int": (
        "def h(v):\n    return int(v)\n",
        "f\"Hi {h(request.args['q'])}\"",
        False,
    ),
}


@pytest.mark.parametrize(
    "helpers, expression, listed", list(SHAPES.values()), ids=list(SHAPES)
)
def test_readable_helper_shapes_keep_request_data_unless_proved(
    tmp_path, monkeypatch, helpers, expression, listed
):
    source = (
        "from flask import Flask, request\n"
        + helpers
        + "app = Flask(__name__)\n"
        + "@app.route('/')\n"
        + "def page():\n"
        + f"    return {expression}\n"
    )
    result = _analyze(tmp_path, monkeypatch, source)
    expected = []
    if listed:
        expected = [_line(source, f"    return {expression}")]
    assert _listed_lines(result, symbol="page") == expected
    assert _reported_lines(result, symbol="page") == expected


def test_nested_functions_read_the_enclosing_request_data(tmp_path, monkeypatch):
    source = (
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/')\n"
        "def page():\n"
        "    q = request.args['q']\n"
        "    def inner():\n"
        "        return q\n"
        "    def same(v):\n"
        "        return v\n"
        "    return 'Hi ' + inner() + same(q)\n"
    )
    result = _analyze(tmp_path, monkeypatch, source)
    assert _listed_lines(result, symbol="page") == [_line(source, "    return 'Hi '")]


ENCODER = (
    "def encode(text):\n"
    "    out = ''\n"
    "    for char in text:\n"
    "        if char.isalnum():\n"
    "            out += char\n"
    "        else:\n"
    "            out += '&#' + str(ord(char)) + ';'\n"
    "    return out\n"
)
TABLE_ENCODER = (
    "SAFE_PUNCTUATION = (',', '.', '-', ' ')\n"
    "ENTITIES = {34: 'quot', 38: 'amp', 60: 'lt', 62: 'gt'}\n"
    "def encode(text):\n"
    "    out = ''\n"
    "    for char in text:\n"
    "        if char.isalnum() or char in SAFE_PUNCTUATION:\n"
    "            out += char\n"
    "        elif ord(char) in ENTITIES:\n"
    "            out += f'&{ENTITIES[ord(char)]};'\n"
    "        else:\n"
    "            out += f'&#x{hex(ord(char))[2:]};'\n"
    "    return out\n"
)
ENCODERS = {
    "allowlist encoder loop": (ENCODER, "'Hi ' + encode(request.args['q'])", (), False),
    "encoder with a punctuation tuple and an entity table": (
        TABLE_ENCODER,
        "'Hi ' + encode(request.args['q'])",
        (),
        "table",
    ),
    "encoder in another module": (
        "from myproject.codec import encode\n",
        "'Hi ' + encode(request.args['q'])",
        (("myproject/codec.py", TABLE_ENCODER),),
        "table",
    ),
    "join of a generator": (
        "def encode(text):\n"
        "    return ''.join(c if c.isalnum() else f'&#{ord(c)};' for c in text)\n",
        "'Hi ' + encode(request.args['q'])",
        (),
        False,
    ),
    "join of a filtered comprehension": (
        "def encode(text):\n    return ''.join([c for c in text if c.isdigit()])\n",
        "'Hi ' + encode(request.args['q'])",
        (),
        False,
    ),
    "list accumulator": (
        "def encode(text):\n"
        "    parts = []\n"
        "    for char in text:\n"
        "        if char.isalpha():\n"
        "            parts.append(char)\n"
        "        else:\n"
        "            parts.append('&#{};'.format(ord(char)))\n"
        "    return ''.join(parts)\n",
        "'Hi ' + encode(request.args['q'])",
        (),
        False,
    ),
    "alias of the encoder": None,
    "correct replace chain": None,
    "raw character appended in the else branch": (
        ENCODER.replace("out += '&#' + str(ord(char)) + ';'", "out += char"),
        "'Hi ' + encode(request.args['q'])",
        (),
        True,
    ),
    "punctuation list containing <": (
        TABLE_ENCODER.replace("(',', '.', '-', ' ')", "(',', '.', '<', ' ')"),
        "'Hi ' + encode(request.args['q'])",
        (),
        True,
    ),
    "guard that does not guard": (
        "FLAG = True\n"
        + ENCODER.replace("if char.isalnum():", "if char.isalnum() or FLAG:"),
        "'Hi ' + encode(request.args['q'])",
        (),
        True,
    ),
    "entity branch embedding the raw character": (
        TABLE_ENCODER.replace("f'&#x{hex(ord(char))[2:]};'", "f'&{char};'"),
        "'Hi ' + encode(request.args['q'])",
        (),
        True,
    ),
    "returning the input instead of the accumulator": (
        ENCODER.replace("    return out\n", "    return text\n"),
        "'Hi ' + encode(request.args['q'])",
        (),
        True,
    ),
    "replace chain skipping <": (
        "",
        "'Hi ' + request.args['q'].replace('&', '&amp;').replace('>', '&gt;')",
        (),
        True,
    ),
    "replace chain with a non-entity for <": (
        "",
        "'Hi ' + request.args['q'].replace('&', '&amp;').replace('<', '').replace('>', '&gt;')",
        (),
        True,
    ),
    "replace chain with & after <": (
        "",
        "'Hi ' + request.args['q'].replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')",
        (),
        True,
    ),
    "replace chain on one variable, another returned": None,
    "alias of the encoder applied to something else": None,
    "wrapper calling the encoder with a different argument": (
        ENCODER + "def show(value, label):\n    return encode(label) + value\n",
        "'Hi ' + show(request.args['q'], 'x')",
        (),
        True,
    ),
}
ENCODERS["alias of the encoder"] = (
    ENCODER + "def aliased_ok(value):\n    esc = encode\n    return esc(value)\n",
    "'Hi ' + aliased_ok(request.args['q'])",
    (),
    False,
)
ENCODERS["correct replace chain"] = (
    "def clean(value):\n"
    "    value = value.replace('&', '&amp;')\n"
    "    value = value.replace('<', '&lt;')\n"
    "    value = value.replace('>', '&gt;')\n"
    "    return value\n",
    "'Hi ' + clean(request.args['q'])",
    (),
    False,
)
ENCODERS["replace chain on one variable, another returned"] = (
    "def other(value):\n"
    "    safe = value.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')\n"
    "    return value\n",
    "'Hi ' + other(request.args['q'])",
    (),
    True,
)
ENCODERS["alias of the encoder applied to something else"] = (
    ENCODER
    + "def aliased(value):\n    esc = encode\n    esc('fixed')\n    return value\n",
    "'Hi ' + aliased(request.args['q'])",
    (),
    True,
)


@pytest.mark.parametrize(
    "helpers, expression, modules, listed", list(ENCODERS.values()), ids=list(ENCODERS)
)
def test_hand_written_encoders_are_proved_from_their_structure(
    tmp_path, monkeypatch, helpers, expression, modules, listed
):
    source = (
        "from flask import Flask, request\n"
        + helpers
        + "app = Flask(__name__)\n"
        + "@app.route('/')\n"
        + "def page():\n"
        + f"    return {expression}\n"
    )
    result = _analyze(tmp_path, monkeypatch, source, modules=[*PROJECT, *modules])
    outcome = {True: "listed", False: "quiet"}.get(listed, listed)
    _assert_outcome(result, source, f"    return {expression}", outcome)


HEX_ENCODER = (
    "def encode(text):\n"
    "    out = ''\n"
    "    for char in text:\n"
    "        if char.isalnum():\n"
    "            out += char\n"
    "        else:\n"
    "            out += f'&#x{ord(char):04x};'\n"
    "    return out\n"
)


def _encoder(body_before="", in_loop="", piece="'&#' + str(ord(char)) + ';'", tail=""):
    return (
        "def encode(text):\n"
        "    out = ''\n"
        + body_before
        + "    for char in text:\n"
        + in_loop
        + "        if char.isalnum():\n"
        + "            out += char\n"
        + "        else:\n"
        + f"            out += {piece}\n"
        + tail
        + "    return out\n"
    )


TIGHT = {
    "four-digit hex spec": (HEX_ENCODER, (), False),
    "table read by another module": (
        TABLE_ENCODER,
        (("myproject/report.py", "import app\nFIRST = app.ENTITIES[60]\n"),),
        "table",
    ),
    "nested function writes the accumulator": (
        "def encode(text):\n"
        "    out = ''\n"
        "    def inject():\n"
        "        nonlocal out\n"
        "        out += text\n"
        "    for c in text:\n"
        "        if c.isalnum():\n"
        "            out += c\n"
        "        else:\n"
        "            out += '&#' + str(ord(c)) + ';'\n"
        "    inject()\n"
        "    return out\n",
        (),
        True,
    ),
    "named allowlist mutated before use": (
        "SAFE = ['a', 'b']\n"
        "def encode(text):\n"
        "    out = ''\n"
        "    SAFE[0] = '<'\n"
        "    SAFE[1] = '>'\n"
        "    for c in text:\n"
        "        if c.isalnum() or c in SAFE:\n"
        "            out += c\n"
        "        else:\n"
        "            out += '&#' + str(ord(c)) + ';'\n"
        "    return out\n",
        (),
        True,
    ),
    "entity table mutated with request data": (
        "TABLE = {60: 'lt', 62: 'gt'}\n"
        "def encode(text):\n"
        "    out = ''\n"
        "    TABLE[60] = text\n"
        "    for c in text:\n"
        "        out += f'&{TABLE[ord(c)]};'\n"
        "    return out\n",
        (),
        True,
    ),
    "format spec c through format()": (
        _encoder(piece="'&' + format(ord(char), 'c') + ';'"),
        (),
        True,
    ),
    "format spec c in an f-string": (_encoder(piece="f'&{ord(char):c};'"), (), True),
    "format spec c in str.format": (
        _encoder(piece="'&#{:c};'.format(ord(char))"),
        (),
        True,
    ),
    "computed format spec": (
        "WIDTH = 4\n" + _encoder(piece="f'&#{ord(char):{WIDTH}};'"),
        (),
        True,
    ),
    "conversion on ord": (_encoder(piece="f'&{ord(char)!r};'"), (), True),
    "global statement": (
        "out = ''\n"
        + _encoder(body_before="    global out\n").replace("    out = ''\n", "", 1),
        (),
        True,
    ),
    "exec in the helper": (_encoder(body_before="    exec('pass')\n"), (), True),
    "accumulator reassigned": (_encoder(tail="    out = out + text\n"), (), True),
    "accumulator walrus": (_encoder(tail="    (out := text)\n"), (), True),
    "accumulator passed to a call": (_encoder(tail="    print(out)\n"), (), True),
    "accumulator aliased": (_encoder(tail="    copy = out\n"), (), True),
    "try/finally returning something else": (
        "def encode(text):\n"
        "    out = ''\n"
        "    try:\n"
        "        for char in text:\n"
        "            if char.isalnum():\n"
        "                out += char\n"
        "    finally:\n"
        "        return text\n",
        (),
        True,
    ),
    "loop variable rebound": (_encoder(in_loop="        char = text\n"), (), True),
    "loop variable bound by except": (
        _encoder(
            in_loop="        try:\n            pass\n        except ValueError as char:\n            pass\n"
        ),
        (),
        True,
    ),
    "loop variable rebound by a nested loop": (
        _encoder(in_loop="        for char in text:\n            pass\n"),
        (),
        True,
    ),
    "loop source rebound": (
        _encoder(body_before="    text = text + '<b>'\n"),
        (),
        True,
    ),
    "module allowlist mutated by a method": (
        "SAFE = [',']\nSAFE.append('<')\n"
        + TABLE_ENCODER.split("ENTITIES = ", 1)[0].replace(
            "SAFE_PUNCTUATION = (',', '.', '-', ' ')\n", ""
        )
        + "def encode(text):\n"
        "    out = ''\n"
        "    for char in text:\n"
        "        if char in SAFE:\n"
        "            out += char\n"
        "    return out\n",
        (),
        True,
    ),
    "module allowlist passed to a call": (
        "SAFE = [',']\nregister(SAFE)\n"
        "def encode(text):\n"
        "    out = ''\n"
        "    for char in text:\n"
        "        if char in SAFE:\n"
        "            out += char\n"
        "    return out\n",
        (),
        True,
    ),
    "module allowlist aliased": (
        "SAFE = [',']\nOTHER = SAFE\n"
        "def encode(text):\n"
        "    out = ''\n"
        "    for char in text:\n"
        "        if char in SAFE:\n"
        "            out += char\n"
        "    return out\n",
        (),
        True,
    ),
    "global table rebound elsewhere in the module": (
        TABLE_ENCODER + "def reset():\n    global ENTITIES\n    ENTITIES = {60: '<'}\n",
        (),
        True,
    ),
    "table imported and written by another module": (
        TABLE_ENCODER,
        (("myproject/patch.py", "from app import ENTITIES\nENTITIES[60] = '<'\n"),),
        "table",
    ),
    "table written through the module by another module": (
        TABLE_ENCODER,
        (("myproject/patch.py", "import app\napp.ENTITIES[60] = '<'\n"),),
        "table",
    ),
}


@pytest.mark.parametrize(
    "helpers, modules, listed", list(TIGHT.values()), ids=list(TIGHT)
)
def test_encoder_proof_rejects_every_way_around_it(
    tmp_path, monkeypatch, helpers, modules, listed
):
    source = (
        "from flask import Flask, request\n"
        + helpers
        + "app = Flask(__name__)\n"
        + "@app.route('/')\n"
        + "def page():\n"
        + "    return 'Hi ' + encode(request.args['q'])\n"
    )
    result = _analyze(tmp_path, monkeypatch, source, modules=[*PROJECT, *modules])
    outcome = {True: "listed", False: "quiet"}.get(listed, listed)
    _assert_outcome(result, source, "    return 'Hi '", outcome)


def _assert_outcome(result, source, line_text, outcome):
    line = _line(source, line_text)
    rows = [
        f
        for f in result.get("danger", [])
        if f["rule_id"] == "SKY-D228" and f["symbol"] == "page"
    ]
    if outcome == "quiet":
        assert rows == []
    elif outcome == "listed":
        assert [(f["line"], f["listing"]["listed"]) for f in rows] == [(line, True)]
    else:
        assert [
            (f["line"], f["listing"]["listed"], f["low_risk_context"]["reason"])
            for f in rows
        ] == [(line, False, "module-table-encoder")]
        passed, _ = check_gate(result, {"gate": {"max_high": 0}})
        assert passed is False


SAFE_LIST_ENCODER = (
    "SAFE = [',', '.']\n"
    "def encode(text):\n"
    "    out = ''\n"
    "    for char in text:\n"
    "        if char.isalnum() or char in SAFE:\n"
    "            out += char\n"
    "        else:\n"
    "            out += '&#' + str(ord(char)) + ';'\n"
    "    return out\n"
)
TIERS = {
    "inline allowlist": (
        SAFE_LIST_ENCODER.replace("char in SAFE", "char in (',', '.')").replace(
            "SAFE = [',', '.']\n", ""
        ),
        (),
        "quiet",
    ),
    "local allowlist list": (
        SAFE_LIST_ENCODER.replace("SAFE = [',', '.']\n", "").replace(
            "    out = ''\n", "    SAFE = [',', '.']\n    out = ''\n", 1
        ),
        (),
        "quiet",
    ),
    "module tuple allowlist with a local table": (
        "SAFE = (',', '.')\n"
        "def encode(text):\n"
        "    names = {60: 'lt', 62: 'gt'}\n"
        "    out = ''\n"
        "    for char in text:\n"
        "        if char in SAFE:\n"
        "            out += char\n"
        "        elif ord(char) in names:\n"
        "            out += f'&{names[ord(char)]};'\n"
        "        else:\n"
        "            out += f'&#{ord(char)};'\n"
        "    return out\n",
        (),
        "quiet",
    ),
    "module frozenset allowlist": (
        SAFE_LIST_ENCODER.replace("SAFE = [',', '.']", "SAFE = frozenset({',', '.'})"),
        (),
        "quiet",
    ),
    "module list allowlist": (SAFE_LIST_ENCODER, (), "table"),
    "module dict entity table": (TABLE_ENCODER, (), "table"),
    "another module rewrites the list through getattr": (
        SAFE_LIST_ENCODER,
        (("myproject/patch.py", "import app\ngetattr(app, 'SAFE')[:] = ['<', '>']\n"),),
        "table",
    ),
    "another module rewrites the list through __dict__": (
        SAFE_LIST_ENCODER,
        (("myproject/patch.py", "import app\napp.__dict__['SAFE'][:] = ['<', '>']\n"),),
        "table",
    ),
    "another module rewrites the list directly": (
        SAFE_LIST_ENCODER,
        (("myproject/patch.py", "import app\napp.SAFE[:] = ['<', '>']\n"),),
        "table",
    ),
    "owner module rewrites the list through globals()": (
        SAFE_LIST_ENCODER + "globals()['SAFE'][:] = ['<', '>']\n",
        (),
        "listed",
    ),
    "owner module reads its namespace with vars()": (
        SAFE_LIST_ENCODER + "vars()['SAFE'].append('<')\n",
        (),
        "listed",
    ),
    "owner module uses getattr anywhere": (
        SAFE_LIST_ENCODER.replace("SAFE = [',', '.']", "SAFE = (',', '.')")
        + "def lookup(name):\n    return getattr(name, 'x')\n",
        (),
        "listed",
    ),
}


@pytest.mark.parametrize(
    "helpers, modules, outcome", list(TIERS.values()), ids=list(TIERS)
)
def test_named_allowlists_and_tables_by_proof_tier(
    tmp_path, monkeypatch, helpers, modules, outcome
):
    source = (
        "from flask import Flask, request\n"
        + helpers
        + "app = Flask(__name__)\n"
        + "@app.route('/')\n"
        + "def page():\n"
        + "    return 'Hi ' + encode(request.args['q'])\n"
    )
    result = _analyze(tmp_path, monkeypatch, source, modules=[*PROJECT, *modules])
    _assert_outcome(result, source, "    return 'Hi '", outcome)


class _NoWalk:
    def __init__(self, real):
        self._real = real

    def walk(self, *args, **kwargs):
        raise AssertionError("response_xss walked the disk")

    def __getattr__(self, name):
        return getattr(self._real, name)


def test_only_files_the_view_imports_are_read(tmp_path, monkeypatch):
    from skylos.rules.danger.danger_web import response_xss

    opened = []
    parse = response_xss._parse_project_module

    def recording(path, mtime_ns, size):
        opened.append(path)
        return parse.__wrapped__(path, mtime_ns, size)

    monkeypatch.setattr(response_xss, "os", _NoWalk(response_xss.os))
    monkeypatch.setattr(response_xss, "_parse_project_module", recording)
    modules = [
        *PROJECT,
        ("myproject/codec.py", TABLE_ENCODER),
        ("myproject/unrelated.py", "ENTITIES = {60: '<'}\nSAFE_PUNCTUATION = ['<']\n"),
    ]
    source = (
        "from flask import Flask, request\n"
        "from myproject.codec import encode\n"
        "app = Flask(__name__)\n"
        "@app.route('/')\n"
        "def page():\n"
        "    return 'Hi ' + encode(request.args['q'])\n"
    )
    result = _analyze(tmp_path, monkeypatch, source, modules=modules)
    _assert_outcome(result, source, "    return 'Hi '", "table")
    assert {path.rsplit("/", 2)[-1] for path in opened} == {"codec.py"}


SAFE_TUPLE_ENCODER = SAFE_LIST_ENCODER.replace("SAFE = [',', '.']", "SAFE = (',', '.')")
IMPORTED_ENCODER = SAFE_TUPLE_ENCODER.replace(
    "SAFE = (',', '.')\n", "from myproject.consts import SAFE\n"
)
DYNAMIC = {
    "sys imported under another name": (
        "import sys as runtime\n"
        + SAFE_TUPLE_ENCODER
        + "runtime.modules[__name__].SAFE = ('<', '>')\n",
        (),
        "listed",
    ),
    "modules imported from sys under another name": (
        "from sys import modules as registry\n"
        + SAFE_TUPLE_ENCODER
        + "registry[__name__].SAFE = ('<', '>')\n",
        (),
        "listed",
    ),
    "globals aliased": (
        SAFE_TUPLE_ENCODER + "g = globals\ng()['SAFE'] = ('<', '>')\n",
        (),
        "listed",
    ),
    "function __globals__": (
        SAFE_TUPLE_ENCODER + "encode.__globals__['SAFE'] = ('<', '>')\n",
        (),
        "listed",
    ),
    "frame globals": (
        "import inspect\n"
        + SAFE_TUPLE_ENCODER
        + "inspect.currentframe().f_globals['SAFE'] = ('<', '>')\n",
        (),
        "listed",
    ),
    "builtins under another name": (
        "import builtins as b\n"
        + SAFE_TUPLE_ENCODER
        + "b.globals()['SAFE'] = ('<',)\n",
        (),
        "listed",
    ),
    "star import in the owner module": (
        "from os.path import *\n" + SAFE_TUPLE_ENCODER,
        (),
        "listed",
    ),
    "imported allowlist whose owner uses sys.modules": (
        IMPORTED_ENCODER,
        (
            (
                "myproject/consts.py",
                "import sys\nSAFE = (',', '.')\nsys.modules[__name__].SAFE = ('<',)\n",
            ),
        ),
        "listed",
    ),
    "imported allowlist from an unresolved owner": (
        SAFE_TUPLE_ENCODER.replace(
            "SAFE = (',', '.')\n", "from elsewhere import SAFE\n"
        ),
        (),
        "listed",
    ),
    "imported allowlist from a clean owner": (
        IMPORTED_ENCODER,
        (("myproject/consts.py", "SAFE = (',', '.')\n"),),
        "quiet",
    ),
    "imported mutable allowlist from a clean owner": (
        IMPORTED_ENCODER,
        (("myproject/consts.py", "SAFE = [',', '.']\n"),),
        "table",
    ),
    "sys used only for argv and stdout": (
        "import sys\n"
        + SAFE_TUPLE_ENCODER
        + "DEBUG = '--debug' in sys.argv\nOUT = sys.stdout\n",
        (),
        "quiet",
    ),
}


@pytest.mark.parametrize(
    "helpers, modules, outcome", list(DYNAMIC.values()), ids=list(DYNAMIC)
)
def test_owner_module_dynamic_access_rejects_the_encoder_proof(
    tmp_path, monkeypatch, helpers, modules, outcome
):
    source = (
        "from flask import Flask, request\n"
        + helpers
        + "app = Flask(__name__)\n"
        + "@app.route('/')\n"
        + "def page():\n"
        + "    return 'Hi ' + encode(request.args['q'])\n"
    )
    result = _analyze(tmp_path, monkeypatch, source, modules=[*PROJECT, *modules])
    _assert_outcome(result, source, "    return 'Hi '", outcome)


ATTRGETTER_WRITE = (
    "import sys\n"
    "from operator import attrgetter\n"
    "attrgetter('modules')(sys)[__name__].SAFE = ('<', '>')\n"
)
NAMED_WRITES = {
    "attrgetter write in the view module": (
        SAFE_TUPLE_ENCODER + ATTRGETTER_WRITE,
        (),
        "listed",
    ),
    "attrgetter write in an imported encoder module": (
        "from myproject.codec import encode\n",
        (("myproject/codec.py", SAFE_TUPLE_ENCODER + ATTRGETTER_WRITE),),
        "listed",
    ),
    "attrgetter write in the owner of an imported allowlist": (
        IMPORTED_ENCODER,
        (("myproject/consts.py", "SAFE = (',', '.')\n" + ATTRGETTER_WRITE),),
        "listed",
    ),
    "update with a keyword of the name": (
        SAFE_TUPLE_ENCODER
        + "from operator import attrgetter\n"
        + "attrgetter('__globals__')(encode).update(SAFE=('<',))\n",
        (),
        "listed",
    ),
    "subscript store keyed by the name": (
        SAFE_TUPLE_ENCODER
        + "from operator import attrgetter\n"
        + "holder = attrgetter('__globals__')(encode)\n"
        + "holder['SAFE'] = ('<',)\n",
        (),
        "listed",
    ),
    "the name as a string passed to a call": (
        SAFE_TUPLE_ENCODER + "install('SAFE', ('<',))\n",
        (),
        "listed",
    ),
    "unrelated attribute and string in the module": (
        SAFE_TUPLE_ENCODER
        + "class Config:\n    mode = 'lax'\n"
        + "config = Config()\nconfig.mode = 'strict'\nLABEL = 'SAFE_MODE'\n",
        (),
        "quiet",
    ),
}


@pytest.mark.parametrize(
    "helpers, modules, outcome", list(NAMED_WRITES.values()), ids=list(NAMED_WRITES)
)
def test_tables_written_by_name_lose_the_encoder_proof(
    tmp_path, monkeypatch, helpers, modules, outcome
):
    source = (
        "from flask import Flask, request\n"
        + helpers
        + "app = Flask(__name__)\n"
        + "@app.route('/')\n"
        + "def page():\n"
        + "    return 'Hi ' + encode(request.args['q'])\n"
    )
    result = _analyze(tmp_path, monkeypatch, source, modules=[*PROJECT, *modules])
    _assert_outcome(result, source, "    return 'Hi '", outcome)
