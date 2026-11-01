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
    "allowlist escaper loop": (
        "    return 'Results ' + encode(request.args['q'])\n"
        "def encode(text):\n"
        "    out = ''\n"
        "    for char in text:\n"
        "        if char.isalnum():\n"
        "            out += char\n"
        "        else:\n"
        "            out += '&#' + str(ord(char)) + ';'\n"
        "    return out\n"
    ),
    "allowlist escaper comprehension": (
        "    return 'Results ' + encode(request.args['q'])\n"
        "def encode(text):\n"
        "    return ''.join(c for c in text if c.isalnum())\n"
    ),
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
    "hand-written replace of markup": (
        "    q = request.args['q'].replace('&', '&amp;').replace('<', '&lt;')\n"
        "    return 'Results ' + q\n"
    ),
}


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
    "allowlist escaper loop": (
        "from myproject.utils import encode\n",
        "encode(request.args['q'])",
        "def encode(text):\n"
        "    out = ''\n"
        "    for char in text:\n"
        "        if char.isalnum():\n"
        "            out += char\n"
        "        else:\n"
        "            out += '&#' + str(ord(char)) + ';'\n"
        "    return out\n",
        False,
    ),
    "helper calling another helper": (
        "from myproject.utils import outer\n",
        "outer(request.args['q'])",
        "def inner(value):\n    return value\ndef outer(value):\n    return inner(value)\n",
        False,
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
    modules = [*PROJECT, ("myproject/utils.py", helper)]
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
