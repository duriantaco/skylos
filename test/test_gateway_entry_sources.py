"""A raw WSGI or ASGI callable receives request data from the server."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from test.fixture_paths import write_fixture

HEAD = "import MySQLdb\n\n\ndef connect():\n    return MySQLdb.connect()\n\n\n"

WSGI_FUNCTION = HEAD + (
    "def app(environ, start_response):\n"
    "    table = environ['PATH_INFO']\n"
    "    cursor = connect().cursor()\n"
    "    cursor.execute('DESCRIBE ' + table)\n"
    "    start_response('200 OK', [])\n"
    "    return [b'']\n"
)
WSGI_CLASS = HEAD + (
    "class App:\n"
    "    def __call__(self, environ, start_response):\n"
    "        table = environ['PATH_INFO']\n"
    "        cursor = connect().cursor()\n"
    "        cursor.execute('DESCRIBE ' + table)\n"
    "        start_response('200 OK', [])\n"
    "        return [b'']\n"
)
WSGI_HELPER = HEAD + (
    "def describe(table):\n"
    "    cursor = connect().cursor()\n"
    "    cursor.execute('DESCRIBE ' + table)\n\n\n"
    "def app(environ, start_response):\n"
    "    describe(environ['PATH_INFO'])\n"
    "    start_response('200 OK', [])\n"
    "    return [b'']\n"
)
WSGI_PROVIDER = HEAD + (
    "class Base:\n"
    "    def describe(self, table):\n"
    "        raise NotImplementedError\n\n\n"
    "class Provider(Base):\n"
    "    def describe(self, table):\n"
    "        cursor = connect().cursor()\n"
    "        cursor.execute('DESCRIBE ' + table)\n\n\n"
    "class App:\n"
    "    def __init__(self, provider):\n"
    "        self._provider = provider\n\n"
    "    def __call__(self, environ, start_response):\n"
    "        self._provider.describe(environ['PATH_INFO'])\n"
    "        start_response('200 OK', [])\n"
    "        return [b'']\n"
)
ASGI_FUNCTION = HEAD + (
    "async def app(scope, receive, send):\n"
    "    table = scope['path']\n"
    "    cursor = connect().cursor()\n"
    "    cursor.execute('DESCRIBE ' + table)\n"
    "    await send({'type': 'http.response.start', 'status': 200})\n"
)
ASGI_CLASS = HEAD + (
    "class App:\n"
    "    async def __call__(self, scope, receive, send):\n"
    "        message = await receive()\n"
    "        cursor = connect().cursor()\n"
    "        cursor.execute('DESCRIBE ' + message['body'].decode())\n"
    "        await send({'type': 'http.response.start', 'status': 200})\n"
)


def _report(root, source, name="app.py"):
    (root / ".git").mkdir()
    write_fixture(root, "pyproject.toml", '[project]\nname = "proj"\n')
    write_fixture(root, name, source)
    return json.loads(
        analyze(
            str(root),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
        )
    )


def _sql(report, section="danger"):
    return [row for row in report.get(section, []) if row.get("rule_id") == "SKY-D211"]


@pytest.mark.parametrize(
    ("source", "line"),
    [
        (WSGI_FUNCTION, 11),
        (WSGI_CLASS, 12),
        (WSGI_HELPER, 10),
        (WSGI_PROVIDER, 16),
        (ASGI_FUNCTION, 11),
        (ASGI_CLASS, 12),
    ],
    ids=[
        "wsgi-function",
        "wsgi-class",
        "wsgi-helper",
        "wsgi-provider",
        "asgi-function",
        "asgi-class",
    ],
)
def test_gateway_request_data_reaching_sql_text_is_reported(
    tmp_path, monkeypatch, source, line
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    report = _report(tmp_path.resolve(), source)

    rows = _sql(report)
    assert [(int(row["line"]), row["severity"]) for row in rows] == [(line, "CRITICAL")]
    assert rows[0]["metadata"]["source_status"] == "untrusted"
    assert _sql(report, "suppressed") == []
    assert (
        check_gate(report, {"gate": {"max_critical": 0, "max_high": 1000}})[0] is False
    )


ONE_NAME_ONLY = HEAD + (
    "def lookup(environ):\n"
    "    cursor = connect().cursor()\n"
    "    cursor.execute('DESCRIBE ' + environ['TABLE'])\n"
)
EXTRA_PARAMETER = HEAD + (
    "def lookup(environ, start_response, table):\n"
    "    cursor = connect().cursor()\n"
    "    cursor.execute('DESCRIBE ' + table)\n"
)
OTHER_PARAMETER = HEAD + (
    "def app(environ, start_response):\n"
    "    cursor = connect().cursor()\n"
    "    cursor.execute('DESCRIBE ' + start_response.table)\n"
    "    return [b'']\n"
)
ASGI_TWO_NAMES = HEAD + (
    "def push(scope, send):\n"
    "    cursor = connect().cursor()\n"
    "    cursor.execute('DESCRIBE ' + scope['table'])\n"
)
RENAMED = HEAD + (
    "def app(settings, callback):\n"
    "    cursor = connect().cursor()\n"
    "    cursor.execute('DESCRIBE ' + settings['table'])\n"
)


@pytest.mark.parametrize(
    "source",
    [ONE_NAME_ONLY, EXTRA_PARAMETER, OTHER_PARAMETER, ASGI_TWO_NAMES, RENAMED],
    ids=["one-name", "extra-parameter", "other-parameter", "asgi-two-names", "renamed"],
)
def test_functions_that_are_not_gateway_callables_keep_an_unresolved_origin(
    tmp_path, monkeypatch, source
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    report = _report(tmp_path.resolve(), source)

    assert _sql(report) == []
    hidden = _sql(report, "suppressed")
    assert len(hidden) == 1
    assert hidden[0]["metadata"]["sql_provenance"]["status"] == "unknown"


def test_bound_parameters_in_a_gateway_callable_stay_quiet(tmp_path, monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    source = HEAD + (
        "def app(environ, start_response):\n"
        "    cursor = connect().cursor()\n"
        "    cursor.execute('SELECT * FROM t WHERE name = %s', (environ['PATH_INFO'],))\n"
        "    start_response('200 OK', [])\n"
        "    return [b'']\n"
    )
    report = _report(tmp_path.resolve(), source)

    assert _sql(report) == []
    assert _sql(report, "suppressed") == []


def test_gateway_request_data_reaching_a_file_path_is_reported(tmp_path, monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    source = (
        "import os\n\n\n"
        "def app(environ, start_response):\n"
        "    with open(os.path.join('/srv/files', environ['PATH_INFO'])) as handle:\n"
        "        body = handle.read()\n"
        "    start_response('200 OK', [])\n"
        "    return [body.encode()]\n"
    )
    report = _report(tmp_path.resolve(), source)

    reported = {(row["rule_id"], int(row["line"])) for row in report.get("danger", [])}
    assert ("SKY-D215", 5) in reported


def _provider_app(method, extra=""):
    return (
        HEAD
        + extra
        + (
            "class Provider:\n"
            f"    def {method}(self, table):\n"
            "        cursor = connect().cursor()\n"
            "        cursor.execute('DESCRIBE ' + table)\n\n\n"
            "class App:\n"
            "    def __init__(self, provider):\n"
            "        self._provider = provider\n\n"
            "    def __call__(self, environ, start_response):\n"
            f"        self._provider.{method}(environ['PATH_INFO'])\n"
            "        start_response('200 OK', [])\n"
            "        return [b'']\n"
        )
    )


SECOND_FAMILY = (
    "class Printer:\n    def describe(self, table):\n        return str(table)\n\n\n"
)
MODULE_FUNCTION = "def describe(table):\n    return str(table)\n\n\n"
EXTERNAL_USE = (
    "import requests\n\n\ndef ping(url):\n    return requests.describe(url)\n\n\n"
)


@pytest.mark.parametrize(
    ("method", "extra"),
    [
        ("get", ""),
        ("update", ""),
        ("describe", SECOND_FAMILY),
        ("describe", MODULE_FUNCTION),
        ("describe", EXTERNAL_USE),
    ],
    ids=[
        "dict-method-name",
        "set-method-name",
        "second-family",
        "module-function",
        "external-use",
    ],
)
def test_unresolved_receiver_with_an_ambiguous_method_name_stays_unresolved(
    tmp_path, monkeypatch, method, extra
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    report = _report(tmp_path.resolve(), _provider_app(method, extra))

    assert _sql(report) == []
    hidden = _sql(report, "suppressed")
    assert len(hidden) == 1
    assert hidden[0]["metadata"]["sql_provenance"]["status"] == "unknown"


def test_unresolved_receiver_with_a_method_of_one_hierarchy_is_reported(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    report = _report(tmp_path.resolve(), _provider_app("describe"))

    assert [(int(row["line"]), row["severity"]) for row in _sql(report)] == [
        (11, "CRITICAL")
    ]


def test_gateway_callable_in_a_test_module_is_not_a_request_source(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    source = WSGI_FUNCTION + (
        "\n\ndef test_app():\n"
        "    assert app({'PATH_INFO': 't'}, lambda *args: None) == [b'']\n"
    )
    report = _report(tmp_path.resolve(), source, name="tests/test_app.py")

    assert _sql(report) == []


SERVER_OBJECT = (
    "import os\n\n\n"
    "class Store:\n"
    "    def locate(self, name):\n"
    "        return os.path.join('/srv/files', os.path.basename(name))\n\n\n"
    "def app(environ, start_response):\n"
    "    store = environ['app.store']\n"
    "    with open(store.locate('index.html')) as handle:\n"
    "        body = handle.read()\n"
    "    start_response('200 OK', [])\n"
    "    return [body.encode()]\n"
)
ASGI_SERVER_OBJECT = (
    "async def app(scope, receive, send):\n"
    "    with open(scope['state']['index']) as handle:\n"
    "        body = handle.read()\n"
    "    await send({'type': 'http.response.body', 'body': body.encode()})\n"
)


@pytest.mark.parametrize(
    "source", [SERVER_OBJECT, ASGI_SERVER_OBJECT], ids=["wsgi", "asgi"]
)
def test_objects_the_server_stores_in_the_gateway_mapping_are_not_client_data(
    tmp_path, monkeypatch, source
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    report = _report(tmp_path.resolve(), source)

    assert [
        row
        for row in report.get("danger", [])
        if row["rule_id"] in {"SKY-D215", "SKY-D324", "SKY-D325"}
    ] == []


@pytest.mark.parametrize(
    "read",
    [
        "environ['QUERY_STRING']",
        "environ.get('HTTP_X_TABLE', '')",
        "environ['wsgi.input'].read().decode()",
        "environ['PATH_INFO'].split('/')[1]",
    ],
)
def test_client_filled_gateway_keys_stay_request_data(tmp_path, monkeypatch, read):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    source = HEAD + (
        "def app(environ, start_response):\n"
        "    cursor = connect().cursor()\n"
        f"    cursor.execute('DESCRIBE ' + {read})\n"
        "    start_response('200 OK', [])\n"
        "    return [b'']\n"
    )
    report = _report(tmp_path.resolve(), source)

    assert [(int(row["line"]), row["severity"]) for row in _sql(report)] == [
        (10, "CRITICAL")
    ]
