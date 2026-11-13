"""Concrete missing security checks and their safe lookalikes."""

import pytest

from skylos.rules.danger.danger import scan_ctx


def scan(tmp_path, code):
    path = tmp_path / "server.py"
    path.write_text(code)
    return scan_ctx(tmp_path, [path])


@pytest.mark.parametrize(
    "constructor",
    ["Environment()", "Environment(autoescape=False)", "Environment(loader=loader)"],
)
def test_jinja_environment_without_autoescape(tmp_path, constructor):
    findings = scan(tmp_path, "from jinja2 import Environment\n" + constructor + "\n")
    assert [
        (f["rule_id"], f["line"]) for f in findings if f["rule_id"] == "SKY-D355"
    ] == [("SKY-D355", 2)]


@pytest.mark.parametrize(
    "code",
    [
        "from jinja2 import Environment\nEnvironment(autoescape=True)",
        "from jinja2 import Environment, select_autoescape\nEnvironment(autoescape=select_autoescape())",
        "from jinja2 import Environment\nEnvironment(**options)",
        "from jinja2 import Environment\nEnvironment(*options)",
        "def Environment(): pass\nEnvironment()",
        "from jinja2 import Environment\ndef build(Environment):\n    return Environment()",
        "from jinja2 import Environment\nEnvironment = custom\nEnvironment()",
    ],
)
def test_jinja_environment_safe_and_unknown_controls(tmp_path, code):
    assert not [f for f in scan(tmp_path, code) if f["rule_id"] == "SKY-D355"]


@pytest.mark.parametrize(
    "code",
    [
        "import requests\nrequests.get('http://api.example.com/data')",
        "from httpx import post as send\nsend('http://api.example.com/data')",
        "from urllib.request import urlopen\nurlopen('http://api.example.com/data')",
        "import requests\nurl = 'http://api.example.com/data'\nrequests.get(url)",
    ],
)
def test_cleartext_outbound_http(tmp_path, code):
    assert len([f for f in scan(tmp_path, code) if f["rule_id"] == "SKY-D356"]) == 1


@pytest.mark.parametrize(
    "code",
    [
        "import requests\nrequests.get('https://api.example.com/data')",
        "import requests\nrequests.get('http://127.0.0.1:8000/data')",
        "import requests\nrequests.get('http://localhost/data')",
        "class requests:\n    def get(self, value): pass\nrequests.get('http://api.example.com')",
        "import requests\ndef call(requests):\n    requests.get('http://api.example.com')",
    ],
)
def test_http_safe_or_unrelated_controls(tmp_path, code):
    assert not [f for f in scan(tmp_path, code) if f["rule_id"] == "SKY-D356"]


def test_dynamic_import_requires_source_evidence(tmp_path):
    findings = scan(
        tmp_path,
        "from importlib import import_module as load\nfrom flask import request\nload(request.args['plugin'])\n",
    )
    hit = next(f for f in findings if f["rule_id"] == "SKY-D357")
    assert hit["security_evidence"]["source"]


@pytest.mark.parametrize(
    "code",
    [
        "from importlib import import_module\nimport_module('known.plugin')",
        "from importlib import import_module\ndef load(name):\n    return import_module(name)",
        "def import_module(name): pass\nfrom flask import request\nimport_module(request.args['plugin'])",
    ],
)
def test_dynamic_import_unknown_is_not_attacker(tmp_path, code):
    assert not [f for f in scan(tmp_path, code) if f["rule_id"] == "SKY-D357"]


def test_public_gradio_without_auth(tmp_path):
    findings = scan(
        tmp_path,
        "import gradio as gr\nwith gr.Blocks() as demo:\n    pass\ndemo.launch(server_name='0.0.0.0')\n",
    )
    assert len([f for f in findings if f["rule_id"] == "SKY-D358"]) == 1


@pytest.mark.parametrize(
    "code",
    [
        "import gradio as gr\ngr.Interface(fn=f, inputs=[], outputs=[]).launch(server_name='127.0.0.1')",
        "import gradio as gr\ngr.Interface(fn=f, inputs=[], outputs=[]).launch(server_name='0.0.0.0', auth=('user', 'password'))",
        "import gradio as gr\ngr.Interface(fn=f, inputs=[], outputs=[]).launch(server_name='0.0.0.0', **options)",
        "class Demo: pass\ndemo = Demo()\ndemo.launch(server_name='0.0.0.0')",
    ],
)
def test_gradio_safe_and_unknown_controls(tmp_path, code):
    assert not [f for f in scan(tmp_path, code) if f["rule_id"] == "SKY-D358"]


def test_fixed_shared_tmp_directory(tmp_path):
    findings = scan(tmp_path, "import os\nos.makedirs('/tmp/myapp', exist_ok=True)\n")
    assert len([f for f in findings if f["rule_id"] == "SKY-D348"]) == 1


@pytest.mark.parametrize("source_present", [False, True])
@pytest.mark.parametrize(
    "code, expected",
    [
        ("import os\nos.makedirs('/' + 'tmp/' + 'shared', exist_ok=True)\n", True),
        (
            "from pathlib import Path\nPath('/' + 'tmp/' + 'shared').mkdir(exist_ok=True)\n",
            True,
        ),
        ("import os\nos.makedirs('/var/' + 'lib/shared', exist_ok=True)\n", False),
        (
            "class OS:\n    def makedirs(self, *args, **kwargs): pass\n"
            "os=OS()\nos.makedirs('/' + 'tmp/' + 'shared', exist_ok=True)\n",
            False,
        ),
    ],
)
def test_shared_tmp_detection_survives_source_prefilter(
    tmp_path, source_present, code, expected
):
    import ast
    from skylos.rules.danger.danger import scan_file_with_tree

    path = tmp_path / "server.py"
    path.write_text(code)
    findings = []
    scan_file_with_tree(
        ast.parse(code),
        path,
        findings,
        source=code if source_present else None,
        project_root=tmp_path,
    )
    rows = [row for row in findings if row["rule_id"] == "SKY-D348"]
    assert len(rows) == int(expected)


@pytest.mark.parametrize(
    "code",
    [
        "import tempfile\ntempfile.mkdtemp(prefix='myapp-')",
        "import os\nos.makedirs('/var/lib/myapp', exist_ok=True)",
        "import os\nos.mkdir('/tmp/myapp')",
        "class os: pass\nos.makedirs('/tmp/myapp', exist_ok=True)",
    ],
)
def test_shared_tmp_controls(tmp_path, code):
    assert not [f for f in scan(tmp_path, code) if f["rule_id"] == "SKY-D348"]


def test_fixed_tmp_directory_through_literal_config(tmp_path):
    findings = scan(
        tmp_path,
        "import os\napp.config['REPORTS_FOLDER'] = os.path.abspath('/tmp/reports')\ndef run():\n    os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)\n",
    )
    assert [
        (f["rule_id"], f["line"]) for f in findings if f["rule_id"] == "SKY-D348"
    ] == [("SKY-D348", 4)]


def test_gradio_visible_kwargs_without_auth(tmp_path):
    findings = scan(
        tmp_path,
        "import gradio as gr\nstyle = {'show_api': False}\nwith gr.Blocks() as demo:\n    pass\ndef run():\n    demo.launch(server_name='0.0.0.0', **style)\n",
    )
    assert len([f for f in findings if f["rule_id"] == "SKY-D358"]) == 1


def test_host_url_reaches_cached_content_through_helper(tmp_path):
    findings = scan(
        tmp_path,
        "from functools import cached_property\nfrom flask.helpers import url_for\nclass Page:\n    @cached_property\n    def content(self):\n        return render(self.get_ctx())\n    def get_ctx(self):\n        def link():\n            return url_for('search', _external=True)\n        return {'link': link}\n",
    )
    assert [
        (f["rule_id"], f["line"]) for f in findings if f["rule_id"] == "SKY-D359"
    ] == [("SKY-D359", 9)]


@pytest.mark.parametrize("decorator", ["", "    @property\n"])
def test_external_url_without_cache_is_not_cache_poisoning(tmp_path, decorator):
    findings = scan(
        tmp_path,
        "from flask import url_for\nclass Page:\n"
        + decorator
        + "    def content(self):\n        return url_for('search', _external=True)\n",
    )
    assert not [f for f in findings if f["rule_id"] == "SKY-D359"]


@pytest.mark.parametrize("privacy", [True, False])
def test_weak_random_slug_requires_private_model_context(tmp_path, privacy):
    context = (
        "    class PrivacyLevel(models.TextChoices):\n        PUBLIC = 'public'\n        PRIVATE = 'private'\n        PROTECTED = 'protected'\n    privacy_level = models.CharField(choices=PrivacyLevel.choices)\n"
        if privacy
        else ""
    )
    code = (
        "from django.db import models\nfrom random import choice\nclass Agent(models.Model):\n"
        + context
        + "    slug = models.CharField(unique=True)\n    def save(self):\n        random_sequence = ''.join(choice('0123456789') for _ in range(6))\n        slug = f'agent-{random_sequence}'\n        self.slug = slug\n"
    )
    findings = scan(tmp_path, code)
    assert bool([f for f in findings if f["rule_id"] == "SKY-D250"]) == privacy


def test_digest_client_nonce_is_security_random_context(tmp_path):
    findings = scan(
        tmp_path,
        "import random\ndef _cnonce():\n    return ''.join(str(random.randrange(10)) for _ in range(20))\n",
    )
    assert len([f for f in findings if f["rule_id"] == "SKY-D250"]) == 1


def test_dynamic_import_through_local_helper(tmp_path):
    findings = scan(
        tmp_path,
        "from importlib import import_module\nfrom flask import request\ndef load(name):\n    return import_module(name)\nload(request.args['plugin'])\n",
    )
    assert len([f for f in findings if f["rule_id"] == "SKY-D357"]) == 1


def test_public_gradio_auth_dependency_none(tmp_path):
    findings = scan(
        tmp_path,
        "import gradio as gr\ngr.Blocks().launch(server_name='0.0.0.0', auth_dependency=None)\n",
    )
    assert len([f for f in findings if f["rule_id"] == "SKY-D358"]) == 1


def test_bound_path_temporary_directory(tmp_path):
    findings = scan(
        tmp_path,
        "from pathlib import Path as P\nreports = P('/tmp/reports')\nreports.mkdir(exist_ok=True)\n",
    )
    assert len([f for f in findings if f["rule_id"] == "SKY-D348"]) == 1


@pytest.mark.parametrize(
    "setting",
    [
        "app.config['SERVER_NAME'] = 'example.com'",
        "app.config['TRUSTED_HOSTS'] = ['example.com']",
    ],
)
def test_fixed_host_prevents_cache_host_warning(tmp_path, setting):
    findings = scan(
        tmp_path,
        "from functools import lru_cache\nfrom flask import url_for, Flask\napp = Flask(__name__)\n"
        + setting
        + "\n@lru_cache\ndef page():\n    return url_for('search', _external=True)\n",
    )
    assert not [f for f in findings if f["rule_id"] == "SKY-D359"]


@pytest.mark.parametrize(
    "mutation", ["style['auth'] = authenticate", "style.update(options)"]
)
def test_gradio_mutated_kwargs_are_not_missing_auth_proof(tmp_path, mutation):
    findings = scan(
        tmp_path,
        "import gradio as gr\nstyle = {'show_api': False}\n"
        + mutation
        + "\ngr.Blocks().launch(server_name='0.0.0.0', **style)\n",
    )
    assert not [f for f in findings if f["rule_id"] == "SKY-D358"]


def test_conditional_fixed_host_is_not_configuration_proof(tmp_path):
    findings = scan(
        tmp_path,
        "from functools import cache\nfrom flask import url_for, Flask\napp = Flask(__name__)\nif configured:\n    app.config['SERVER_NAME'] = 'example.com'\n@cache\ndef page():\n    return url_for('search', _external=True)\n",
    )
    assert len([f for f in findings if f["rule_id"] == "SKY-D359"]) == 1


def test_dynamic_import_helper_replaced_parameter_is_not_tainted(tmp_path):
    findings = scan(
        tmp_path,
        "from importlib import import_module\nfrom flask import request\ndef load(name):\n    name = 'known.module'\n    return import_module(name)\nload(request.args['plugin'])\n",
    )
    assert not [f for f in findings if f["rule_id"] == "SKY-D357"]


@pytest.mark.parametrize(
    "code",
    [
        "from jinja2 import Environment\ndef build():\n    return Environment()\nEnvironment = custom\nbuild()",
        "import jinja2\nsetattr(jinja2, 'Environment', custom)\njinja2.Environment()",
        "from jinja2 import Environment\nfor Environment in constructors:\n    Environment()",
        "from jinja2 import Environment\ntry:\n    operation()\nexcept Error as Environment:\n    Environment()",
    ],
)
def test_mutated_provider_is_not_jinja_environment_proof(tmp_path, code):
    assert not [f for f in scan(tmp_path, code) if f["rule_id"] == "SKY-D355"]


@pytest.mark.parametrize(
    "mutation", ["other = style\nother['auth'] = authenticate", "configure(style)"]
)
def test_gradio_kwargs_alias_or_escape_is_unknown(tmp_path, mutation):
    findings = scan(
        tmp_path,
        "import gradio as gr\nstyle = {'show_api':False}\n"
        + mutation
        + "\ngr.Blocks().launch(server_name='0.0.0.0', **style)",
    )
    assert not [f for f in findings if f["rule_id"] == "SKY-D358"]


def test_host_configuration_for_another_app_is_unknown(tmp_path):
    findings = scan(
        tmp_path,
        "from flask import Flask, url_for\nfrom functools import cache\nsafe = Flask(__name__)\nsafe.config['SERVER_NAME'] = 'example.com'\nunsafe = Flask('unsafe')\n@cache\ndef page():\n    return url_for('search', _external=True)",
    )
    assert len([f for f in findings if f["rule_id"] == "SKY-D359"]) == 1


def test_host_config_from_replaced_app_instance_is_unknown(tmp_path):
    findings = scan(
        tmp_path,
        "from flask import Flask, url_for\nfrom functools import cache\napp = Flask(__name__)\napp.config['SERVER_NAME'] = 'example.com'\napp = Flask('unsafe')\n@cache\ndef page():\n    return url_for('search', _external=True)",
    )
    assert len([f for f in findings if f["rule_id"] == "SKY-D359"]) == 1


def test_host_app_replaced_after_cached_function_definition(tmp_path):
    findings = scan(
        tmp_path,
        "from flask import Flask, url_for\nfrom functools import cache\napp = Flask(__name__)\napp.config['SERVER_NAME'] = 'example.com'\n@cache\ndef page():\n    return url_for('search', _external=True)\napp = Flask('unsafe')",
    )
    assert len([f for f in findings if f["rule_id"] == "SKY-D359"]) == 1


@pytest.mark.parametrize(
    "replacement,expected",
    [
        ("        value = secrets.token_urlsafe()", False),
        ("        if condition:\n            value = secrets.token_urlsafe()", True),
    ],
)
def test_weak_slug_flow_respects_reaching_assignments(tmp_path, replacement, expected):
    code = (
        "from django.db import models\nfrom random import choice\nimport secrets\nclass Agent(models.Model):\n    class PrivacyLevel(models.TextChoices):\n        PRIVATE='private'\n        PROTECTED='protected'\n    privacy_level=models.CharField(choices=PrivacyLevel.choices)\n    slug=models.CharField(unique=True)\n    def save(self):\n        value=choice('abc')\n"
        + replacement
        + "\n        self.slug=value\n"
    )
    assert (
        bool([f for f in scan(tmp_path, code) if f["rule_id"] == "SKY-D250"])
        == expected
    )


@pytest.mark.parametrize(
    "code",
    [
        "import os, tempfile\n"
        "os.makedirs(os.path.join(tempfile.gettempdir(), 'myapp/sessions'), exist_ok=True)\n",
        "import os\nfrom tempfile import gettempdir as tmp\n"
        "base = os.path.join(tmp(), 'myapp')\n"
        "os.makedirs(base, mode=0o700, exist_ok=True)\n",
        "import tempfile\nfrom pathlib import Path\n"
        "(Path(tempfile.gettempdir()) / 'myapp' / 'cache').mkdir(parents=True, exist_ok=True)\n",
        "import os, tempfile\n"
        "class Store:\n"
        "    def __init__(self, storage_dir=None):\n"
        "        self.storage_dir = storage_dir or os.path.join(tempfile.gettempdir(), 'myapp')\n"
        "        os.makedirs(self.storage_dir, exist_ok=True)\n",
        "import os, tempfile\n"
        "def open_store(root=None):\n"
        "    target = root if root else os.path.join(tempfile.gettempdir(), 'myapp')\n"
        "    os.makedirs(target, exist_ok=True)\n",
        "import os, tempfile\n"
        "os.makedirs(f'{tempfile.gettempdir()}/myapp', exist_ok=True)\n",
    ],
)
def test_fixed_directory_under_system_temp_root(tmp_path, code):
    findings = scan(tmp_path, code)
    assert len([f for f in findings if f["rule_id"] == "SKY-D348"]) == 1


@pytest.mark.parametrize(
    "code",
    [
        "import tempfile\ntempfile.mkdtemp(prefix='myapp')\n",
        "import os, tempfile, uuid\n"
        "os.makedirs(os.path.join(tempfile.gettempdir(), uuid.uuid4().hex), exist_ok=True)\n",
        "import os, tempfile\n"
        "def make(name):\n"
        "    os.makedirs(os.path.join(tempfile.gettempdir(), name), exist_ok=True)\n",
        "import os, tempfile\n"
        "os.makedirs(os.path.join(tempfile.gettempdir(), 'myapp'))\n",
        "import os, tempfile\n"
        "os.makedirs(os.path.join(tempfile.gettempdir(), 'myapp'), exist_ok=False)\n",
        "import os\n"
        "os.makedirs(os.path.join(os.path.expanduser('~'), '.myapp'), exist_ok=True)\n",
        "import os\n"
        "def gettempdir():\n    return os.path.expanduser('~/.private')\n"
        "os.makedirs(os.path.join(gettempdir(), 'myapp'), exist_ok=True)\n",
        "import os, tempfile\n"
        "os.makedirs(os.path.join(tempfile.gettempdir(), 'myapp', '/srv/data'), exist_ok=True)\n",
        "import os, tempfile\n"
        "class Store:\n"
        "    def __init__(self, storage_dir):\n"
        "        self.storage_dir = os.path.join(tempfile.gettempdir(), 'myapp')\n"
        "        self.storage_dir = storage_dir\n"
        "        os.makedirs(self.storage_dir, exist_ok=True)\n",
        "import os, tempfile\n"
        "class Store:\n"
        "    def __init__(self):\n"
        "        self.storage_dir = os.path.join(tempfile.gettempdir(), 'myapp')\n"
        "        self.relocate()\n"
        "        os.makedirs(self.storage_dir, exist_ok=True)\n"
        "    def relocate(self):\n"
        "        self.storage_dir = os.path.expanduser('~/.myapp')\n",
        "import os, tempfile\nos.makedirs(tempfile.gettempdir(), exist_ok=True)\n",
    ],
)
def test_private_or_unknown_temp_paths_stay_quiet(tmp_path, code):
    assert not [f for f in scan(tmp_path, code) if f["rule_id"] == "SKY-D348"]


def _graph_rows(findings):
    return [
        f
        for f in findings
        if f["rule_id"] == "SKY-D211" and "graph query" in f["message"]
    ]


@pytest.mark.parametrize(
    "code, line",
    [
        (
            "def add(graph, node):\n"
            "    graph.query(f\"MERGE (n:Entity {{id: '{node.id}'}}) RETURN n\")\n",
            2,
        ),
        (
            'def esc(v):\n    return str(v).replace("\'", "\\\\\'")\n'
            "def link(session, a, b):\n"
            "    session.run(\n"
            "        f\"MATCH (a {{id: '{esc(a)}'}}), \"\n"
            "        f\"(b {{id: '{esc(b)}'}}) \"\n"
            '        f"MERGE (a)-[:KNOWS]->(b)"\n'
            "    )\n",
            4,
        ),
        (
            "def find(driver, name):\n"
            "    cypher = f'MATCH (p:Person) WHERE p.name = \"{name}\" RETURN p'\n"
            "    return driver.execute_query(cypher)\n",
            3,
        ),
        (
            "def find(graph, name):\n"
            "    return graph.query(\"MATCH (p:Person {{name: '{}'}}) RETURN p\".format(name))\n",
            2,
        ),
    ],
)
def test_graph_query_with_value_interpolated_inside_quotes(tmp_path, code, line):
    rows = _graph_rows(scan(tmp_path, code))
    assert [row["line"] for row in rows] == [line]


@pytest.mark.parametrize(
    "code",
    [
        "def add(graph, node):\n"
        "    graph.query('MERGE (n:Entity {id: $id}) RETURN n', params={'id': node.id})\n",
        "def add(graph, label, node):\n"
        "    graph.query(f'MERGE (n:`{label}` {{id: $id}}) RETURN n', params={'id': node.id})\n",
        "KIND = 'person'\n"
        "def find(graph):\n"
        "    graph.query(f\"MATCH (n {{kind: '{KIND}'}}) RETURN n\")\n",
        "def page(graph, size):\n"
        "    graph.query(f'MATCH (n:Entity) RETURN n LIMIT {int(size)}')\n",
        "def find(cursor, name):\n"
        "    cursor.query(f\"SELECT id FROM people WHERE name = '{name}'\")\n",
        "def search(db, text):\n"
        "    db.query(f\"SELECT id FROM docs WHERE MATCH (title) AGAINST ('{text}')\")\n",
        "def describe(node):\n"
        "    return f\"MERGE (n:Entity {{id: '{node.id}'}}) RETURN n\"\n",
        "def log(logger, node):\n"
        "    logger.info(f\"MERGE (n:Entity {{id: '{node.id}'}}) RETURN n\")\n",
    ],
)
def test_parameterized_or_non_graph_queries_stay_quiet(tmp_path, code):
    assert not _graph_rows(scan(tmp_path, code))


@pytest.mark.parametrize(
    "code",
    [
        "import tempfile\nfrom pathlib import Path\n"
        "cache = Path(tempfile.gettempdir()) / 'myapp'\n"
        "cache.mkdir(parents=True, exist_ok=True)\n",
        "import tempfile\nfrom pathlib import Path\n"
        "Path(tempfile.gettempdir(), 'myapp').mkdir(exist_ok=True)\n",
        "from pathlib import Path\nPath('/tmp').joinpath('myapp').mkdir(exist_ok=True)\n",
        "import os, tempfile\nos.makedirs(tempfile.gettempdir() + '/myapp', exist_ok=True)\n",
        "import os, tempfile\n"
        "os.makedirs(os.path.join(tempfile.gettempdir(), 'myapp'), 0o755, True)\n",
    ],
)
def test_fixed_temp_directory_common_spellings(tmp_path, code):
    findings = scan(tmp_path, code)
    assert len([f for f in findings if f["rule_id"] == "SKY-D348"]) == 1


@pytest.mark.parametrize(
    "code",
    [
        "import os, uuid\n"
        "class Store:\n"
        "    def __init__(self):\n"
        "        self.d = '/tmp/app'\n"
        "        self.d += uuid.uuid4().hex\n"
        "        os.makedirs(self.d, exist_ok=True)\n",
        "import os, tempfile, uuid\n"
        "d = os.path.join(tempfile.gettempdir(), 'app')\n"
        "d += uuid.uuid4().hex\n"
        "os.makedirs(d, exist_ok=True)\n",
        "import os, tempfile\n"
        "class Store:\n"
        "    def __init__(self):\n"
        "        self.d = '/tmp/app'\n"
        "        me = self\n"
        "        me.d = tempfile.mkdtemp()\n"
        "        os.makedirs(self.d, exist_ok=True)\n",
        "import os\n"
        "def configure(target):\n    target.d = os.path.expanduser('~/.app')\n"
        "class Store:\n"
        "    def __init__(self):\n"
        "        self.d = '/tmp/app'\n"
        "        configure(target=self)\n"
        "        os.makedirs(self.d, exist_ok=True)\n",
        "import os, tempfile\n"
        "class Store:\n"
        "    def __init__(self):\n"
        "        self.d = '/tmp/app'\n"
        "        def fix():\n"
        "            self.d = tempfile.mkdtemp()\n"
        "        fix()\n"
        "        os.makedirs(self.d, exist_ok=True)\n",
        "import os\n"
        "class Store:\n"
        "    def __init__(self, **kw):\n"
        "        self.d = '/tmp/app'\n"
        "        self.__dict__.update(kw)\n"
        "        os.makedirs(self.d, exist_ok=True)\n",
        "import os\nos.makedirs('/tmp/', exist_ok=True)\n",
    ],
)
def test_temp_directory_value_that_changed_stays_quiet(tmp_path, code):
    assert not [f for f in scan(tmp_path, code) if f["rule_id"] == "SKY-D348"]


def test_graph_query_keyword_of_the_neo4j_driver(tmp_path):
    code = (
        "def find(driver, name):\n"
        "    return driver.execute_query(\n"
        "        query_=f\"MATCH (p:Person {{name: '{name}'}}) RETURN p\"\n"
        "    )\n"
    )
    assert [row["line"] for row in _graph_rows(scan(tmp_path, code))] == [2]


def test_graph_query_finding_claims_no_source(tmp_path):
    code = (
        "def add(graph, node):\n"
        "    graph.query(f\"MERGE (n:Entity {{id: '{node.id}'}}) RETURN n\")\n"
    )
    (row,) = _graph_rows(scan(tmp_path, code))
    assert row["severity"] == "MEDIUM"
    assert row["metadata"]["source_status"] == "unresolved"
    assert row["metadata"]["audit_only"] is True


@pytest.mark.parametrize(
    "code",
    [
        "def ask(chain, question):\n"
        "    chain.run(f\"Translate to Cypher like MATCH (p:Person) RETURN p. Question: '{question}'\")\n",
        "def explain(engine, topic):\n"
        "    engine.query(f'Explain what MATCH (n) RETURN n does for \"{topic}\"')\n",
        "import subprocess\n"
        "def seed(db):\n"
        "    subprocess.run(f\"echo 'CREATE (n:Seed)' | cypher-shell -d '{db}'\", shell=True)\n",
        "def touch(db, v):\n    db.run(f\"UPDATE t SET a='{v}' WHERE MATCH (b)\")\n",
        "def page(graph, limit):\n"
        '    graph.query(f"MATCH (n:User) // don\'t page\\n RETURN n LIMIT {limit}")\n',
        "def find(graph, x):\n"
        "    graph.query(f\"MATCH (n {{rank: '{x:d}'}}) RETURN n\")\n",
    ],
)
def test_text_that_only_mentions_cypher_stays_quiet(tmp_path, code):
    assert not _graph_rows(scan(tmp_path, code))
