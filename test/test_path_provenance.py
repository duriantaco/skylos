"""Caller provenance for path findings that rest on a helper parameter.

``path_provenance`` follows a helper's parameter to the call sites it can
resolve in the scanned source. A finding stays reported only when a resolved
chain starts at untrusted input; every step is recorded in
``metadata.path_provenance``. A caller it cannot resolve leaves the finding
``unknown``: not reported, but kept in ``suppressed`` with the chain.
"""

import json
from pathlib import Path

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink

PATH_RULES = {"SKY-D215", "SKY-D324", "SKY-D325"}

READER = """\
from pathlib import Path

BASE = Path("/srv/files")


def read_file(name):
    return (BASE / name).read_text()
"""


def _project(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "proj"
    (root / ".git").mkdir(parents=True)
    assert write_text_no_symlink(root / "pyproject.toml", '[project]\nname = "proj"\n')
    for name, text in files.items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("fixture path leaves project")
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(path, text)
    return root


def _scan(root: Path) -> dict:
    return json.loads(analyze(str(root), enable_danger=True))


def _reported(result: dict, symbol: str) -> dict[str, dict]:
    return {
        f["rule_id"]: f
        for f in result.get("danger") or []
        if f.get("rule_id") in PATH_RULES and f.get("symbol") == symbol
    }


def _suppressed(result: dict, symbol: str) -> dict[str, dict]:
    return {
        f["rule_id"]: f
        for f in result.get("suppressed") or []
        if f.get("rule_id") in PATH_RULES and f.get("symbol") == symbol
    }


def _status(finding: dict) -> str:
    return finding["metadata"]["path_provenance"]["status"]


def _untrusted_chain(finding: dict) -> list[str]:
    return finding["metadata"]["path_provenance"]["untrusted"][0]




def test_request_value_through_two_helper_calls_is_reported_with_its_chain(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/service.py": "from app.reader import read_file\n\n\n"
            "def load(name):\n    return read_file(name)\n",
            "app/routes.py": "from flask import Flask, request\n\nfrom app.service import load\n\n"
            "app = Flask(__name__)\n\n\n"
            "@app.route('/f')\n"
            "def view():\n    return load(request.args['name'])\n",
        },
    )
    reported = _reported(_scan(root), "read_file")
    assert {"SKY-D215", "SKY-D325"} <= set(reported)
    finding = reported["SKY-D215"]
    assert _status(finding) == "untrusted"
    chain = _untrusted_chain(finding)
    assert chain[0].startswith("app/routes.py:10 request data")
    assert any(step.startswith("app/routes.py:10 call `load(...)` binds `name`") for step in chain)
    assert any(step.startswith("app/service.py:5 call `read_file(...)` binds `name`") for step in chain)
    assert chain[-1].startswith("app/reader.py:7 path")
    assert finding["metadata"]["path_source"] == "resolved_caller"
    evidence = finding["metadata"]["security_evidence"]
    assert evidence["source"].startswith("request data")
    assert all(":" not in step.split(" ", 1)[0] for step in evidence["path"][1:])
    assert "callers are not visible" not in finding["message"]


def test_request_value_through_a_name_alias_and_a_module_alias_is_reported(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/routes.py": "from flask import Flask, request\n\nimport app.reader as files\n\n"
            "app = Flask(__name__)\nfetch = files.read_file\n\n\n"
            "@app.route('/f')\n"
            "def view():\n    name = request.args['name']\n    alias = name\n    return fetch(alias)\n",
        },
    )
    assert "SKY-D215" in _reported(_scan(root), "read_file")


def test_request_value_through_functools_partial_alias_is_reported(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": "from pathlib import Path\n\n\n"
            "def read_file(base, name):\n    return (Path(base) / name).read_text()\n",
            "app/routes.py": "from functools import partial\n\nfrom flask import Flask, request\n\n"
            "from app.reader import read_file\n\n"
            "app = Flask(__name__)\nLOAD = partial(read_file, '/srv')\n\n\n"
            "@app.route('/f')\n"
            "def view():\n    return LOAD(request.args['name'])\n",
        },
    )
    finding = _reported(_scan(root), "read_file")["SKY-D215"]
    assert any(step.startswith("app/routes.py:13 call `LOAD(...)` binds `name`") for step in _untrusted_chain(finding))


def test_request_value_through_a_class_constructor_is_reported(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/job.py": "from app.reader import read_file\n\n\n"
            "class Job:\n"
            "    def __init__(self, name):\n        self.name = name\n\n"
            "    def run(self):\n        return read_file(self.name)\n",
            "app/routes.py": "from fastapi import FastAPI\n\nfrom app.job import Job\n\n"
            "api = FastAPI()\n\n\n"
            "@api.get('/files/{name}')\n"
            "def get_file(name: str):\n    return Job(name).run()\n",
        },
    )
    finding = _reported(_scan(root), "read_file")["SKY-D215"]
    chain = _untrusted_chain(finding)
    assert chain[0].startswith("app/routes.py:9 route parameter `name` of `get_file`")
    assert any("assigns `self.name`" in step for step in chain)


def test_request_value_to_a_method_of_a_module_level_instance_is_reported(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/store.py": "from pathlib import Path\n\n\n"
            "class Store:\n"
            "    def load(self, name):\n"
            "        return (Path('/data') / name).read_text()\n",
            "app/routes.py": "from fastapi import FastAPI\n\nfrom app.store import Store\n\n"
            "api = FastAPI()\nstore = Store()\n\n\n"
            "@api.get('/files/{name}')\n"
            "def get_file(name: str):\n    return store.load(name)\n",
        },
    )
    assert "SKY-D215" in _reported(_scan(root), "load")


def test_value_returned_by_a_helper_that_reads_the_request_is_reported(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/routes.py": "from flask import request\n\nfrom app.reader import read_file\n\n\n"
            "def requested_name():\n    return request.args.get('name', 'index.html')\n\n\n"
            "def show():\n    return read_file(requested_name())\n",
        },
    )
    finding = _reported(_scan(root), "read_file")["SKY-D215"]
    assert any("`requested_name` returns" in step for step in _untrusted_chain(finding))


def test_executor_submit_with_request_data_is_reported(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/routes.py": "from concurrent.futures import ThreadPoolExecutor\n\n"
            "from flask import Flask, request\n\nfrom app.reader import read_file\n\n"
            "app = Flask(__name__)\npool = ThreadPoolExecutor()\n\n\n"
            "@app.route('/f')\n"
            "def view():\n    return pool.submit(read_file, request.args['name']).result()\n",
        },
    )
    assert "SKY-D215" in _reported(_scan(root), "read_file")


def test_dispatch_by_computed_name_with_request_data_is_reported(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/actions.py": "from pathlib import Path\n\n\n"
            "def do_read(name):\n    return (Path('/srv') / name).read_text()\n",
            "app/routes.py": "from flask import Flask, request\n\nfrom app import actions\n\n"
            "app = Flask(__name__)\n\n\n"
            "@app.route('/<action>')\n"
            "def run(action):\n    return getattr(actions, 'do_' + action)(request.args['name'])\n",
        },
    )
    assert "SKY-D215" in _reported(_scan(root), "do_read")


def test_cgi_request_variable_from_another_module_is_reported(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "cgi-bin/view.py": "import os\n\nfrom app.reader import read_file\n\n"
            "print(read_file(os.environ['QUERY_STRING']))\n",
        },
    )
    finding = _reported(_scan(root), "read_file")["SKY-D215"]
    assert "CGI request variable `QUERY_STRING`" in _untrusted_chain(finding)[0]


def test_network_response_value_is_reported(tmp_path):
    root = _project(
        tmp_path,
        {
            "sync/__init__.py": "",
            "sync/store.py": "from pathlib import Path\n\n\n"
            "def _save(name, body):\n    (Path('/var/cache') / name).write_bytes(body)\n",
            "sync/client.py": "import requests\n\nfrom sync.store import _save\n\n\n"
            "def mirror(url):\n"
            "    listing = requests.get(url, timeout=5).json()\n"
            "    for entry in listing['files']:\n"
            "        _save(entry['path'], b'')\n",
        },
    )
    reported = _reported(_scan(root), "_save")
    assert {"SKY-D215", "SKY-D324"} <= set(reported)
    assert "network response" in _untrusted_chain(reported["SKY-D215"])[0]


def test_archive_member_name_passed_to_a_helper_is_reported(tmp_path):
    root = _project(
        tmp_path,
        {
            "tools/unpack.py": "import zipfile\nfrom pathlib import Path\n\n\n"
            "def _write_member(dest, name, data):\n"
            "    (Path(dest) / name).write_bytes(data)\n\n\n"
            "def unpack(archive, dest):\n"
            "    with zipfile.ZipFile(archive) as bundle:\n"
            "        for info in bundle.infolist():\n"
            "            _write_member(dest, info.filename, bundle.read(info))\n",
        },
    )
    reported = _reported(_scan(root), "_write_member")
    assert "SKY-D215" in reported
    assert "archive member name" in _untrusted_chain(reported["SKY-D215"])[0]


def test_mcp_tool_argument_passed_to_a_helper_in_another_module_is_reported(tmp_path):
    root = _project(
        tmp_path,
        {
            "srv/__init__.py": "",
            "srv/files.py": READER,
            "srv/tools.py": "from mcp.server.fastmcp import FastMCP\n\nfrom srv.files import read_file\n\n"
            "mcp = FastMCP('files')\n\n\n"
            "@mcp.tool()\n"
            "def read(path: str) -> str:\n    return read_file(path)\n",
        },
    )
    finding = _reported(_scan(root), "read_file")["SKY-D215"]
    assert "MCP/agent tool argument `path`" in _untrusted_chain(finding)[0]


def test_wsgi_application_named_by_a_server_command_is_reported(tmp_path):
    root = _project(
        tmp_path,
        {
            "Dockerfile.prod": 'CMD ["gunicorn", "wsgi_app:application"]\n',
            "wsgi_app.py": "import os\n\nROOT = '/srv/files'\n\n\n"
            "def application(environ, start_response):\n"
            "    path = environ.get('PATH_INFO', '/').lstrip('/')\n"
            "    with open(os.path.join(ROOT, path), 'rb') as fh:\n"
            "        body = fh.read()\n"
            "    start_response('200 OK', [])\n"
            "    return [body]\n",
        },
    )
    finding = _reported(_scan(root), "application")["SKY-D215"]
    assert _untrusted_chain(finding)[0].startswith("Dockerfile.prod:1 deployment file names")


def test_flask_view_registered_with_add_url_rule_is_reported(tmp_path):
    root = _project(
        tmp_path,
        {
            "views.py": "from pathlib import Path\n\nfrom flask import Flask\n\n"
            "app = Flask(__name__)\n\n\n"
            "def download(name):\n    return (Path('/srv') / name).read_text()\n\n\n"
            "app.add_url_rule('/d/<name>', view_func=download)\n",
        },
    )
    finding = _reported(_scan(root), "download")["SKY-D215"]
    assert "registered as a web route" in _untrusted_chain(finding)[0]


def test_module_state_written_by_a_route_is_reported(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/state.py": "from flask import Flask, request\n\nfrom app.reader import read_file\n\n"
            "app = Flask(__name__)\nSTATE = {'name': 'index.html'}\n\n\n"
            "@app.route('/set', methods=['POST'])\n"
            "def set_name():\n    STATE['name'] = request.form['name']\n    return ''\n\n\n"
            "def show():\n    return read_file(STATE['name'])\n",
        },
    )
    assert "SKY-D215" in _reported(_scan(root), "read_file")


def test_mutated_lookup_table_with_a_request_key_is_not_proven_constant(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/routes.py": "from flask import Flask, request\n\nfrom app.reader import read_file\n\n"
            "app = Flask(__name__)\nFILES = {'a': 'a.txt'}\n\n\n"
            "@app.route('/add', methods=['POST'])\n"
            "def add():\n    FILES[request.form['key']] = request.form['path']\n    return ''\n\n\n"
            "@app.route('/f')\n"
            "def view():\n    return read_file(FILES[request.args['key']])\n",
        },
    )
    assert "SKY-D215" in _reported(_scan(root), "read_file")


def test_http_server_request_path_from_an_extensionless_script_is_reported(tmp_path):
    root = _project(
        tmp_path,
        {
            "fileutil.py": "import os\n\nBASE = '/srv/share'\n\n\n"
            "def read_file(name):\n"
            "    with open(os.path.join(BASE, name), 'rb') as fh:\n"
            "        return fh.read()\n",
            "bin/serve": "#!/usr/bin/env python3\n"
            "from http.server import BaseHTTPRequestHandler\n"
            "from fileutil import read_file\n\n\n"
            "class Handler(BaseHTTPRequestHandler):\n"
            "    def do_GET(self):\n"
            "        self.wfile.write(read_file(self.path.lstrip('/')))\n",
        },
    )
    finding = _reported(_scan(root), "read_file")["SKY-D215"]
    assert "HTTP request `self.path`" in _untrusted_chain(finding)[0]


def test_one_untrusted_caller_is_reported_beside_safe_ones(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/report.py": "from app.reader import read_file\n\n\n"
            "def build():\n    return read_file('summary.txt')\n",
            "app/routes.py": "from flask import request\n\nfrom app.reader import read_file\n\n\n"
            "def view():\n    return read_file(request.args['name'])\n",
        },
    )
    finding = _reported(_scan(root), "read_file")["SKY-D215"]
    provenance = finding["metadata"]["path_provenance"]
    assert provenance["status"] == "untrusted"
    assert any(chain[0].startswith("app/report.py:5 literal") for chain in provenance["safe"])


def test_process_launch_with_request_arguments_keeps_cli_paths_unproven(tmp_path):
    root = _project(
        tmp_path,
        {
            "scripts/report.py": "import sys\nfrom pathlib import Path\n\n\n"
            "def _read_doc(path):\n    return Path(path).read_text()\n\n\n"
            "if __name__ == '__main__':\n    print(_read_doc(sys.argv[1]))\n",
            "web.py": "import subprocess\nimport sys\n\nfrom flask import request\n\n\n"
            "def run_report():\n"
            "    return subprocess.run([sys.executable, 'scripts/report.py', request.args['doc']])\n",
        },
    )
    finding = _suppressed(_scan(root), "_read_doc")["SKY-D325"]
    provenance = finding["metadata"]["path_provenance"]
    assert provenance["status"] == "unknown"
    assert any("process launch passes untrusted arguments" in chain[0] for chain in provenance["unknown"])


def test_request_value_assigned_to_an_instance_after_construction_is_reported(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/job.py": "from app.reader import read_file\n\n\n"
            "class Job:\n"
            "    name = 'index.html'\n\n"
            "    def run(self):\n        return read_file(self.name)\n",
            "app/routes.py": "from flask import request\n\nfrom app.job import Job\n\n\n"
            "def view():\n    job = Job()\n    job.name = request.args['name']\n    return job.run()\n",
        },
    )
    assert "SKY-D215" in _reported(_scan(root), "read_file")


def test_request_value_through_a_dataclass_field_is_reported(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/model.py": "from dataclasses import dataclass\n\nfrom app.reader import read_file\n\n\n"
            "@dataclass\nclass Download:\n    path: str\n    size: int = 0\n\n"
            "    def body(self):\n        return read_file(self.path)\n",
            "app/routes.py": "from flask import request\n\nfrom app.model import Download\n\n\n"
            "def view():\n    return Download(request.args['path']).body()\n",
        },
    )
    assert "SKY-D215" in _reported(_scan(root), "read_file")


def test_request_value_through_super_init_is_reported(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/jobs.py": "from app.reader import read_file\n\n\n"
            "class Base:\n    def __init__(self, name):\n        self.name = name\n\n"
            "    def run(self):\n        return read_file(self.name)\n\n\n"
            "class Child(Base):\n    def __init__(self, name):\n        super().__init__(name)\n",
            "app/routes.py": "from flask import request\n\nfrom app.jobs import Child\n\n\n"
            "def view():\n    return Child(request.args['name']).run()\n",
        },
    )
    assert "SKY-D215" in _reported(_scan(root), "read_file")


def test_request_value_forwarded_through_keyword_mappings_is_reported(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/service.py": "from app.reader import read_file\n\n\n"
            "def forward(**options):\n    return read_file(**options)\n",
            "app/routes.py": "from flask import request\n\nfrom app.service import forward\n\n\n"
            "def view():\n    return forward(name=request.args['name'])\n",
        },
    )
    assert "SKY-D215" in _reported(_scan(root), "read_file")


def test_each_item_of_a_request_list_is_reported(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/routes.py": "from flask import request\n\nfrom app.reader import read_file\n\n\n"
            "def bundle():\n"
            "    names = request.get_json()['files']\n"
            "    return [read_file(item.strip()) for item in names]\n",
        },
    )
    assert "SKY-D215" in _reported(_scan(root), "read_file")


def test_flask_restful_request_parser_is_request_input(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/api.py": "from flask_restful import reqparse\n\nfrom app.reader import read_file\n\n"
            "parser = reqparse.RequestParser()\nparser.add_argument('name')\n\n\n"
            "def get():\n    args = parser.parse_args()\n    return read_file(args.name)\n",
        },
    )
    assert "SKY-D215" in _reported(_scan(root), "read_file")


def test_augmented_and_conditional_assignments_keep_the_request_value(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/routes.py": "from flask import request\n\nfrom app.reader import read_file\n\n\n"
            "def view():\n"
            "    name = request.args['name']\n"
            "    name += '.txt'\n"
            "    for suffix in ():\n        name = 'fixed' + suffix\n"
            "    return read_file(name)\n",
        },
    )
    assert "SKY-D215" in _reported(_scan(root), "read_file")


def test_request_value_stored_into_a_local_container_is_reported(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/routes.py": "from flask import request\n\nfrom app.reader import read_file\n\n\n"
            "def view():\n"
            "    options = {'name': 'index.html'}\n"
            "    options['name'] = request.args['name']\n"
            "    names = []\n"
            "    names.append(request.args['other'])\n"
            "    return read_file(options['name']), read_file(names[0])\n",
        },
    )
    finding = _reported(_scan(root), "read_file")["SKY-D215"]
    assert any("stores into `options`" in step for chain in finding["metadata"]["path_provenance"]["untrusted"] for step in chain)


def test_local_container_filled_by_another_function_is_not_proven_safe(tmp_path):
    root = _project(
        tmp_path,
        {
            "tools/__init__.py": "",
            "tools/reader.py": "from pathlib import Path\n\n\n"
            "def _read(name):\n    return (Path('/srv') / name).read_text()\n",
            "tools/run.py": "from tools.reader import _read\n\n\n"
            "def _fill(options):\n    options['name'] = input()\n\n\n"
            "def main():\n    options = {}\n    _fill(options)\n    return _read(options['name'])\n\n\n"
            "if __name__ == '__main__':\n    main()\n",
        },
    )
    finding = _suppressed(_scan(root), "_read")["SKY-D215"]
    assert _status(finding) == "unknown"


def test_request_value_stored_into_an_instance_container_is_reported(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/cache.py": "from app.reader import read_file\n\n\n"
            "class Cache:\n"
            "    def __init__(self):\n        self.files = {}\n\n"
            "    def remember(self, key, name):\n        self.files[key] = name\n\n"
            "    def show(self, key):\n        return read_file(self.files[key])\n",
            "app/routes.py": "from flask import request\n\nfrom app.cache import Cache\n\n"
            "CACHE = Cache()\n\n\n"
            "def view():\n    CACHE.remember('k', request.args['name'])\n    return CACHE.show('k')\n",
        },
    )
    assert "SKY-D215" in _reported(_scan(root), "read_file")


def test_aliased_framework_request_object_is_reported(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/views.py": "import flask\n\nfrom app.reader import read_file\n\n"
            "incoming = flask.request\n\n\n"
            "def view():\n    return read_file(incoming.args['name'])\n",
        },
    )
    assert "SKY-D215" in _reported(_scan(root), "read_file")




def test_private_script_helper_called_only_with_constants_is_safe(tmp_path):
    root = _project(
        tmp_path,
        {
            "scripts/build.py": "from pathlib import Path\n\n"
            "DATA = Path(__file__).parent / 'data'\n\n\n"
            "def _load(path):\n    return path.read_text()\n\n\n"
            "def main():\n    return _load(DATA / 'stars.json')\n\n\n"
            "if __name__ == '__main__':\n    main()\n",
        },
    )
    result = _scan(root)
    assert _reported(result, "_load") == {}
    finding = _suppressed(result, "_load")["SKY-D325"]
    assert _status(finding) == "safe"
    assert any("module location `__file__`" in chain[0] for chain in finding["metadata"]["path_provenance"]["safe"])


def test_cli_argument_caller_is_operator_input_not_a_report(tmp_path):
    root = _project(
        tmp_path,
        {
            "tool.py": "import argparse\nfrom pathlib import Path\n\n\n"
            "def _convert(path):\n    return Path(path).read_text()\n\n\n"
            "def main():\n"
            "    parser = argparse.ArgumentParser()\n    parser.add_argument('path')\n"
            "    args = parser.parse_args()\n    print(_convert(args.path))\n\n\n"
            "if __name__ == '__main__':\n    main()\n",
        },
    )
    result = _scan(root)
    assert _reported(result, "_convert") == {}
    finding = _suppressed(result, "_convert")["SKY-D325"]
    assert _status(finding) == "safe"
    assert finding["metadata"]["path_provenance"]["operator"]


def test_clock_and_integer_values_are_safe(tmp_path):
    root = _project(
        tmp_path,
        {
            "jobs.py": "from datetime import datetime\nfrom pathlib import Path\n\n\n"
            "def _snapshot(folder, stamp):\n    (Path(folder) / f'{stamp}.txt').write_text('x')\n\n\n"
            "def _read_pid(pid):\n    return open(f'/proc/{pid}/cmdline', 'rb').read()\n\n\n"
            "def main():\n"
            "    _snapshot('output', datetime.now().strftime('%H-%M'))\n"
            "    _read_pid(int(open('/run/app.pid').read()))\n\n\n"
            "if __name__ == '__main__':\n    main()\n",
        },
    )
    result = _scan(root)
    assert _reported(result, "_snapshot") == {}
    assert _reported(result, "_read_pid") == {}
    assert _status(_suppressed(result, "_snapshot")["SKY-D324"]) == "safe"


def test_helper_returning_a_package_file_is_safe_whatever_its_argument(tmp_path):
    root = _project(
        tmp_path,
        {
            "db.py": "from pathlib import Path\n\n\n"
            "class _Schema:\n"
            "    def _path(self, kind):\n"
            "        if kind == 'rss':\n            return Path(__file__).parent / 'rss.sql'\n"
            "        return Path(__file__).parent / 'news.sql'\n\n"
            "    def _init(self, kind):\n"
            "        with open(self._path(kind)) as fh:\n            return fh.read()\n\n\n"
            "def main():\n    return _Schema()._init('news')\n\n\n"
            "if __name__ == '__main__':\n    main()\n",
        },
    )
    result = _scan(root)
    assert _reported(result, "_init") == {}


def test_constant_table_lookup_with_a_request_key_is_safe(tmp_path):
    root = _project(
        tmp_path,
        {
            "files.py": "from pathlib import Path\n\n\n"
            "def _load(path):\n    return path.read_text()\n",
            "views.py": "from pathlib import Path\n\nfrom flask import request\n\nfrom files import _load\n\n"
            "DATA = Path(__file__).parent\nTABLE = {'style': {'file': 'styles.csv'}, 'color': {'file': 'colors.csv'}}\n\n\n"
            "def view():\n    return _load(DATA / TABLE[request.args['kind']]['file'])\n",
        },
    )
    result = _scan(root)
    assert _reported(result, "_load") == {}
    assert _status(_suppressed(result, "_load")["SKY-D325"]) == "safe"


def test_mutable_allowlist_in_the_caller_is_not_a_guard(tmp_path):
    root = _project(
        tmp_path,
        {
            "files.py": "from pathlib import Path\n\n\n"
            "def _load(name):\n    return (Path('/srv') / name).read_text()\n",
            "views.py": "from flask import abort, request\n\nfrom files import _load\n\n"
            "ALLOWED = {'a.txt'}\n\n\n"
            "def allow():\n    ALLOWED.add(request.args['extra'])\n\n\n"
            "def view():\n"
            "    name = request.args['name']\n"
            "    if name not in ALLOWED:\n        abort(404)\n"
            "    return _load(name)\n",
        },
    )
    assert "SKY-D215" in _reported(_scan(root), "_load")


def test_allowlist_check_in_the_caller_is_safe(tmp_path):
    root = _project(
        tmp_path,
        {
            "files.py": "from pathlib import Path\n\n\n"
            "def _load(name):\n    return (Path('/srv') / name).read_text()\n",
            "views.py": "from flask import abort, request\n\nfrom files import _load\n\n"
            "ALLOWED = {'a.txt', 'b.txt'}\n\n\n"
            "def view():\n"
            "    name = request.args['name']\n"
            "    if name not in ALLOWED:\n        abort(404)\n"
            "    return _load(name)\n",
        },
    )
    assert _reported(_scan(root), "_load") == {}


def test_basename_in_the_caller_clears_traversal_but_not_the_symlink_read(tmp_path):
    root = _project(
        tmp_path,
        {
            "files.py": "from pathlib import Path\n\n\n"
            "def _load(name):\n    return (Path('/srv') / name).read_text()\n",
            "views.py": "import os\n\nfrom flask import request\n\nfrom files import _load\n\n\n"
            "def view():\n    return _load(os.path.basename(request.args['name']))\n",
        },
    )
    reported = _reported(_scan(root), "_load")
    assert "SKY-D215" not in reported
    assert "SKY-D325" in reported


def test_local_variable_named_like_a_request_is_followed_not_assumed(tmp_path):
    root = _project(
        tmp_path,
        {
            "tools/__init__.py": "",
            "tools/reader.py": "from pathlib import Path\n\n\n"
            "def _read(name):\n    return (Path('/srv') / name).read_text()\n",
            "tools/build.py": "from tools.reader import _read\n\n\n"
            "class Requirement:\n    name = 'requirements.txt'\n\n\n"
            "def main():\n    req = Requirement()\n    return _read(req.name)\n\n\n"
            "if __name__ == '__main__':\n    main()\n",
        },
    )
    result = _scan(root)
    assert _reported(result, "_read") == {}
    assert _status(_suppressed(result, "_read")["SKY-D215"]) == "safe"


def test_helper_without_callers_is_unknown_not_reported(tmp_path):
    root = _project(tmp_path, {"lib.py": READER})
    result = _scan(root)
    assert _reported(result, "read_file") == {}
    finding = _suppressed(result, "read_file")["SKY-D215"]
    assert _status(finding) == "unknown"
    assert any(
        "no call of `read_file` in the scanned project" in chain[0]
        for chain in finding["metadata"]["path_provenance"]["unknown"]
    )


def test_helper_passed_as_a_callback_is_unknown_with_the_escape_recorded(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/plugins.py": "from app.reader import read_file\n\nHANDLERS = {'read': read_file}\n",
        },
    )
    result = _scan(root)
    assert _reported(result, "read_file") == {}
    unknown = _suppressed(result, "read_file")["SKY-D215"]["metadata"]["path_provenance"]["unknown"]
    assert any("app/plugins.py:3 `read_file` is passed as a value" in chain[0] for chain in unknown)


def test_same_name_on_another_module_is_not_a_caller(tmp_path):
    root = _project(
        tmp_path,
        {
            "files.py": "from pathlib import Path\n\n\n"
            "def load(name):\n    return (Path('/srv') / name).read_text()\n",
            "config.py": "import json\n\n\n"
            "def read_config(handle):\n    return json.load(handle)\n",
        },
    )
    provenance = _suppressed(_scan(root), "load")["SKY-D215"]["metadata"]["path_provenance"]
    steps = [step for kind in ("unknown", "safe", "operator") for chain in provenance.get(kind, []) for step in chain]
    assert not any(step.startswith("config.py") for step in steps)
    assert any("no call of `load`" in step for step in steps)


def test_subdirectory_scan_cannot_prove_safety(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/_reader.py": READER,
            "app/report.py": "from app._reader import read_file\n\n\n"
            "def build():\n    return read_file('summary.txt')\n",
        },
    )
    result = _scan(root / "app")
    assert _reported(result, "read_file") == {}
    provenance = _suppressed(result, "read_file")["SKY-D215"]["metadata"]["path_provenance"]
    assert provenance["status"] == "unknown"
    assert provenance["complete_project"] is False


def test_public_function_of_a_package_is_unknown_even_with_constant_callers(tmp_path):
    root = _project(
        tmp_path,
        {
            "mylib/__init__.py": "",
            "mylib/storage.py": READER + "\n\nDEFAULT = read_file('default.bin')\n",
        },
    )
    provenance = _suppressed(_scan(root), "read_file")["SKY-D215"]["metadata"]["path_provenance"]
    assert provenance["status"] == "unknown"
    assert any("public in an importable package" in chain[0] for chain in provenance["unknown"])


_CONTAINED_LOADER = (
    "def _load(path):\n"
    "    with open(path, 'rb') as handle:\n"
    "        return handle.read()\n"
)


def _containment_view(guard, bind="full = (BASE / name).resolve().absolute()"):
    return (
        "from pathlib import Path\n\nfrom flask import abort, request\n\nfrom files import _load\n\n"
        "BASE = Path('/srv/files')\n\n\n"
        "@app.route('/f')\n"
        "def view():\n"
        "    name = request.args['name']\n"
        f"    {bind}\n"
        f"{guard}"
        "    return _load(full)\n"
    )


_SAFE_CONTAINMENT_GUARDS = [
    "    try:\n        full.relative_to(BASE.resolve())\n    except ValueError:\n        abort(404)\n",
    "    try:\n        full.relative_to(BASE)\n    except ValueError:\n        return 'outside'\n",
    "    full.relative_to(BASE)\n",
    "    if not full.is_relative_to(BASE):\n        abort(404)\n",
    "    if not str(full).startswith(str(BASE) + '/'):\n        raise PermissionError(name)\n",
    "    if not str(full).startswith(str(BASE) + os.sep):\n        raise PermissionError(name)\n",
    "    if os.path.commonpath([full, BASE]) != str(BASE):\n        abort(404)\n",
    "    assert full.is_relative_to(BASE)\n",
]


def test_containment_check_in_the_caller_is_safe(tmp_path):
    for index, guard in enumerate(_SAFE_CONTAINMENT_GUARDS):
        root = _project(
            tmp_path / str(index),
            {"files.py": _CONTAINED_LOADER, "views.py": "import os\n" + _containment_view(guard)},
        )
        result = _scan(root)
        assert _reported(result, "_load") == {}, guard
        assert _status(_suppressed(result, "_load")["SKY-D215"]) == "safe", guard


def test_containment_check_inside_an_if_around_the_call_is_safe(tmp_path):
    view = (
        "from pathlib import Path\n\nfrom flask import request\n\nfrom files import _load\n\n"
        "BASE = Path('/srv/files')\n\n\n"
        "@app.route('/f')\n"
        "def view():\n"
        "    full = (BASE / request.args['name']).resolve()\n"
        "    if full.is_relative_to(BASE) and full.is_file():\n"
        "        return _load(full)\n"
        "    return ''\n"
    )
    root = _project(tmp_path, {"files.py": _CONTAINED_LOADER, "views.py": view})
    assert _reported(_scan(root), "_load") == {}


def test_containment_checks_that_prove_nothing_still_report(tmp_path):
    cases = [
        ("    try:\n        full.relative_to(BASE)\n    except ValueError:\n        pass\n", None),
        ("    try:\n        full.relative_to(BASE)\n    except ValueError:\n        abort(404)\n", "full = BASE / name"),
        ("    if not full.is_relative_to(BASE):\n        print('outside')\n", None),
        ("    full.is_relative_to(BASE)\n", None),
        ("    if not other.is_relative_to(BASE):\n        abort(404)\n", None),
        ("    if not full.is_relative_to(BASE) and name:\n        abort(404)\n", None),
        ("    if not full.is_relative_to(BASE):\n        abort(404)\n    full = BASE / name\n", None),
        ("    if os.path.commonpath([full, BASE]) == str(BASE):\n        abort(404)\n", None),
        ("    if not str(full).startswith(str(BASE)):\n        raise PermissionError(name)\n", None),
        ("    if os.path.commonpath([full, BASE]) != '/':\n        abort(404)\n", None),
        ("    full.relative_to(Path(request.args['base']).resolve())\n", None),
        ("    if not full.is_relative_to(Path(request.args['base']).resolve()):\n        abort(404)\n", None),
        ("    full.relative_to(BASE, walk_up=True)\n", None),
        ("    if not str(full).startswith(str(BASE) + '/'):\n        abort(404)\n", "full = os.path.abspath(BASE / name)"),
        ("    if not str(full).startswith(str(BASE) + '/'):\n        abort(404)\n", "full = os.path.normpath(BASE / name)"),
    ]
    for index, (guard, bind) in enumerate(cases):
        view = _containment_view(guard)
        if bind is not None:
            view = _containment_view(guard, bind)
        root = _project(
            tmp_path / str(index),
            {"files.py": _CONTAINED_LOADER, "views.py": "import os\nother = None\n" + view},
        )
        assert "SKY-D215" in _reported(_scan(root), "_load"), guard


def test_containment_proof_requires_real_standard_library_bindings(tmp_path):
    cases = [
        (
            "def resolve(value):\n    return value\n",
            "full = resolve(str(BASE / name))",
            "    if not full.startswith(str(BASE) + '/'):\n        abort(404)\n",
        ),
        (
            "def commonpath(values):\n    return str(BASE)\n",
            "full = (BASE / name).resolve()",
            "    if commonpath([full, BASE]) != str(BASE):\n        abort(404)\n",
        ),
        (
            "os.path.commonpath = lambda values: str(BASE)\n",
            "full = (BASE / name).resolve()",
            "    if os.path.commonpath([full, BASE]) != str(BASE):\n        abort(404)\n",
        ),
        (
            "def abort(status):\n    return None\n",
            "full = (BASE / name).resolve()",
            "    if not full.is_relative_to(BASE):\n        abort(404)\n",
        ),
        (
            "os.sep = ''\n",
            "full = (BASE / name).resolve()",
            "    if not str(full).startswith(str(BASE) + os.sep):\n        abort(404)\n",
        ),
    ]
    for index, (setup, bind, guard) in enumerate(cases):
        view = "import os\n" + _containment_view(guard, bind)
        view = view.replace("@app.route('/f')", setup + "\n@app.route('/f')")
        root = _project(tmp_path / str(index), {"files.py": _CONTAINED_LOADER, "views.py": view})
        assert "SKY-D215" in _reported(_scan(root), "_load"), setup


def _closure_root_view(calls):
    return (
        "from pathlib import Path\nfrom flask import request\nfrom files import _load\n\n"
        "def make_handler(root):\n"
        "    root = Path(root)\n"
        "    def handler(request):\n"
        "        full = (root / request.args['name']).resolve()\n"
        "        full.relative_to(root.resolve())\n"
        "        return _load(full)\n"
        "    return handler\n\n"
        + calls
    )


def test_configured_closure_root_preserves_unresolved_caller_evidence(tmp_path):
    root = _project(
        tmp_path,
        {
            "files.py": _CONTAINED_LOADER,
            "application/__init__.py": "",
            "application/views.py": _closure_root_view("handler = make_handler('/srv/files')\n"),
        },
    )
    result = _scan(root)
    assert _reported(result, "_load") == {}
    record = _suppressed(result, "_load")["SKY-D215"]["metadata"]["path_provenance"]
    assert record["status"] == "unknown"
    explained = False
    for chain in record["unknown"]:
        for step in chain:
            if "configured closure-root callers are only partly resolved" in step:
                explained = True
    assert explained


def test_unknown_or_request_controlled_closure_roots_still_report(tmp_path):
    callers = [
        "",
        "handler = make_handler(unknown_root / 'static')\n",
        "handler = make_handler(request.args['base'])\n",
        "handler = make_handler('/srv/files')\nunsafe = make_handler(request.args['base'])\n",
    ]
    for index, calls in enumerate(callers):
        root = _project(
            tmp_path / str(index),
            {
                "files.py": _CONTAINED_LOADER,
                "application/__init__.py": "",
                "application/views.py": _closure_root_view(calls),
            },
        )
        assert "SKY-D215" in _reported(_scan(root), "_load"), calls


def test_unknown_handler_base_is_not_a_containment_proof(tmp_path):
    view = _containment_view("    full.relative_to(Path(base).resolve())\n")
    view = view.replace("@app.route('/f')\n", "").replace("def view():", "def view(base):")
    root = _project(tmp_path, {"files.py": _CONTAINED_LOADER, "views.py": view})
    assert "SKY-D215" in _reported(_scan(root), "_load")
