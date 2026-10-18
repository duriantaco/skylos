"""Path findings on a production helper's parameter stay reported.

A cross-file "every caller passes safe values" proof was tried and removed:
independent adversarial review found real traversals it hid (dispatch by
computed name, mutable module state, CGI/SSH environment, subprocess argv,
symlinked archive members). These cases pin that production helpers keep
their finding whatever their visible callers pass; only test code is exempt
(test_path_closed_world.py).
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


def _reported(root: Path) -> set[tuple[str, str]]:
    result = json.loads(analyze(str(root), enable_danger=True))
    return {
        (Path(f["file"]).name, f.get("symbol"))
        for f in result.get("danger") or []
        if f.get("rule_id") in PATH_RULES
    }


# ------------------------------------- visible callers pass safe values


def test_helper_called_only_with_internal_values_is_kept(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/report.py": "from app.reader import read_file\n\n\n"
            "def build():\n    return read_file('summary.txt')\n",
        },
    )
    assert ("reader.py", "read_file") in _reported(root)


def test_helper_called_with_cli_arguments_across_modules_is_kept(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/cli.py": "import argparse\n\nfrom app.reader import read_file\n\n\n"
            "def main():\n"
            "    parser = argparse.ArgumentParser()\n"
            "    parser.add_argument('name')\n"
            "    args = parser.parse_args()\n"
            "    print(read_file(args.name))\n",
        },
    )
    assert ("reader.py", "read_file") in _reported(root)


def test_chain_of_helpers_ending_in_internal_values_is_kept(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/service.py": "from app.reader import read_file\n\n\n"
            "def load(name):\n    return read_file(name)\n",
            "app/jobs.py": "import hashlib\n\nfrom app.service import load\n\n\n"
            "def nightly():\n"
            "    key = hashlib.sha256(b'x').hexdigest()\n"
            "    return load(key + '.json')\n",
        },
    )
    assert ("reader.py", "read_file") in _reported(root)


def test_method_run_in_an_executor_with_internal_values_is_kept(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/store.py": "from concurrent.futures import ThreadPoolExecutor\nfrom pathlib import Path\n\n"
            "POOL = ThreadPoolExecutor()\n\n\n"
            "class Store:\n"
            "    def load(self, name):\n"
            "        return (Path('/data') / name).read_text()\n\n"
            "    def load_index(self):\n"
            "        return POOL.submit(self.load, 'index.json').result()\n\n\n"
            "def main():\n"
            "    return Store().load_index()\n",
        },
    )
    assert ("store.py", "load") in _reported(root)


def test_partial_is_kept_because_it_may_get_more_arguments_later(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/routes.py": "from functools import partial\n\nfrom flask import request\n\n"
            "from app.reader import read_file\n\n"
            "LOAD = partial(read_file)\n\n\n"
            "def view():\n    return LOAD(request.args['name'])\n",
        },
    )
    assert ("reader.py", "read_file") in _reported(root)


# ------------------------------------------------------------------- kept


def test_helper_reached_from_a_route_through_two_modules_is_kept(tmp_path):
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
    assert ("reader.py", "read_file") in _reported(root)


def test_method_called_by_a_route_on_an_instance_is_kept(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/store.py": "from pathlib import Path\n\n\n"
            "class Store:\n"
            "    def load(self, name):\n"
            "        return (Path('/data') / name).read_text()\n",
            "app/routes.py": "from fastapi import FastAPI\n\nfrom app.store import Store\n\n"
            "app = FastAPI()\nstore = Store()\n\n\n"
            "@app.get('/files/{name}')\n"
            "def get_file(name: str):\n    return store.load(name)\n",
        },
    )
    assert ("store.py", "load") in _reported(root)


def test_executor_call_with_request_data_is_kept(tmp_path):
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
    assert ("reader.py", "read_file") in _reported(root)


def test_lambda_handler_shape_without_callers_is_kept(tmp_path):
    root = _project(
        tmp_path,
        {
            "handler.py": "import os\n\n\n"
            "def handle(event, context):\n"
            "    return open(os.path.join('/var/task', event['file'])).read()\n",
        },
    )
    assert ("handler.py", "handle") in _reported(root)


def test_module_importing_a_web_framework_without_callers_is_kept(tmp_path):
    root = _project(
        tmp_path,
        {
            "views.py": "from pathlib import Path\n\nfrom flask import Flask\n\n"
            "app = Flask(__name__)\n\n\n"
            "def download(name):\n    return (Path('/srv') / name).read_text()\n\n\n"
            "app.add_url_rule('/d/<name>', view_func=download)\n",
        },
    )
    assert ("views.py", "download") in _reported(root)


def test_framework_handler_subclass_method_without_callers_is_kept(tmp_path):
    root = _project(
        tmp_path,
        {
            "server.py": "from pathlib import Path\n\nimport tornado.web\n\n\n"
            "class FileHandler(tornado.web.RequestHandler):\n"
            "    def serve(self, name):\n"
            "        return (Path('/srv') / name).read_text()\n",
        },
    )
    assert ("server.py", "serve") in _reported(root)


def test_helper_registered_as_a_callback_is_kept(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/plugins.py": "from app.reader import read_file\n\n"
            "HANDLERS = {'read': read_file}\n",
        },
    )
    assert ("reader.py", "read_file") in _reported(root)


def test_helper_dispatched_by_name_is_kept(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/dispatch.py": "from app import reader\n\n\n"
            "def run(action, arg):\n    return getattr(reader, 'read_file')(arg)\n",
        },
    )
    assert ("reader.py", "read_file") in _reported(root)


def test_argument_from_object_state_is_kept(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/job.py": "from app.reader import read_file\n\n\n"
            "class Job:\n"
            "    def __init__(self, name):\n        self.name = name\n\n"
            "    def run(self):\n        return read_file(self.name)\n",
        },
    )
    assert ("reader.py", "read_file") in _reported(root)


def test_same_name_on_another_module_is_not_a_caller(tmp_path):
    # ``json.load`` must not count as a call of the project's own ``load``,
    # which nothing calls, inside a module a framework imports.
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/files.py": "from pathlib import Path\n\nfrom flask import Flask\n\n"
            "app = Flask(__name__)\n\n\n"
            "def load(name):\n    return (Path('/srv') / name).read_text()\n",
            "app/config.py": "import json\n\n\n"
            "def read_config(handle):\n    return json.load(handle)\n",
        },
    )
    assert ("files.py", "load") in _reported(root)


def test_subdirectory_scan_keeps_findings(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/report.py": "from app.reader import read_file\n\n\n"
            "def build():\n    return read_file('summary.txt')\n",
        },
    )
    result = json.loads(analyze(str(root / "app"), enable_danger=True))
    assert any(
        f.get("symbol") == "read_file" and f.get("rule_id") in PATH_RULES
        for f in result.get("danger") or []
    )


# Adversarial cases from independent review: a visible safe call must not
# hide the caller that passes outside input.


def test_dispatch_by_computed_name_with_a_safe_test_call_is_kept(tmp_path):
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
            "tests/test_actions.py": "from app.actions import do_read\n\n\n"
            "def test_read():\n    assert do_read('README.md')\n",
        },
    )
    assert ("actions.py", "do_read") in _reported(root)


def test_module_state_set_by_a_route_is_kept(tmp_path):
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
    assert ("reader.py", "read_file") in _reported(root)


def test_cgi_environment_value_is_kept(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "cgi-bin/view.py": "import os\n\nfrom app.reader import read_file\n\n"
            "print(read_file(os.environ['QUERY_STRING']))\n",
        },
    )
    assert ("reader.py", "read_file") in _reported(root)
