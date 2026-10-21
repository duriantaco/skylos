"""Path findings on a production helper's parameter: what the callers show.

These cases first pinned that a helper finding stayed reported whatever its
visible callers passed, because an earlier cross-file "every caller is safe"
proof hid real traversals (dispatch by computed name, mutable module state,
CGI environment, subprocess argv). ``path_provenance`` now resolves the
callers and models those cases instead of trusting them: a finding is
reported when a resolved chain starts at untrusted input, and recorded as
``safe`` or ``unknown`` in ``suppressed`` otherwise. Unknown callers are
neither proof of an attack nor of safety, so they no longer produce a report.
The adversarial cases below still report; the others now assert the recorded
provenance, and each says why its expectation changed.
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


def _provenance(root: Path, name: str, symbol: str) -> list[dict]:
    """Provenance of the suppressed (not reported) path findings."""
    result = json.loads(analyze(str(root), enable_danger=True))
    assert not any(
        Path(f["file"]).name == name and f.get("symbol") == symbol
        for f in result.get("danger") or []
        if f.get("rule_id") in PATH_RULES
    )
    found = [
        f["metadata"]["path_provenance"]
        for f in result.get("suppressed") or []
        if f.get("rule_id") in PATH_RULES
        and Path(f["file"]).name == name
        and f.get("symbol") == symbol
    ]
    assert found
    return found


def _steps(provenance: dict, kind: str) -> list[str]:
    return [step for chain in provenance.get(kind, []) for step in chain]


# ------------------------------------- visible callers pass safe values


def test_helper_called_only_with_internal_values_is_not_reported(tmp_path):
    """Changed: the only caller passes a literal. ``read_file`` is public in
    the ``app`` package, so importers outside the project stay unknown; that
    is recorded, not reported.
    """
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/report.py": "from app.reader import read_file\n\n\n"
            "def build():\n    return read_file('summary.txt')\n",
        },
    )
    for provenance in _provenance(root, "reader.py", "read_file"):
        assert provenance["status"] == "unknown"
        assert "app/report.py:5 literal" in _steps(provenance, "safe")
        assert any("public in an importable package" in step for step in _steps(provenance, "unknown"))


def test_helper_called_with_cli_arguments_across_modules_is_not_reported(tmp_path):
    """Changed: argparse arguments are the operator's input, as for a direct
    ``open(args.name)`` in one file. No process launch in the project passes
    untrusted arguments (that case stays unknown, test_path_provenance.py).
    """
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
    for provenance in _provenance(root, "reader.py", "read_file"):
        assert provenance["status"] == "unknown"
        assert any("CLI arguments" in step for step in _steps(provenance, "operator"))


def test_chain_of_helpers_ending_in_internal_values_is_not_reported(tmp_path):
    """Changed: a hex digest joined to a literal cannot carry a path; the chain
    through ``load`` is followed and recorded.
    """
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
    for provenance in _provenance(root, "reader.py", "read_file"):
        assert not provenance.get("untrusted")
        assert any("hex digest from `hashlib.sha256.hexdigest`" in step for step in _steps(provenance, "safe"))


def test_method_run_in_an_executor_with_internal_values_is_not_reported(tmp_path):
    """Changed: ``POOL.submit(self.load, 'index.json')`` is followed as a call
    that passes a literal.
    """
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
    for provenance in _provenance(root, "store.py", "load"):
        assert not provenance.get("untrusted")
        assert "app/store.py:12 literal" in _steps(provenance, "safe")


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


def test_lambda_handler_shape_without_callers_is_not_reported(tmp_path):
    """Changed: an ``(event, context)`` signature alone does not show that a
    platform invokes it. A deployment file naming it as a handler does (test
    _path_closed_world.py::test_lambda_handler_named_only_in_terraform_is_ke
    pt).
    """
    root = _project(
        tmp_path,
        {
            "handler.py": "import os\n\n\n"
            "def handle(event, context):\n"
            "    return open(os.path.join('/var/task', event['file'])).read()\n",
        },
    )
    for provenance in _provenance(root, "handler.py", "handle"):
        assert provenance["status"] == "unknown"
        assert any("no call of `handle`" in step for step in _steps(provenance, "unknown"))


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


def test_framework_handler_subclass_method_without_callers_is_not_reported(tmp_path):
    """Changed: tornado calls ``get``/``post``... with URL arguments, which is
    reported below; ``serve`` has no caller, and what the external base may
    call stays unknown.
    """
    root = _project(
        tmp_path,
        {
            "server.py": "from pathlib import Path\n\nimport tornado.web\n\n\n"
            "class FileHandler(tornado.web.RequestHandler):\n"
            "    def serve(self, name):\n"
            "        return (Path('/srv') / name).read_text()\n",
        },
    )
    for provenance in _provenance(root, "server.py", "serve"):
        assert provenance["status"] == "unknown"
        assert any("extends `tornado.web.RequestHandler`" in step for step in _steps(provenance, "unknown"))


def test_framework_handler_verb_argument_is_kept(tmp_path):
    root = _project(
        tmp_path,
        {
            "server.py": "from pathlib import Path\n\nimport tornado.web\n\n\n"
            "class FileHandler(tornado.web.RequestHandler):\n"
            "    def get(self, name):\n"
            "        self.write(_read(name))\n\n\n"
            "def _read(name):\n"
            "    return (Path('/srv') / name).read_text()\n",
        },
    )
    assert ("server.py", "_read") in _reported(root)


def test_helper_registered_as_a_callback_is_not_reported(tmp_path):
    """Changed: the callers of a function stored in a table are not visible;
    the escape is recorded as unknown, not as an attack.
    """
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/plugins.py": "from app.reader import read_file\n\n"
            "HANDLERS = {'read': read_file}\n",
        },
    )
    for provenance in _provenance(root, "reader.py", "read_file"):
        assert provenance["status"] == "unknown"
        assert any("app/plugins.py:3 `read_file` is passed as a value" in step for step in _steps(provenance, "unknown"))


def test_helper_dispatched_by_name_is_not_reported(tmp_path):
    """Changed: ``getattr(reader, 'read_file')`` resolves to the helper, but
    ``run`` is never called, so what reaches ``arg`` is unknown. Dispatch
    with request data is reported (test_dispatch_by_computed_name_...).
    """
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/reader.py": READER,
            "app/dispatch.py": "from app import reader\n\n\n"
            "def run(action, arg):\n    return getattr(reader, 'read_file')(arg)\n",
        },
    )
    for provenance in _provenance(root, "reader.py", "read_file"):
        assert provenance["status"] == "unknown"
        assert any(step.startswith("app/dispatch.py:5 call `getattr(...)(...)` binds `name`") for step in _steps(provenance, "unknown"))


def test_argument_from_object_state_is_not_reported(tmp_path):
    """Changed: ``self.name`` is followed to ``Job.__init__``; nothing
    constructs a ``Job``, so its argument is unknown. A constructor called
    with request data is reported (test_path_provenance.py).
    """
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
    for provenance in _provenance(root, "reader.py", "read_file"):
        assert provenance["status"] == "unknown"
        assert any("assigns `self.name`" in step for step in _steps(provenance, "unknown"))


def test_same_name_on_another_module_is_not_a_caller(tmp_path):
    """Changed: with no caller the finding is unknown, recorded rather than
    reported.
    """
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
    for provenance in _provenance(root, "files.py", "load"):
        steps = _steps(provenance, "unknown") + _steps(provenance, "safe")
        assert not any(step.startswith("app/config.py") for step in steps)
        assert not provenance.get("untrusted")
        assert any("public in an importable package" in step for step in steps)


def test_subdirectory_scan_does_not_prove_safety(tmp_path):
    """Changed: a scan of part of the project cannot see every caller, so a
    literal-only caller leaves the finding unknown, not safe.
    """
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
    assert not any(
        f.get("symbol") == "read_file" and f.get("rule_id") in PATH_RULES
        for f in result.get("danger") or []
    )
    provenances = [
        f["metadata"]["path_provenance"]
        for f in result.get("suppressed") or []
        if f.get("symbol") == "read_file" and f.get("rule_id") in PATH_RULES
    ]
    assert provenances
    assert all(p["status"] == "unknown" and p["complete_project"] is False for p in provenances)


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
