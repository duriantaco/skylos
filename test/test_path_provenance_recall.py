"""Recall regressions from an independent review of ``path_provenance``.

Each case is a review fixture (r1041/review-path/fixtures) that the committed
baseline reported. Caller resolution must keep reporting it: Django
class-based views, FastAPI dependencies, JSON decoding of request, network or
downloaded data, lambdas, container aliases, Celery and RQ task arguments,
asyncio streams, ``recv_into`` buffers and long caller chains. A parameter
merely named ``request``/``req`` is followed to its real caller. Analysis
limits keep a finding as ``incomplete`` instead of hiding it.
"""

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink

PATH_RULES = {"SKY-D215", "SKY-D324", "SKY-D325", "SKY-D326"}
STORAGE = "from pathlib import Path\nBASE = Path('/srv/uploads')\ndef load(name):\n    return (BASE / name).read_text()\n"


def _project(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "proj"
    root.mkdir(parents=True)
    assert write_text_no_symlink(
        root / "pyproject.toml",
        '[project]\nname = "path-review-fixture"\nversion = "0.0.0"\n',
    )
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(path, text)
    return root


def _scan(root: Path) -> dict:
    return json.loads(analyze(str(root), enable_danger=True, grep_verify=False, conf=0))


def _reported(result: dict) -> dict[tuple[str, str], dict]:
    return {
        (Path(f["file"]).name, f["rule_id"]): f
        for f in result.get("danger") or []
        if f.get("rule_id") in PATH_RULES
    }


def _suppressed(result: dict) -> dict[tuple[str, str], dict]:
    return {
        (Path(f["file"]).name, f["rule_id"]): f
        for f in result.get("suppressed") or []
        if f.get("rule_id") in PATH_RULES
    }


APPS = {
    'x_django_cbv': (
        'from storage import load\n'
        'from django.views import View\n'
        'from django.urls import path\n'
        'from django.http import HttpResponse\n'
        '\n'
        'class FileView(View):\n'
        '    def get(self, request, slug):\n'
        '        return HttpResponse(load(slug))\n'
        "urlpatterns = [path('read/<path:slug>/', FileView.as_view())]\n"
    ),
    'x_django_cbv_kwargs': (
        'from storage import load\n'
        'from django.views import View\n'
        'from django.urls import path\n'
        'from django.http import HttpResponse\n'
        '\n'
        'class FileView(View):\n'
        '    def get(self, request, **kwargs):\n'
        "        return HttpResponse(load(self.kwargs['slug']))\n"
        "urlpatterns = [path('read/<path:slug>/', FileView.as_view())]\n"
    ),
    'x_fastapi_dependency_call': (
        'from storage import load\n'
        'from fastapi import FastAPI, Depends, Query\n'
        'app = FastAPI()\n'
        'def path_dep(name: str = Query(...)):\n'
        '    return load(name)\n'
        "@app.get('/read')\n"
        'def view(result: str = Depends(path_dep)):\n'
        '    return result\n'
    ),
    'x_fastapi_annotated_dep': (
        'from storage import load\n'
        'from typing import Annotated\n'
        'from fastapi import FastAPI, Depends, Query\n'
        'app = FastAPI()\n'
        'def path_dep(name: str = Query(...)):\n'
        '    return load(name)\n'
        "@app.get('/read')\n"
        'def view(result: Annotated[str, Depends(path_dep)]):\n'
        '    return result\n'
    ),
    'x_flask_json_loads': (
        'from storage import load\n'
        'import json\n'
        'from flask import Flask, request\n'
        'app = Flask(__name__)\n'
        "@app.post('/read')\n"
        'def view():\n'
        '    body = json.loads(request.data)\n'
        "    return load(body['name'])\n"
    ),
    'x_django_json_body': (
        'from storage import load\n'
        'import json\n'
        'from django.http import HttpResponse\n'
        'def view(request):\n'
        '    body = json.loads(request.body)\n'
        "    return HttpResponse(load(body['name']))\n"
    ),
    'x_http_json_loads': (
        'from storage import load\n'
        'import json\n'
        'import sys\n'
        'import urllib.request\n'
        'def main():\n'
        '    with urllib.request.urlopen(sys.argv[1]) as response:\n'
        '        manifest = json.loads(response.read())\n'
        "    return load(manifest['name'])\n"
        "if __name__ == '__main__':\n"
        '    main()\n'
    ),
    'x_http_file_json_load': (
        'from storage import load\n'
        'import json\n'
        'import sys\n'
        'import urllib.request\n'
        'def main():\n'
        '    filename, _ = urllib.request.urlretrieve(sys.argv[1])\n'
        '    with open(filename) as input_file:\n'
        '        manifest = json.load(input_file)\n'
        "    return load(manifest['name'])\n"
        "if __name__ == '__main__':\n"
        '    main()\n'
    ),
    'x_lambda': (
        'from storage import load\n'
        'from flask import Flask, request\n'
        'app = Flask(__name__)\n'
        'read = lambda name: load(name)\n'
        "@app.get('/read')\n"
        'def view():\n'
        "    return read(request.args['name'])\n"
    ),
    'x_lambda_inline': (
        'from storage import load\n'
        'from flask import Flask, request\n'
        'app = Flask(__name__)\n'
        "@app.get('/read')\n"
        'def view():\n'
        "    return (lambda name: load(name))(request.args['name'])\n"
    ),
    'x_dict_alias': (
        'from storage import load\n'
        'from flask import Flask, request\n'
        'app = Flask(__name__)\n'
        "@app.get('/read')\n"
        'def view():\n'
        '    data = {}\n'
        '    alias = data\n'
        "    alias['name'] = request.args['name']\n"
        "    return load(data['name'])\n"
    ),
    'x_list_alias': (
        'from storage import load\n'
        'from flask import Flask, request\n'
        'app = Flask(__name__)\n'
        "@app.get('/read')\n"
        'def view():\n'
        '    data = []\n'
        '    alias = data\n'
        "    alias.append(request.args['name'])\n"
        '    return load(data[0])\n'
    ),
    'x_celery_web': (
        'from storage import load\n'
        'from flask import Flask, request\n'
        'from celery import Celery\n'
        'app = Flask(__name__)\n'
        "celery = Celery('jobs')\n"
        '@celery.task\n'
        'def read_job(name):\n'
        '    return load(name)\n'
        "@app.post('/queue')\n"
        'def queue():\n'
        "    return read_job.delay(request.form['name'])\n"
    ),
    'x_rq_web': (
        'from storage import load\n'
        'from flask import Flask, request\n'
        'from rq import Queue\n'
        'app = Flask(__name__)\n'
        'q = Queue()\n'
        'def read_job(name):\n'
        '    return load(name)\n'
        "@app.post('/queue')\n"
        'def queue():\n'
        "    return q.enqueue(read_job, request.form['name'])\n"
    ),
    'x_asyncio_stream': (
        'from storage import load\n'
        'import asyncio\n'
        'async def receive():\n'
        "    reader, writer = await asyncio.open_connection('example.invalid', 80)\n"
        '    name = (await reader.readline()).decode().strip()\n'
        '    return load(name)\n'
    ),
    'x_socket_into': (
        'from storage import load\n'
        'import socket\n'
        'sock = socket.socket()\n'
        'def receive():\n'
        '    data = bytearray(4096)\n'
        '    size = sock.recv_into(data)\n'
        '    return load(data[:size].decode().strip())\n'
    ),
    'x_chain_13': (
        'from storage import load\n'
        'def layer_0(name):\n'
        '    return load(name)\n'
        'def layer_1(name):\n'
        '    return layer_0(name)\n'
        'def layer_2(name):\n'
        '    return layer_1(name)\n'
        'def layer_3(name):\n'
        '    return layer_2(name)\n'
        'def layer_4(name):\n'
        '    return layer_3(name)\n'
        'def layer_5(name):\n'
        '    return layer_4(name)\n'
        'def layer_6(name):\n'
        '    return layer_5(name)\n'
        'def layer_7(name):\n'
        '    return layer_6(name)\n'
        'def layer_8(name):\n'
        '    return layer_7(name)\n'
        'def layer_9(name):\n'
        '    return layer_8(name)\n'
        'def layer_10(name):\n'
        '    return layer_9(name)\n'
        'def layer_11(name):\n'
        '    return layer_10(name)\n'
        'def layer_12(name):\n'
        '    return layer_11(name)\n'
        'from flask import Flask, request\n'
        'app = Flask(__name__)\n'
        '@app.get("/read")\n'
        'def view():\n'
        '    return layer_12(request.args["name"])\n'
    ),
    'write_lambda': (
        'from pathlib import Path\n'
        'BASE = Path("/srv/uploads")\n'
        'from flask import Flask, request\n'
        'app = Flask(__name__)\n'
        'def save(name):\n'
        "    (BASE / name).write_text('data')\n"
        'write = lambda name: save(name)\n'
        "@app.post('/write')\n"
        'def view():\n'
        "    return write(request.form['name'])\n"
    ),
    'write_django_cbv': (
        'from pathlib import Path\n'
        'BASE = Path("/srv/uploads")\n'
        'from django.views import View\n'
        'from django.urls import path\n'
        'class FileView(View):\n'
        '    def post(self, request, slug):\n'
        '        return save(slug)\n'
        'def save(name):\n'
        "    (BASE / name).write_text('data')\n"
        "urlpatterns = [path('write/<path:slug>/', FileView.as_view())]\n"
    ),
}
SINK_FILE = {"write_lambda": "app.py", "write_django_cbv": "app.py"}
EXPECTED = {'x_django_cbv': 'SKY-D325', 'x_django_cbv_kwargs': 'SKY-D325', 'x_fastapi_dependency_call': 'SKY-D325', 'x_fastapi_annotated_dep': 'SKY-D325', 'x_flask_json_loads': 'SKY-D325', 'x_django_json_body': 'SKY-D325', 'x_http_json_loads': 'SKY-D325', 'x_http_file_json_load': 'SKY-D325', 'x_lambda': 'SKY-D325', 'x_lambda_inline': 'SKY-D325', 'x_dict_alias': 'SKY-D325', 'x_list_alias': 'SKY-D325', 'x_celery_web': 'SKY-D325', 'x_rq_web': 'SKY-D325', 'x_asyncio_stream': 'SKY-D325', 'x_socket_into': 'SKY-D325', 'x_chain_13': 'SKY-D325', 'write_lambda': 'SKY-D324', 'write_django_cbv': 'SKY-D324'}


@pytest.mark.parametrize("case", sorted(APPS))
def test_review_fixture_with_untrusted_input_is_reported(tmp_path, case):
    files = {"app.py": APPS[case]}
    if case not in SINK_FILE:
        files["storage.py"] = STORAGE
    result = _scan(_project(tmp_path, files))
    sink_file = SINK_FILE.get(case, "storage.py")
    reported = _reported(result)
    assert (sink_file, "SKY-D215") in reported
    finding = reported[(sink_file, EXPECTED[case])]
    assert finding["metadata"]["path_provenance"]["status"] == "untrusted"


def test_sixty_five_callers_with_the_unsafe_one_last_is_reported(tmp_path):
    calls = "".join(f"    load('static_{index}.txt')\n" for index in range(64))
    app = (
        "from storage import load\n"
        "def regular_calls():\n" + calls +
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.get('/read')\n"
        "def view():\n"
        "    return load(request.args['name'])\n"
    )
    result = _scan(_project(tmp_path, {"app.py": app, "storage.py": STORAGE}))
    assert ("storage.py", "SKY-D325") in _reported(result)


def test_chain_beyond_the_caller_depth_limit_is_kept_as_incomplete(tmp_path):
    layers = ["from storage import load\n", "def layer_0(name):\n    return load(name)\n"]
    for index in range(1, 40):
        layers.append(f"def layer_{index}(name):\n    return layer_{index - 1}(name)\n")
    layers.append("import sys\n\n\ndef main():\n    return layer_39(sys.argv[1])\n")
    result = _scan(_project(tmp_path, {"app.py": "".join(layers), "storage.py": STORAGE}))
    finding = _reported(result)[("storage.py", "SKY-D215")]
    provenance = finding["metadata"]["path_provenance"]
    assert provenance["status"] == "incomplete"
    assert any("caller depth limit" in chain[0] for chain in provenance["incomplete"])


def test_caller_file_over_the_size_budget_keeps_the_finding_incomplete(tmp_path):
    padding = "PADDING = '" + "x" * 2_100_000 + "'\n"
    app = (
        "from flask import request\n"
        "from storage import load\n" + padding +
        "def view():\n    return load(request.args['name'])\n"
    )
    result = _scan(_project(tmp_path, {"app.py": app, "storage.py": STORAGE}))
    finding = _reported(result)[("storage.py", "SKY-D215")]
    provenance = finding["metadata"]["path_provenance"]
    assert provenance["status"] == "incomplete"
    assert any("over the size budget" in chain[0] for chain in provenance["incomplete"])


@pytest.mark.parametrize("case", ["constant_param_named_request", "cli_param_named_req"])
def test_parameter_merely_named_request_is_followed_to_its_caller(tmp_path, case):
    app = CONTROLS[case]
    result = _scan(_project(tmp_path, {"app.py": app}))
    assert ("app.py", "SKY-D215") not in _reported(result)
    assert _suppressed(result)[("app.py", "SKY-D215")]["metadata"]["path_provenance"]["status"] == "safe"


CONTROLS = {
    'constant_param_named_request': (
        'from pathlib import Path\n'
        'BASE = Path("/srv/uploads")\n'
        'def read(request):\n'
        '    return (BASE / request).read_text()\n'
        'def main():\n'
        "    return read('manual.txt')\n"
        "if __name__ == '__main__':\n"
        '    main()\n'
    ),
    'cli_param_named_req': (
        'from pathlib import Path\n'
        'BASE = Path("/srv/uploads")\n'
        'import sys\n'
        'def read(req):\n'
        '    return (BASE / req).read_text()\n'
        'def main():\n'
        '    return read(sys.argv[1])\n'
        "if __name__ == '__main__':\n"
        '    main()\n'
    ),
}
UNPACK = (
        'import shutil\n'
        'from flask import Flask, request\n'
        'app = Flask(__name__)\n'
        "@app.post('/unpack')\n"
        'def upload():\n'
        "    request.files['archive'].save('/tmp/upload.zip')\n"
        "    shutil.unpack_archive('/tmp/upload.zip', '/srv/uploads')\n"
    )


def test_unpack_archive_of_an_upload_is_unsafe_extraction(tmp_path):
    result = _scan(_project(tmp_path, {"app.py": UNPACK}))
    assert ("app.py", "SKY-D326") in _reported(result)


def test_unpack_archive_with_the_data_filter_is_not_reported(tmp_path):
    app = UNPACK.replace("'/srv/uploads')", "'/srv/uploads', filter='data')")
    assert "filter='data'" in app
    result = _scan(_project(tmp_path, {"app.py": app}))
    assert ("app.py", "SKY-D326") not in _reported(result)


def test_allowlist_guard_is_void_after_the_name_is_rebound(tmp_path):
    files = {
        "storage.py": STORAGE,
        "app.py": (
            "from flask import abort, request\n"
            "from storage import load\n\n\n"
            "def view():\n"
            "    name = request.args['name']\n"
            "    if name not in {'index.txt'}:\n"
            "        abort(404)\n"
            "    name = request.args['other']\n"
            "    return load(name)\n"
        ),
    }
    assert ("storage.py", "SKY-D215") in _reported(_scan(_project(tmp_path, files)))


def test_allowlist_guard_that_reaches_the_call_is_safe(tmp_path):
    files = {
        "storage.py": STORAGE,
        "app.py": (
            "from flask import abort, request\n"
            "from storage import load\n\n\n"
            "def view():\n"
            "    name = request.args['name']\n"
            "    if name not in {'index.txt'}:\n"
            "        abort(404)\n"
            "    return load(name)\n"
        ),
    }
    assert ("storage.py", "SKY-D215") not in _reported(_scan(_project(tmp_path, files)))


def test_method_named_hexdigest_is_not_a_sanitizer_without_its_library(tmp_path):
    files = {
        "storage.py": STORAGE,
        "app.py": (
            "from flask import request\n"
            "from storage import load\n\n\n"
            "class Fake:\n"
            "    def __init__(self, value):\n        self.value = value\n\n"
            "    def hexdigest(self):\n        return self.value\n\n\n"
            "def view():\n    return load(Fake(request.args['name']).hexdigest())\n"
        ),
    }
    assert ("storage.py", "SKY-D215") in _reported(_scan(_project(tmp_path, files)))


def test_real_hash_digest_of_request_data_is_safe(tmp_path):
    files = {
        "storage.py": STORAGE,
        "app.py": (
            "import hashlib\n\nfrom flask import request\n"
            "from storage import load\n\n\n"
            "def view():\n    return load(hashlib.sha256(request.args['name'].encode()).hexdigest())\n"
        ),
    }
    result = _scan(_project(tmp_path, files))
    assert ("storage.py", "SKY-D215") not in _reported(result)


def test_command_of_a_project_click_group_is_operator_input(tmp_path):
    files = {
        "cli.py": (
            "import click\nfrom pathlib import Path\n\n\n"
            "@click.group()\ndef cli():\n    pass\n\n\n"
            "@cli.group()\ndef publish():\n    pass\n\n\n"
            "@cli.command()\n@click.argument('input_path')\n"
            "def show(input_path):\n    return Path(input_path).read_text()\n\n\n"
            "@publish.command()\n@click.argument('name')\n"
            "def write(name):\n    Path(name).write_text('x')\n"
        ),
    }
    result = _scan(_project(tmp_path, files))
    assert not {key for key in _reported(result) if key[0] == "cli.py"}
    assert _suppressed(result)[("cli.py", "SKY-D325")]["metadata"]["path_provenance"]["status"] == "safe"


def test_command_decorator_of_an_unresolved_bot_stays_reported(tmp_path):
    files = {
        "bot.py": (
            "from pathlib import Path\n\nfrom discord.ext import commands\n\n"
            "bot = commands.Bot(command_prefix='!')\n\n\n"
            "@bot.command()\nasync def show(ctx, name):\n    return (Path('/srv') / name).read_text()\n"
        ),
    }
    assert ("bot.py", "SKY-D215") in _reported(_scan(_project(tmp_path, files)))


def test_pytest_request_fixture_is_not_http_request_data(tmp_path):
    files = {
        "tests/test_files.py": (
            "def test_write(tmp_path, request):\n"
            "    target = tmp_path / request.node.name\n"
            "    target.write_text('x')\n"
            "    assert target.read_text() == 'x'\n"
        ),
    }
    result = _scan(_project(tmp_path, files))
    assert not {key for key in _reported(result) if key[0] == "test_files.py"}


def test_request_object_of_a_flask_route_stays_reported(tmp_path):
    files = {
        "views.py": (
            "from pathlib import Path\n\nfrom flask import Flask, request\n\n"
            "app = Flask(__name__)\n\n\n"
            "@app.get('/f')\ndef view():\n    return (Path('/srv') / request.args['name']).read_text()\n"
        ),
    }
    assert ("views.py", "SKY-D215") in _reported(_scan(_project(tmp_path, files)))


def test_path_without_any_source_is_traced_to_its_constructor(tmp_path):
    database = (
        "import os\n\n\n"
        "class Database:\n"
        "    def __init__(self, path):\n        self.path = path\n\n"
        "    def cleanup(self):\n"
        "        for suffix in ('', '-wal'):\n"
        "            os.unlink(self.path + suffix)\n"
    )
    safe = _scan(_project(tmp_path / "safe", {
        "db.py": database,
        "main.py": "from db import Database\n\n\ndef main():\n    Database('/var/lib/app.db').cleanup()\n",
    }))
    assert ("db.py", "SKY-D215") not in _reported(safe)
    assert _suppressed(safe)[("db.py", "SKY-D215")]["metadata"]["path_provenance"]["status"] == "safe"
    unsafe = _scan(_project(tmp_path / "unsafe", {
        "db.py": database,
        "main.py": "from flask import request\n\nfrom db import Database\n\n\n"
        "def view():\n    Database(request.args['db']).cleanup()\n",
    }))
    assert ("db.py", "SKY-D215") in _reported(unsafe)


def test_plugin_command_with_click_options_is_operator_input(tmp_path):
    files = {
        "plugin.py": (
            "import click\nfrom pathlib import Path\n\n\n"
            "def register(cli):\n"
            "    @cli.command()\n"
            "    @click.option('--output')\n"
            "    def export(output):\n"
            "        Path(output).write_text('x')\n"
        ),
    }
    result = _scan(_project(tmp_path, files))
    assert not {key for key in _reported(result) if key[0] == "plugin.py"}
