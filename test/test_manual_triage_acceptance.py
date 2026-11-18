"""Independent source-triage acceptance. Fixtures are parsed, never executed."""

import ast
import json
import textwrap

import pytest

from skylos.analyzer import analyze
from skylos.rules.danger.danger_fs import path_provenance
from test.fixture_paths import write_fixture


@pytest.fixture(autouse=True)
def _serial(monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")


def _scan(tmp_path, source, *, relative="app.py", extra=None):
    write_fixture(tmp_path, "pyproject.toml", '[project]\nname="acceptance"\n')
    for name, body in (extra or {}).items():
        write_fixture(tmp_path, name, textwrap.dedent(body))
    write_fixture(tmp_path, relative, textwrap.dedent(source))
    return json.loads(
        analyze(
            str(tmp_path), enable_danger=True, enable_quality=True, grep_verify=False
        )
    )


def _rows(report, rule, *, category="danger", symbol=None):
    return [
        row
        for row in report.get(category, [])
        if row["rule_id"] == rule and (symbol is None or row.get("symbol") == symbol)
    ]


def _visible(report, rule, *, symbol=None):
    rows = _rows(report, rule, symbol=symbol)
    assert rows, report.get("suppressed", [])
    expected = {
        "SKY-D215": "HIGH",
        "SKY-D324": "HIGH",
        "SKY-D325": "MEDIUM",
        "SKY-D216": "CRITICAL",
    }
    if rule in expected:
        assert all(row["severity"] == expected[rule] for row in rows)
    assert all(
        row.get("metadata", {}).get("path_provenance", {}).get("status") != "safe"
        for row in rows
    )
    return rows


def _safe(report, rule, *, symbol):
    assert not _rows(report, rule, symbol=symbol)
    rows = _rows(report, rule, category="suppressed", symbol=symbol)
    assert rows
    assert all(row["metadata"]["path_provenance"]["status"] == "safe" for row in rows)


def test_native_unittest_lifetime_reaches_fixture_helper(tmp_path):
    report = _scan(
        tmp_path,
        """
        import tempfile
        import unittest
        from pathlib import Path
        class CatalogTests(unittest.TestCase):
            def make_catalog(self, root):
                target = root / 'fixture' / 'manifest.json'
                target.parent.mkdir()
                target.write_text('{}')
            def test_catalog(self):
                with tempfile.TemporaryDirectory() as temporary:
                    self.make_catalog(Path(temporary))
        """,
        relative="tests/test_catalog.py",
    )
    _safe(report, "SKY-D324", symbol="make_catalog")


def test_unittest_inherited_acl_workspace_keeps_following_write(tmp_path):
    report = _scan(
        tmp_path,
        """
        import unittest
        import uuid
        from contextlib import contextmanager
        from pathlib import Path
        @contextmanager
        def workspace():
            root = Path(__file__).parent / ('fixture-' + uuid.uuid4().hex)
            root.mkdir()
            yield root
        class MarkerTests(unittest.TestCase):
            def write_marker(self, root):
                (root / 'supervisor-marker').write_text('{}')
            def test_marker(self):
                with workspace() as temporary:
                    self.write_marker(temporary)
        """,
        relative="tests/test_marker.py",
    )
    _visible(report, "SKY-D324", symbol="write_marker")


def test_native_fixture_call_does_not_hide_external_callback(tmp_path):
    report = _scan(
        tmp_path,
        """
        import tempfile
        import unittest
        from pathlib import Path
        import foreign
        def write_marker(root):
            (root / 'marker').write_text('{}')
        class MarkerTests(unittest.TestCase):
            def test_marker(self):
                with tempfile.TemporaryDirectory() as temporary:
                    write_marker(Path(temporary))
        foreign.register(write_marker)
        """,
        relative="tests/test_callback.py",
    )
    _visible(report, "SKY-D324", symbol="write_marker")


@pytest.mark.parametrize("access", ["os.O_RDONLY", "READ_ONLY"])
def test_optional_native_non_access_flags_do_not_create_write(tmp_path, access):
    report = _scan(
        tmp_path,
        "import os\nfrom os import O_RDONLY as READ_ONLY\n"
        "from flask import Flask, request\napp=Flask(__name__)\n"
        "@app.get('/read')\ndef inspect_file():\n"
        f"    flags = {access} | getattr(os, 'O_CLOEXEC', 0)\n"
        "    flags |= getattr(os, 'O_NOFOLLOW', 0)\n"
        "    descriptor = os.open(request.args['path'], flags)\n"
        "    try:\n        return os.read(descriptor, 8192)\n"
        "    finally:\n        os.close(descriptor)\n",
    )
    assert not _rows(report, "SKY-D324")
    _visible(report, "SKY-D215")
    # Optional NOFOLLOW cannot prove the flag exists on every platform.
    _visible(report, "SKY-D325")


@pytest.mark.parametrize(
    "replacement", ["os.O_RDONLY = foreign_flags", "os.O_NOFOLLOW = foreign_flags"]
)
def test_changed_optional_flag_provider_cannot_prove_access_mode(tmp_path, replacement):
    report = _scan(
        tmp_path,
        "import os\nfrom flask import Flask, request\napp=Flask(__name__)\n"
        + replacement
        + "\n@app.get('/read')\ndef inspect_file():\n"
        "    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)\n"
        "    descriptor = os.open(request.args['path'], flags)\n"
        "    return os.read(descriptor, 8192)\n",
    )
    _visible(report, "SKY-D324")
    _visible(report, "SKY-D325")


@pytest.mark.parametrize(
    ("operation", "read_expected"),
    [
        ("os.fsync(descriptor)", False),
        ("fcntl.flock(descriptor, fcntl.LOCK_EX)", False),
        ("os.read(descriptor, 8192)", True),
        ("foreign.consume(descriptor)", True),
        ("return descriptor", True),
    ],
)
def test_descriptor_observation_matches_actual_uses(tmp_path, operation, read_expected):
    report = _scan(
        tmp_path,
        "import os, fcntl, foreign\nfrom flask import Flask, request\n"
        "app=Flask(__name__)\n@app.get('/inspect')\ndef inspect_file():\n"
        "    descriptor = os.open(request.args['path'], os.O_RDONLY)\n"
        "    try:\n        " + operation + "\n"
        "    finally:\n        os.close(descriptor)\n",
    )
    _visible(report, "SKY-D215")
    if read_expected:
        _visible(report, "SKY-D325")
    else:
        assert not _rows(report, "SKY-D325")


FILTERED_REQUEST = """
from pathlib import Path
from fastapi import Body, FastAPI
from pydantic import BaseModel
app = FastAPI()
class Job(BaseModel):
    name: str = 'flight'
def component(raw):
    value = ''.join(c if c.isalnum() or c in ('-', '_') else '_' for c in raw)
    return value or 'flight'
@app.post('/read')
def read_job(payload: Job | None = Body(default=None)):
    job = payload or Job()
    return (Path('/srv') / component(job.name) / 'manifest.json').read_text()
"""


def test_actual_http_model_string_filter_only_removes_traversal(tmp_path):
    report = _scan(tmp_path, FILTERED_REQUEST)
    assert not _rows(report, "SKY-D215", symbol="read_job")
    _visible(report, "SKY-D325", symbol="read_job")


@pytest.mark.parametrize(
    "external",
    [
        "read_job(Job.model_construct(name=foreign.value()))",
        "read_job(Job.model_construct(name=Raw('fixture')))",
        "foreign.register(read_job)",
    ],
)
def test_http_model_proof_rejects_unvalidated_or_external_callers(tmp_path, external):
    report = _scan(
        tmp_path,
        FILTERED_REQUEST + "\nimport foreign\nclass Raw(str):\n"
        "    def __iter__(self):\n        yield Raw('../fixture')\n"
        "    def isalnum(self):\n        return True\n" + external + "\n",
    )
    _visible(report, "SKY-D215", symbol="read_job")


PID_PROGRAM = """
import json
import os
def positive_integer(payload, key):
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value
def process_alive(pid):
    with open(f'/proc/{pid}/stat', 'r', encoding='ascii') as stream:
        return stream.read(1024)
def inspect_marker(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        raw = os.read(descriptor, 4097)
    finally:
        os.close(descriptor)
    if len(raw) > 4096:
        return False
    payload = json.loads(raw.decode('utf-8'))
    if not isinstance(payload, dict):
        return False
    pid = positive_integer(payload, 'supervisorPid')
    if pid is None:
        return False
    return process_alive(pid)
inspect_marker('/srv/supervisor-marker')
"""


def test_bounded_native_json_positive_pid_has_fixed_procfs_path(tmp_path):
    report = _scan(tmp_path, PID_PROGRAM)
    _safe(report, "SKY-D215", symbol="process_alive")
    # Fixed procfs spelling alone is not a native mount/no-symlink proof.
    _visible(report, "SKY-D325", symbol="process_alive")


@pytest.mark.parametrize(
    "mutation", ["external-caller", "json-provider", "string-field"]
)
def test_pid_shape_proof_does_not_generalize_to_other_sources(tmp_path, mutation):
    source = PID_PROGRAM
    if mutation == "external-caller":
        source += "\nimport foreign\nforeign.register(process_alive)\n"
    elif mutation == "json-provider":
        source = source.replace(
            "import os\n", "import os\nimport foreign\njson.loads=foreign.decode\n"
        )
    else:
        source = source.replace(
            "if isinstance(value, bool) or not isinstance(value, int) or value <= 0:",
            "if not isinstance(value, str):",
        )
    report = _scan(tmp_path, source)
    _visible(report, "SKY-D215", symbol="process_alive")


@pytest.mark.parametrize("source", ["os.environ['READ_PATH']", "sys.argv[1]"])
@pytest.mark.parametrize("forwarded", [False, True])
def test_late_http_transport_requires_actual_operator_source_control(
    tmp_path, source, forwarded
):
    worker = (
        "import os, sys\ndef load():\n    return open(" + source + ").read()\nload()\n"
    )
    if forwarded:
        arguments = "[sys.executable, 'a_worker.py', path]"
        keywords = ""
        if source.startswith("os.environ"):
            arguments = "[sys.executable, 'a_worker.py']"
            keywords = ", env={'READ_PATH': path}"
        launcher = (
            "import subprocess, sys\nfrom fastapi import FastAPI\napp=FastAPI()\n"
            "@app.post('/read')\ndef read_route(path: str):\n"
            "    return subprocess.run(" + arguments + keywords + ")\n"
        )
    else:
        launcher = (
            "from a_worker import load\nfrom fastapi import FastAPI\napp=FastAPI()\n"
            "@app.get('/read')\ndef read_route():\n    return load()\n"
        )
    report = _scan(
        tmp_path, worker, relative="a_worker.py", extra={"z_routes.py": launcher}
    )
    if forwarded:
        _visible(report, "SKY-D215", symbol="load")
    else:
        assert not _rows(report, "SKY-D215", symbol="load")


def test_resolution_exhaustion_never_promotes_partial_source_to_safe(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(path_provenance, "_MAX_RESOLUTION_WORK", 24)
    source = (
        "from pathlib import Path\n"
        "def f0(name):\n    return (Path('/srv') / name).read_text()\n"
        + "".join(
            f"def f{index}(f{index - 1}):\n    return f{index - 1}\n"
            for index in range(1, 20)
        )
    )
    report = _scan(tmp_path, source)
    rows = _visible(report, "SKY-D215", symbol="f0")
    assert any(
        row["metadata"]["path_provenance"]["status"] == "incomplete" for row in rows
    )


def test_recursive_source_resolution_remains_visible(tmp_path):
    report = _scan(
        tmp_path,
        "def first(value):\n    return open(second(value)).read()\n"
        "def second(value):\n    return first(value)\n",
    )
    _visible(report, "SKY-D215", symbol="first")


@pytest.mark.parametrize("http", [False, True])
def test_operator_url_and_http_url_have_distinct_ssrf_results(tmp_path, http):
    source = (
        "import argparse\nimport requests\n"
        "def main():\n    parser=argparse.ArgumentParser()\n"
        "    parser.add_argument('--url')\n    args=parser.parse_args()\n"
        "    return requests.get(args.url, timeout=5)\nmain()\n"
    )
    if http:
        source = (
            "import requests\nfrom fastapi import FastAPI\napp=FastAPI()\n"
            "@app.get('/fetch')\ndef fetch(url: str):\n"
            "    return requests.get(url, timeout=5)\n"
        )
    report = _scan(tmp_path, source)
    if http:
        _visible(report, "SKY-D216")
    else:
        assert not _rows(report, "SKY-D216")


@pytest.mark.parametrize("http_source", [False, True])
def test_repository_ast_and_request_ast_have_distinct_exec_results(
    tmp_path, http_source
):
    source = (
        "import ast\nfrom pathlib import Path\n"
        "SOURCE=Path(__file__).parent / 'core.py'\n"
        "def load():\n    tree=ast.parse(SOURCE.read_text())\n"
        "    exec(compile(tree, str(SOURCE), 'exec'), {})\nload()\n"
    )
    if http_source:
        source = (
            "import ast\nfrom fastapi import FastAPI\napp=FastAPI()\n"
            "@app.post('/load')\ndef load(code: str):\n"
            "    tree=ast.parse(code)\n"
            "    exec(compile(tree, 'request', 'exec'), {})\n"
        )
    report = _scan(tmp_path, source, extra={"core.py": "VALUE=1\n"})
    if http_source:
        _visible(report, "SKY-D202")
    else:
        assert not _rows(report, "SKY-D202")


@pytest.mark.parametrize("effect", [False, True])
def test_control_named_preview_requires_actual_effect_for_critical_auth(
    tmp_path, effect
):
    body = "    return {'target': radius, 'command': 'preview'}\n"
    if effect:
        body = (
            "    bridge.mav.command_long_send(1, 1, 400, 0, radius, 0, 0, 0, 0, 0, 0)\n"
            + body
        )
    report = _scan(
        tmp_path,
        "from fastapi import FastAPI\napp=FastAPI()\n"
        "@app.post('/control/orbit/preview')\n"
        "def orbit_preview(radius: float):\n" + body,
    )
    if effect:
        _visible(report, "SKY-D283")
    else:
        assert not _rows(report, "SKY-D283")


@pytest.mark.parametrize("http_callback", [False, True])
def test_forwarded_argparse_url_proof_tracks_callback_sources(tmp_path, http_callback):
    source = (
        "import argparse, os, requests\n"
        "def positive_float(raw):\n"
        "    value=float(raw)\n    if value <= 0:\n        raise ValueError()\n"
        "    return value\n"
        "def fetch(url, timeout):\n    return requests.get(url, timeout=timeout)\n"
        "def main():\n    parser=argparse.ArgumentParser()\n"
        "    parser.add_argument('--url', default=os.getenv('API_URL'))\n"
        "    parser.add_argument('--timeout', type=positive_float, default=5.0)\n"
        "    args=parser.parse_args()\n    return fetch(args.url, args.timeout)\n"
        "main()\n"
    )
    if http_callback:
        source = source.replace(
            "def positive_float(raw):",
            "from flask import request\n"
            "class RemoteAction(argparse.Action):\n"
            "    def __call__(self, parser, namespace, values, option_string=None):\n"
            "        namespace.url=request.args['url']\n"
            "def positive_float(raw):",
        )
        source = source.replace(
            "'--url', default=", "'--url', action=RemoteAction, default="
        )
    report = _scan(tmp_path, source)
    if http_callback:
        _visible(report, "SKY-D216")
    else:
        assert not _rows(report, "SKY-D216")


def test_late_http_url_does_not_inherit_operator_only_classification(tmp_path):
    report = _scan(
        tmp_path,
        "import argparse, requests\n"
        "parser=argparse.ArgumentParser()\n"
        "parser.add_argument('--url')\nargs=parser.parse_args()\n"
        "def fetch(url):\n    return requests.get(url or args.url, timeout=5)\n"
        "from fastapi import FastAPI\napp=FastAPI()\n"
        "@app.get('/fetch')\ndef fetch_route(url: str):\n    return fetch(url)\n",
    )
    _visible(report, "SKY-D216")


def test_project_source_written_by_http_is_not_owned_exec_proof(tmp_path):
    report = _scan(
        tmp_path,
        "import ast\nfrom pathlib import Path\n"
        "SOURCE=Path(__file__).parent / 'core.py'\n"
        "def load():\n    tree=ast.parse(SOURCE.read_text())\n"
        "    exec(compile(tree, str(SOURCE), 'exec'), {})\nload()\n",
        extra={
            "core.py": "VALUE=1\n",
            "writer.py": """
                from pathlib import Path
                from fastapi import FastAPI
                app=FastAPI()
                @app.post('/source')
                def replace_source(code: str):
                    (Path(__file__).parent / 'core.py').write_text(code)
                """,
        },
    )
    _visible(report, "SKY-D202")


@pytest.mark.parametrize("kind", ["pure", "dispatch", "unknown"])
def test_preview_method_source_effects_control_auth_conclusion(tmp_path, kind):
    source = (
        "from fastapi import FastAPI\napp=FastAPI()\n"
        "class Controller:\n"
        "    def preview(self, radius):\n"
        "        return {'radius': radius, 'state': 'preview'}\n"
        "controller=Controller()\n"
        "@app.post('/control/orbit/preview')\n"
        "def orbit_preview(radius: float):\n    return controller.preview(radius)\n"
    )
    if kind == "dispatch":
        source = source.replace(
            "        return {'radius':",
            "        bridge.mav.command_long_send(1, 1, 400, 0, radius, 0, 0, 0, 0, 0, 0)\n"
            "        return {'radius':",
        )
    elif kind == "unknown":
        source = source.replace(
            "controller=Controller()", "import foreign\ncontroller=foreign.factory()"
        )
    report = _scan(tmp_path, source)
    if kind == "pure":
        assert not _rows(report, "SKY-D283")
    else:
        _visible(report, "SKY-D283")


@pytest.mark.parametrize(
    "change",
    [
        "foreign.mutate([payload])",
        "box = [payload]\n    foreign.mutate(box)",
        "box = {'value': payload}\n    foreign.mutate(box)",
        "holder.value = payload\n    foreign.mutate(holder)",
        "alias = payload\n    alias['supervisorPid'] = foreign.value()",
    ],
)
def test_json_domain_proof_rejects_container_escape_and_mutation(tmp_path, change):
    source = PID_PROGRAM.replace("import os\n", "import os\nimport foreign\n")
    source = source.replace(
        "    pid = positive_integer(payload, 'supervisorPid')",
        "    " + change + "\n    pid = positive_integer(payload, 'supervisorPid')",
    )
    report = _scan(tmp_path, source)
    _visible(report, "SKY-D215", symbol="process_alive")


def test_json_domain_proof_rejects_decoder_hooks(tmp_path):
    source = PID_PROGRAM.replace("import os\n", "import os\nimport foreign\n")
    source = source.replace(
        "json.loads(raw.decode('utf-8'))",
        "json.loads(raw.decode('utf-8'), parse_int=foreign.decode)",
    )
    _visible(_scan(tmp_path, source), "SKY-D215", symbol="process_alive")


def test_json_domain_proof_rejects_nested_local_container_mutation(tmp_path):
    change = """
class FormattedInt(int):
    def __format__(self, spec):
        return 'non_numeric/component'
def replace_nested(box):
    box[0]['supervisorPid'] = FormattedInt(1)
"""
    source = PID_PROGRAM.replace(
        "def process_alive(pid):", change + "\ndef process_alive(pid):"
    )
    source = source.replace(
        "    pid = positive_integer(payload, 'supervisorPid')",
        "    replace_nested([payload])\n    pid = positive_integer(payload, 'supervisorPid')",
    )
    _visible(_scan(tmp_path, source), "SKY-D215", symbol="process_alive")


@pytest.mark.parametrize(
    "escape",
    [
        "foreign.consume(self)",
        "foreign.consume([self])",
        "foreign.consume({'fixture': self})",
        "box = [self]\n        foreign.consume(box)",
        "callback = lambda: self\n        foreign.consume(callback)",
    ],
)
def test_native_testcase_contract_rejects_nested_instance_escape(tmp_path, escape):
    from skylos.rules.danger.danger_fs.path_test_context import native_testcase

    source = (
        "import unittest, foreign\n"
        "class Files(unittest.TestCase):\n"
        "    def test_fixture(self):\n        " + escape + "\n"
    )
    path = write_fixture(tmp_path, "test_files.py", source)
    project = path_provenance._Project(tmp_path, complete=True)
    project._add_python(path, source)
    project._index()
    cls = next(
        node for node in project.units[0].tree.body if isinstance(node, ast.ClassDef)
    )
    assert not native_testcase(project, cls)


@pytest.mark.parametrize("patched", [False, True])
def test_write_only_fdopen_observation_requires_native_io_dependency(tmp_path, patched):
    source = (
        "import os, io\nfrom flask import Flask, request\n"
        "app=Flask(__name__)\n"
        "@app.get('/write')\ndef update():\n"
        "    descriptor=os.open(request.args['path'], os.O_RDWR)\n"
        "    with os.fdopen(descriptor, 'wb') as stream:\n"
        "        stream.write(b'fixture')\n"
    )
    if patched:
        source = source.replace(
            "app=Flask(__name__)\n",
            "app=Flask(__name__)\nimport foreign\nio.open=foreign.open\n",
        )
    report = _scan(tmp_path, source)
    _visible(report, "SKY-D324")
    if patched:
        _visible(report, "SKY-D325")
    else:
        assert not _rows(report, "SKY-D325")


@pytest.mark.parametrize("hook", ["run", "__getattribute__", "_callTestMethod"])
def test_native_testcase_contract_rejects_assigned_dispatch_hook(tmp_path, hook):
    from skylos.rules.danger.danger_fs.path_test_context import native_testcase

    source = (
        "import unittest, foreign\nclass Files(unittest.TestCase):\n"
        f"    {hook} = foreign.dispatch\n"
        "    def test_fixture(self):\n        pass\n"
    )
    path = write_fixture(tmp_path, "test_files.py", source)
    project = path_provenance._Project(tmp_path, complete=True)
    project._add_python(path, source)
    project._index()
    cls = next(
        node for node in project.units[0].tree.body if isinstance(node, ast.ClassDef)
    )
    assert not native_testcase(project, cls)


@pytest.mark.parametrize(
    "replacement",
    ["controller.preview=foreign.preview", "foreign.register(controller)"],
)
def test_preview_effect_proof_rejects_receiver_mutation_and_escape(
    tmp_path, replacement
):
    report = _scan(
        tmp_path,
        "from fastapi import FastAPI\nimport foreign\napp=FastAPI()\n"
        "class Controller:\n    def preview(self, radius):\n"
        "        return {'radius': radius}\ncontroller=Controller()\n"
        + replacement
        + "\n"
        "@app.post('/control/orbit/preview')\n"
        "def orbit_preview(radius: float):\n    return controller.preview(radius)\n",
    )
    _visible(report, "SKY-D283")


@pytest.mark.parametrize("decorator", ["staticmethod", "classmethod"])
def test_native_testcase_contract_rejects_replaced_descriptor_provider(
    tmp_path, decorator
):
    from skylos.rules.danger.danger_fs.path_test_context import native_testcase

    source = (
        "import unittest, builtins, foreign\n"
        f"builtins.{decorator}=foreign.decorate\n"
        "class Files(unittest.TestCase):\n"
        f"    @{decorator}\n"
        "    def make_file(root):\n        pass\n"
        "    def test_fixture(self):\n        pass\n"
    )
    path = write_fixture(tmp_path, "test_files.py", source)
    project = path_provenance._Project(tmp_path, complete=True)
    project._add_python(path, source)
    project._index()
    cls = next(
        node for node in project.units[0].tree.body if isinstance(node, ast.ClassDef)
    )
    assert not native_testcase(project, cls)


def test_private_temp_object_escape_does_not_prove_its_later_name(tmp_path):
    report = _scan(
        tmp_path,
        """
        import unittest, tempfile, foreign
        from pathlib import Path
        class Files(unittest.TestCase):
            def setUp(self):
                self.tmp = tempfile.TemporaryDirectory()
                self.addCleanup(self.tmp.cleanup)
                foreign.configure(self.tmp)
                self.root = Path(self.tmp.name)
            def save(self, root):
                (root / 'marker').write_text('{}')
            def test_fixture(self):
                self.save(self.root)
        """,
        relative="tests/test_temp_escape.py",
    )
    _visible(report, "SKY-D324", symbol="save")


@pytest.mark.parametrize("name", ["gettempdir", "mktemp"])
def test_temp_name_alone_is_not_private_write_proof(tmp_path, name):
    report = _scan(
        tmp_path,
        "import tempfile\nfrom pathlib import Path\n"
        'def save(path):\n    path.write_text("fixture")\n'
        f'save(Path(tempfile.{name}()) / "fixture-marker")\n',
    )
    _visible(report, "SKY-D324", symbol="save")


@pytest.mark.parametrize(
    "changed",
    [
        "routing.APIRoute.get_route_handler=foreign.handler",
        "routing.get_request_handler=foreign.handler",
        "from pydantic import TypeAdapter\nTypeAdapter.validate_python=foreign.validate",
    ],
)
def test_preview_scalar_contract_requires_native_route_handler_dependency(
    tmp_path, changed
):
    source = (
        "from fastapi import FastAPI, routing\nimport foreign\n"
        + changed
        + "\napp=FastAPI()\n"
        "class Controller:\n    def preview(self, radius):\n"
        "        return {'radius': radius+1}\ncontroller=Controller()\n"
        "@app.post('/control/orbit/preview')\n"
        "def orbit_preview(radius: float):\n    return controller.preview(radius)\n"
    )
    _visible(_scan(tmp_path, source), "SKY-D283")


def test_captured_temp_context_must_be_live_at_callback_invocation(tmp_path):
    report = _scan(
        tmp_path,
        "import tempfile\nfrom pathlib import Path\n"
        'def save(path):\n    path.write_text("fixture")\n'
        "with tempfile.TemporaryDirectory() as temporary:\n"
        "    def callback():\n"
        '        save(Path(temporary) / "fixture-marker")\n'
        "callback()\n",
    )
    _visible(report, "SKY-D324", symbol="save")


def test_native_testcase_selected_method_uses_its_unsafe_default(tmp_path):
    report = _scan(
        tmp_path,
        """
        import unittest, tempfile
        from pathlib import Path
        class Files(unittest.TestCase):
            def save(self, root=Path(tempfile.gettempdir())):
                (root / 'fixture-marker').write_text('fixture')
            def test_fixture(self):
                with tempfile.TemporaryDirectory() as temporary:
                    self.save(Path(temporary))
        Files('save').run()
        """,
        relative="tests/test_selected.py",
    )
    _visible(report, "SKY-D324", symbol="save")


@pytest.mark.parametrize(
    "replacement",
    [
        "from pydantic import TypeAdapter\nTypeAdapter.validate_python=foreign.validate",
        "from fastapi import routing\nrouting.get_request_handler=foreign.handler",
    ],
)
def test_filename_http_string_proof_requires_unchanged_validation_dependency(
    tmp_path, replacement
):
    source = FILTERED_REQUEST.replace(
        "app = FastAPI()", "import foreign\n" + replacement + "\napp = FastAPI()"
    )
    _visible(_scan(tmp_path, source), "SKY-D215", symbol="read_job")


@pytest.mark.parametrize(
    "replacement",
    [
        "json.JSONDecoder.decode=foreign.decode",
        "json._default_decoder=foreign.decoder",
    ],
)
def test_json_scalar_domain_requires_native_default_decoder_dependency(
    tmp_path, replacement
):
    source = PID_PROGRAM.replace(
        "import os\n", "import os\nimport foreign\n" + replacement + "\n"
    )
    _visible(_scan(tmp_path, source), "SKY-D215", symbol="process_alive")


def test_returned_temp_path_is_not_private_after_producer_exits(tmp_path):
    report = _scan(
        tmp_path,
        "import tempfile\nfrom pathlib import Path\n"
        'def save(path):\n    path.write_text("fixture")\n'
        "def make_path():\n"
        "    with tempfile.TemporaryDirectory() as temporary:\n"
        '        return Path(temporary) / "fixture-marker"\n'
        "save(make_path())\n",
    )
    _visible(report, "SKY-D324", symbol="save")


@pytest.mark.parametrize("open_root", [False, True])
def test_private_temp_ancestor_survives_child_mode_but_not_root_mode_change(
    tmp_path, open_root
):
    change = (
        "target=root\n" if open_root else 'target=root / "child"\n    target.mkdir()\n'
    )
    report = _scan(
        tmp_path,
        "import tempfile\nfrom pathlib import Path\n"
        'def save(path):\n    path.write_text("fixture")\n'
        "with tempfile.TemporaryDirectory() as temporary:\n"
        "    root=Path(temporary)\n    "
        + change
        + '    target.chmod(0o777)\n    save(target / "fixture-marker")\n',
    )
    if open_root:
        _visible(report, "SKY-D324", symbol="save")
    else:
        _safe(report, "SKY-D324", symbol="save")


@pytest.mark.parametrize(("mode", "rule"), [("w", "SKY-D324"), ("r", "SKY-D325")])
def test_numeric_http_component_proves_shape_but_not_symlink_ownership(
    tmp_path, mode, rule
):
    report = _scan(
        tmp_path,
        "from pathlib import Path\nfrom fastapi import FastAPI\napp=FastAPI()\n"
        f"def operate(path):\n    return open(path, {mode!r})\n"
        "@app.post('/file')\ndef route(identifier: str):\n"
        '    return operate(Path("/srv") / str(int(identifier)) / "record")\n',
    )
    assert not _rows(report, "SKY-D215", symbol="operate")
    _visible(report, rule, symbol="operate")


@pytest.mark.parametrize(
    "component",
    [
        "f'{int(identifier):{layout}}'",
        "f'{int(identifier):/>8}'",
    ],
)
def test_numeric_shape_does_not_ignore_path_changing_format_spec(tmp_path, component):
    report = _scan(
        tmp_path,
        "from pathlib import Path\nfrom fastapi import FastAPI\napp=FastAPI()\n"
        "def operate(path):\n    return open(path).read()\n"
        "@app.post('/file')\ndef route(identifier: str, layout: str):\n"
        '    return operate(Path("/srv") / ' + component + ' / "record")\n',
    )
    _visible(report, "SKY-D215", symbol="operate")


LIFETIME_CASE = """
import unittest, tempfile
from pathlib import Path
class Files(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
    def save(self, name):
        (self.root / name).write_text('fixture')
    def test_fixture(self):
        self.save('marker')
"""


@pytest.mark.parametrize("manual_cleanup", [False, True])
def test_native_testcase_manual_instance_cannot_borrow_live_framework_fixture(
    tmp_path, manual_cleanup
):
    source = LIFETIME_CASE
    if manual_cleanup:
        source += (
            "\ncase=Files()\ncase.setUp()\ncase.tmp.cleanup()\ncase.save('marker')\n"
        )
    report = _scan(tmp_path, source, relative="tests/test_manual_lifetime.py")
    if manual_cleanup:
        _visible(report, "SKY-D324", symbol="save")
    else:
        _safe(report, "SKY-D324", symbol="save")


@pytest.mark.parametrize("invoke_cleanup", [False, True])
def test_native_testcase_bound_cleanup_alias_preserves_lifetime_order(
    tmp_path, invoke_cleanup
):
    source = LIFETIME_CASE.replace(
        "self.addCleanup(self.tmp.cleanup)",
        "cleanup=self.tmp.cleanup\n        self.addCleanup(cleanup)"
        + ("\n        cleanup()" if invoke_cleanup else ""),
    )
    report = _scan(tmp_path, source, relative="tests/test_alias_lifetime.py")
    if invoke_cleanup:
        _visible(report, "SKY-D324", symbol="save")
    else:
        _safe(report, "SKY-D324", symbol="save")
