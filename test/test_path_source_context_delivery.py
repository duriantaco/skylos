"""Source-context acceptance: fixtures are parsed, never executed."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.rules.danger.danger import scan_ctx
from skylos.rules.danger.danger_fs import path_provenance


def _scan(tmp_path, sources):
    (tmp_path / ".git").mkdir()
    (tmp_path / "pyproject.toml").write_text('[project]\nname="source-context"\n')
    files = []
    for name, text in sources.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        files.append(target)
    if all(name.startswith("tests/") for name in sources):
        suppressed = []
        visible = path_provenance.resolve_helper_parameter_findings(
            scan_ctx(tmp_path, files),
            scan_path=tmp_path,
            project_root=tmp_path,
            suppressed=suppressed,
        )
        return visible, suppressed
    result = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            grep_verify=False,
            grep_cache=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not result.get("analysis_errors")
    return result.get("danger", []), result.get("suppressed", [])


def _matching(rows, rule, symbol):
    return [
        row for row in rows if row["rule_id"] == rule and row.get("symbol") == symbol
    ]


def _quiet(visible, suppressed, rule, symbol):
    assert not _matching(visible, rule, symbol), _matching(visible, rule, symbol)
    matched = _matching(suppressed, rule, symbol)
    assert matched and all(
        row["metadata"]["path_provenance"]["status"] == "safe" for row in matched
    )


def _kept(visible, suppressed, rule, symbol):
    assert _matching(visible, rule, symbol)
    assert not _matching(suppressed, rule, symbol)


@pytest.mark.parametrize(
    ("component", "safe"),
    [
        ("f'{int(identifier)}'", True),
        ("f'{int(identifier):08d}'", True),
        ("f'{int(identifier):c}'", False),
        ("'{:c}'.format(int(identifier))", False),
        ("'{:/>8}'.format(int(identifier))", False),
        ("format(int(identifier), 'c')", False),
        ("'%c' % int(identifier)", False),
        ("'%08d' % int(identifier)", True),
    ],
)
def test_numeric_filename_shape_covers_formatting_semantics(tmp_path, component, safe):
    visible, suppressed = _scan(
        tmp_path,
        {
            "app.py": "from pathlib import Path\nfrom fastapi import FastAPI\napp=FastAPI()\n"
            "def load(path):\n    return open(path).read()\n"
            "@app.post('/load')\ndef route(identifier: str):\n"
            f"    return load(Path('/srv') / ({component}) / 'record')\n"
        },
    )
    (_quiet if safe else _kept)(visible, suppressed, "SKY-D215", "load")


@pytest.mark.parametrize(
    "replacement", ["builtins.int", "builtins.str", "pathlib.Path"]
)
def test_replaced_numeric_provider_does_not_prove_filename_shape(tmp_path, replacement):
    visible, suppressed = _scan(
        tmp_path,
        {
            "app.py": "import builtins, foreign, pathlib\nfrom pathlib import Path\n"
            "from fastapi import FastAPI\napp=FastAPI()\n"
            + f"{replacement}=foreign.convert\n"
            "def load(path):\n    return open(path).read()\n"
            "@app.post('/load')\ndef route(identifier: str):\n"
            "    return load(Path('/srv') / str(int(identifier)) / 'record')\n"
        },
    )
    _kept(visible, suppressed, "SKY-D215", "load")


def test_one_numeric_callable_alternative_cannot_certify_another(tmp_path):
    visible, suppressed = _scan(
        tmp_path,
        {
            "app.py": "from pathlib import Path\nfrom fastapi import FastAPI\napp=FastAPI()\n"
            "def passthrough(value):\n    return value\n"
            "def load(path):\n    return open(path).read()\n"
            "@app.post('/load')\ndef route(identifier: str, numeric: bool):\n"
            "    convert=int if numeric else passthrough\n"
            "    return load(Path('/srv') / str(convert(identifier)) / 'record')\n"
        },
    )
    _kept(visible, suppressed, "SKY-D215", "load")


@pytest.mark.parametrize("child", [False, True])
@pytest.mark.parametrize("binding", ["from os import chmod as widen\n", ""])
@pytest.mark.parametrize("lifetime", ["context", "object"])
def test_temp_root_mode_aliases_do_not_borrow_child_ancestor_proof(
    tmp_path, child, binding, lifetime
):
    target = 'root / "child"' if child else "root"
    setup = "    target.mkdir()\n" if child else ""
    mode_change = (
        "    widen(target, 0o777)\n"
        if binding
        else "    widen=target.chmod\n    widen(0o777)\n"
    )
    allocation = (
        "with tempfile.TemporaryDirectory() as temporary:\n    root=Path(temporary)\n"
        if lifetime == "context"
        else "def main():\n    directory=tempfile.TemporaryDirectory()\n    root=Path(directory.name)\n"
    )
    visible, suppressed = _scan(
        tmp_path,
        {
            "app.py": "import tempfile\nfrom pathlib import Path\n"
            + binding
            + "def save(path):\n    path.write_text('fixture')\n"
            + allocation
            + f"    target={target}\n"
            + setup
            + mode_change
            + "    save(target / 'record')\n"
            + ("main()\n" if lifetime == "object" else "")
        },
    )
    (_quiet if child else _kept)(visible, suppressed, "SKY-D324", "save")


@pytest.mark.parametrize(
    "effect",
    [
        "os.chmod(path=root, mode=0o777)",
        "os.replace(Path('/srv/replacement'), root)",
        "Path('/srv/replacement').replace(root)",
        "widen(root)",
        "foreign.configure(root)",
        "foreign.configure(root / 'child')",
    ],
)
def test_private_temp_root_effects_require_argument_transport_proof(tmp_path, effect):
    visible, suppressed = _scan(
        tmp_path,
        {
            "app.py": "import os, tempfile, foreign\nfrom pathlib import Path\n"
            "def save(path):\n    path.write_text('fixture')\n"
            "def widen(path):\n    path.chmod(0o777)\n"
            "with tempfile.TemporaryDirectory() as temporary:\n"
            "    root=Path(temporary)\n"
            f"    {effect}\n"
            "    save(root / 'record')\n"
        },
    )
    _kept(visible, suppressed, "SKY-D324", "save")


def test_mutable_temp_directory_alias_names_share_root_identity(tmp_path):
    visible, suppressed = _scan(
        tmp_path,
        {
            "app.py": "import tempfile\nfrom pathlib import Path\n"
            "def save(path):\n    path.write_text('fixture')\n"
            "def main():\n"
            "    directory=tempfile.TemporaryDirectory()\n    alias=directory\n"
            "    root=Path(alias.name)\n    root.chmod(0o777)\n"
            "    save(Path(directory.name) / 'record')\nmain()\n"
        },
    )
    _kept(visible, suppressed, "SKY-D324", "save")


@pytest.mark.parametrize("holder", ["{'fixture': root}", "[root]", "lambda: root"])
def test_private_temp_root_nested_alias_escape_is_not_readonly(tmp_path, holder):
    visible, suppressed = _scan(
        tmp_path,
        {
            "app.py": "import tempfile, foreign\nfrom pathlib import Path\n"
            "def save(path):\n    path.write_text('fixture')\n"
            "with tempfile.TemporaryDirectory() as temporary:\n"
            "    root=Path(temporary)\n"
            f"    holder={holder}\n"
            "    foreign.configure(holder)\n    save(root / 'record')\n"
        },
    )
    _kept(visible, suppressed, "SKY-D324", "save")


@pytest.mark.parametrize("helper", [False, True])
def test_mutating_native_path_storage_cannot_preserve_temporary_root_proof(
    tmp_path, helper
):
    operation = "change(root)" if helper else "root._parts=['/', 'tmp', 'shared']"
    visible, suppressed = _scan(
        tmp_path,
        {
            "app.py": "import tempfile\nfrom pathlib import Path\n"
            "def save(path):\n    path.write_text('fixture')\n"
            "def change(path):\n    path._parts=['/', 'tmp', 'shared']\n"
            "with tempfile.TemporaryDirectory() as temporary:\n"
            f"    root=Path(temporary)\n    {operation}\n"
            "    save(root / 'record')\n"
        },
    )
    _kept(visible, suppressed, "SKY-D324", "save")


@pytest.mark.parametrize("opener", ["None", "foreign.opener"])
def test_native_open_positional_opener_is_a_private_root_callback(tmp_path, opener):
    visible, suppressed = _scan(
        tmp_path,
        {
            "app.py": "import tempfile, foreign\nfrom pathlib import Path\n"
            "def save(path):\n    path.write_text('fixture')\n"
            "def prepare(path):\n"
            f"    return open(path / 'created', 'w', -1, None, None, None, True, {opener})\n"
            "with tempfile.TemporaryDirectory() as temporary:\n"
            "    root=Path(temporary)\n    prepare(root)\n    save(root / 'record')\n"
        },
    )
    (_quiet if opener == "None" else _kept)(visible, suppressed, "SKY-D324", "save")


def test_testcase_cannot_store_a_closed_context_as_a_live_fixture(tmp_path):
    visible, suppressed = _scan(
        tmp_path,
        {
            "tests/test_files.py": "import tempfile, unittest\nfrom pathlib import Path\n"
            "class Files(unittest.TestCase):\n"
            "    def setUp(self):\n"
            "        with tempfile.TemporaryDirectory() as temporary:\n"
            "            self.root=Path(temporary)\n"
            "    def save(self, name):\n        (self.root / name).write_text('fixture')\n"
            "    def test_fixture(self):\n        self.save('record')\n"
        },
    )
    _kept(visible, suppressed, "SKY-D324", "save")


@pytest.mark.parametrize("kind", ["pure", "mutation", "cycle", "budget"])
def test_temp_helper_effect_proof_preserves_purity_and_bounded_uncertainty(
    tmp_path, monkeypatch, kind
):
    from skylos.rules.danger.danger_fs import path_temp_ownership

    bodies = {
        "pure": "    (path / 'child').mkdir()\n",
        "mutation": "    path.chmod(0o777)\n",
        "cycle": "    prepare(path)\n",
        "budget": "    (path / 'child').mkdir()\n",
    }
    if kind == "budget":
        monkeypatch.setattr(path_temp_ownership, "_MAX_EFFECT_WORK", 1)
    visible, suppressed = _scan(
        tmp_path,
        {
            "app.py": "import tempfile\nfrom pathlib import Path\nfrom support import prepare\n"
            "def save(path):\n    path.write_text('fixture')\n"
            "with tempfile.TemporaryDirectory() as temporary:\n"
            "    root=Path(temporary)\n    prepare(root)\n    save(root / 'record')\n",
            "support.py": "def prepare(path):\n" + bodies[kind],
        },
    )
    if kind == "pure":
        _quiet(visible, suppressed, "SKY-D324", "save")
    else:
        _kept(visible, suppressed, "SKY-D324", "save")
        if kind in {"cycle", "budget"}:
            assert all(
                row["metadata"]["path_provenance"]["status"] == "incomplete"
                for row in _matching(visible, "SKY-D324", "save")
            )


@pytest.mark.parametrize(
    "change",
    [
        "",
        "unittest.defaultTestLoader.testMethodPrefix='helper'\n",
        "def load_tests(loader, tests, pattern):\n    return foreign.discover(loader, tests)\n",
    ],
)
def test_native_testcase_helper_exclusion_requires_native_discovery(tmp_path, change):
    from skylos.rules.danger.danger_fs.path_test_context import native_testcase

    source = (
        "import unittest, foreign\n"
        + change
        + "class Files(unittest.TestCase):\n    def helper_save(self, root):\n        return root.write_text('fixture')\n"
    )
    target = tmp_path / "test_fixture.py"
    target.write_text(source)
    project = path_provenance._Project.load(tmp_path)
    unit = project.by_path[target.resolve()]
    cls = next(
        node
        for node in unit.tree.body
        if isinstance(node, path_provenance.ast.ClassDef)
    )
    assert native_testcase(project, cls) is (not change)


@pytest.mark.parametrize("static", ["", "    @staticmethod\n"])
def test_native_testcase_does_not_call_parameterized_helpers_implicitly(
    tmp_path, static
):
    args = "root" if static else "self, root"
    call = "self.make_file(Path(root))"
    visible, suppressed = _scan(
        tmp_path,
        {
            "tests/test_files.py": "import unittest, tempfile\nfrom pathlib import Path\n"
            "class Files(unittest.TestCase):\n"
            + static
            + f'    def make_file({args}):\n        return (root / "fixture.txt").write_text("x")\n'
            "    def test_fixture(self):\n"
            "        with tempfile.TemporaryDirectory() as root:\n"
            f"            {call}\n"
        },
    )
    _quiet(visible, suppressed, "SKY-D324", "make_file")


def test_native_testcase_setup_temp_attributes_are_not_arbitrary_external_writes(
    tmp_path,
):
    visible, suppressed = _scan(
        tmp_path,
        {
            "tests/test_files.py": "import unittest, tempfile\nfrom pathlib import Path\n"
            "class Files(unittest.TestCase):\n"
            "    def setUp(self):\n"
            "        self.tmp=tempfile.TemporaryDirectory()\n"
            "        self.addCleanup(self.tmp.cleanup)\n"
            "        self.root=Path(self.tmp.name)\n"
            "    def save(self, name):\n"
            '        (self.root / name).write_text("x")\n'
            '    def test_fixture(self):\n        self.save("fixture.txt")\n'
        },
    )
    _quiet(visible, suppressed, "SKY-D324", "save")


@pytest.mark.parametrize(
    "extra",
    [
        "    def run(self, result=None):\n        self.make_file(Path(input()))\n",
        "    def test_remote(self):\n        self.make_file(Path(input()))\n",
        "    def test_opaque(self):\n        from external_plugin import register\n        register(self.make_file)\n",
    ],
)
def test_testcase_custom_dispatch_inputs_and_callbacks_remain_reviewable(
    tmp_path, extra
):
    visible, suppressed = _scan(
        tmp_path,
        {
            "tests/test_files.py": "import unittest, tempfile\nfrom pathlib import Path\n"
            "class Files(unittest.TestCase):\n"
            '    def make_file(self, root):\n        return (root / "fixture.txt").write_text("x")\n'
            "    def test_fixture(self):\n"
            "        with tempfile.TemporaryDirectory() as root:\n"
            "            self.make_file(Path(root))\n" + extra
        },
    )
    _kept(visible, suppressed, "SKY-D324", "make_file")


JSON_PID = """import json, os
from pathlib import Path

def positive(document, key):
    value=document.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value

def _alive(pid):
    with open(f'/proc/{pid}/stat', 'r') as stream:
        return stream.read(1024)

def check(text):
    document=json.loads(text)
    if not isinstance(document, dict):
        return False
    pid=positive(document, 'pid')
    if pid is None:
        return False
    return _alive(pid)

check(input())
"""


def test_native_json_validated_integer_cannot_format_a_path_component(tmp_path):
    visible, suppressed = _scan(tmp_path, {"app.py": JSON_PID})
    _quiet(visible, suppressed, "SKY-D215", "_alive")


@pytest.mark.parametrize("wrapper", [False, True])
@pytest.mark.parametrize(
    "replacement",
    [
        "",
        "json.loads=foreign.decode",
        "json._default_decoder=foreign.decoder",
        "json.decoder.JSONDecoder.decode=foreign.decode",
    ],
)
def test_json_literal_and_load_wrapper_require_native_decoder_dependencies(
    tmp_path, wrapper, replacement
):
    source = JSON_PID.replace(
        "import json, os", "import json, os, io, foreign\n" + replacement
    )
    if wrapper:
        source = source.replace("json.loads(text)", "json.load(io.StringIO(text))")
    source = source.replace("check(input())", "check('{\"pid\": 7}')")
    visible, suppressed = _scan(tmp_path, {"app.py": source})
    # Replacing loads itself removes the native producer even when load is
    # the apparent caller; replacing decoder methods affects existing aliases.
    (_kept if replacement else _quiet)(visible, suppressed, "SKY-D215", "_alive")


@pytest.mark.parametrize(
    "change",
    [
        ("json.loads(text)", "json.loads(text, parse_int=custom_number)"),
        ("return value\n", 'return document.get("path")\n'),
        ("pid=positive(document, 'pid')", 'pid=document.get("path")'),
        (
            "document=json.loads(text)",
            "document=json.loads(text)\n    mutate(document)",
        ),
    ],
)
def test_json_scalar_lookalikes_keep_path_findings(tmp_path, change):
    source = JSON_PID.replace(*change)
    visible, suppressed = _scan(tmp_path, {"app.py": source})
    _kept(visible, suppressed, "SKY-D215", "_alive")


HTTP = """import os
from storage import _store
from typing import Optional
from fastapi import FastAPI, Body
from pydantic import BaseModel, Field, ConfigDict
app=FastAPI(title='files')
class Request(BaseModel):
    model_config=ConfigDict(extra='forbid')
    name: Optional[str] = None
    count: int = Field(default=1, ge=0)
class Controller:
    @staticmethod
    def clean(raw):
        cleaned=''.join(c if c.isalnum() or c in ('-', '_') else '_' for c in raw)
        return cleaned or 'empty'
    def save(self, payload):
        name=self.clean((payload.name or '').strip())
        return _store(os.path.join('/srv/files', name, 'record.json'))
controller=Controller()
@app.post('/save')
def save(payload: Request | None = Body(default=None)):
    return controller.save(payload or Request())
"""


def test_standard_fastapi_model_flow_is_a_filename_proof_only(tmp_path):
    visible, suppressed = _scan(
        tmp_path,
        {
            "app.py": HTTP,
            "storage.py": "def _store(path):\n    return open(path, 'w')\n",
        },
    )
    _quiet(visible, suppressed, "SKY-D215", "_store")
    _kept(visible, suppressed, "SKY-D324", "_store")


def test_framework_sanitizer_with_public_importer_stays_reviewable_without_false_remote_claim(
    tmp_path,
):
    visible, suppressed = _scan(
        tmp_path,
        {
            "backend/__init__.py": "",
            "backend/app.py": HTTP,
            "storage.py": "def _store(path):\n    return open(path, 'w')\n",
        },
    )
    rows = _matching(visible, "SKY-D215", "_store")
    assert rows and all(
        row["metadata"]["path_provenance"]["status"] == "unknown" for row in rows
    )
    assert not _matching(suppressed, "SKY-D215", "_store")


@pytest.mark.parametrize(
    "change",
    [
        ("        name=self.clean", "        foreign.configure(payload)\n        name=self.clean"),
        ("        name=self.clean", "        foreign.configure(locals().get('payload'))\n        name=self.clean"),
        ("controller=Controller()", "controller=Controller()\ncontroller.save=foreign.save"),
        ("controller=Controller()", "controller=Controller()\nController.save=foreign.save"),
    ],
)
def test_local_model_reader_must_preserve_its_binding_and_only_project_fields(
    tmp_path, change
):
    source = "import foreign\n" + HTTP.replace(*change)
    visible, suppressed = _scan(
        tmp_path,
        {"app.py": source, "storage.py": "def _store(path):\n    return open(path, 'w')\n"},
    )
    _kept(visible, suppressed, "SKY-D215", "_store")


@pytest.mark.parametrize(
    "mutation",
    [
        "payload.name=custom_string(payload.name)",
        'object.__setattr__(payload, "name", custom_string(payload.name))',
        "mutate(payload)",
    ],
)
def test_model_mutations_never_borrow_framework_native_string_authority(
    tmp_path, mutation
):
    source = HTTP.replace(
        "        name=self.clean", "        " + mutation + "\n        name=self.clean"
    )
    visible, suppressed = _scan(
        tmp_path,
        {
            "app.py": source,
            "storage.py": "def _store(path):\n    return open(path, 'w')\n",
        },
    )
    _kept(visible, suppressed, "SKY-D215", "_store")


def test_ordinary_non_model_constructor_fields_do_not_mutate_request_models(tmp_path):
    source = HTTP.replace(
        "controller=Controller()",
        """class Other:
    def __init__(self):
        self.name='initial'
    def rename(self):
        self.name='fixed'
other=Other()
other.rename()
controller=Controller()""",
    )
    visible, suppressed = _scan(
        tmp_path,
        {
            "app.py": source,
            "storage.py": "def _store(path):\n    return open(path, 'w')\n",
        },
    )
    _quiet(visible, suppressed, "SKY-D215", "_store")


def _process_gap_fixture(tmp_path):
    (tmp_path / "worker.py").write_text("import os\nname=os.environ['FILE']\n")
    (tmp_path / "web.py").write_text(
        "import subprocess,sys\nfrom flask import Flask,request\napp=Flask(__name__)\n"
        "@app.get('/run')\ndef run():\n"
        f"    subprocess.run([sys.executable, 'worker.py'], cwd={str(tmp_path)!r}, env={{'FILE':request.args['name']}})\n"
    )
    project = path_provenance._Project.load(tmp_path, complete=True)
    worker = project.by_path[tmp_path / "worker.py"]
    facts = path_provenance._Facts.leaf(
        path_provenance.OPERATOR,
        "worker environment",
        operator_origin=(worker, "environment"),
    )
    return path_provenance._Tracer(project, "SKY-D215"), worker, facts


def test_repeated_process_context_is_reused_without_losing_remote_review(tmp_path):
    from skylos.rules.danger.danger_fs.path_process_flow import operator_launch_gap

    tracer, worker, facts = _process_gap_fixture(tmp_path)
    first = operator_launch_gap(tracer, facts)
    work = tracer.work
    second = operator_launch_gap(tracer, facts)
    assert first.chains[path_provenance.UNKNOWN]
    assert path_provenance._same_facts(first, second)
    assert tracer.work == work
    tracer._operator_launch_gaps_active = {id(worker)}
    cyclic = operator_launch_gap(tracer, facts)
    assert cyclic.chains[path_provenance.UNKNOWN]
    assert any(
        "recursive process" in step
        for chain in cyclic.chains[path_provenance.UNKNOWN]
        for step in chain
    )


def test_process_context_limit_result_is_not_reused_as_completed_analysis(
    tmp_path, monkeypatch
):
    from skylos.rules.danger.danger_fs.path_process_flow import operator_launch_gap

    tracer, _, facts = _process_gap_fixture(tmp_path)
    with monkeypatch.context() as limited:
        limited.setattr(path_provenance, "_MAX_WORK", 0)
        first = operator_launch_gap(tracer, facts)
    assert first.chains[path_provenance.INCOMPLETE]
    tracer.work = 0
    second = operator_launch_gap(tracer, facts)
    assert second.chains[path_provenance.UNKNOWN]
    assert not second.chains[path_provenance.INCOMPLETE]


def test_missing_operator_authority_cannot_borrow_an_empty_context_result(tmp_path):
    from skylos.rules.danger.danger_fs.path_process_flow import operator_launch_gap

    tracer, _, _ = _process_gap_fixture(tmp_path)
    assert operator_launch_gap(tracer, path_provenance._Facts()).empty()
    missing = path_provenance._Facts.leaf(
        path_provenance.OPERATOR, "unassociated source"
    )
    result = operator_launch_gap(tracer, missing)
    assert result.chains[path_provenance.INCOMPLETE]


def test_literal_validated_model_construction_does_not_poison_http_string_source(
    tmp_path,
):
    source = HTTP + "\ncontroller.save(Request(name='fixture', count=1))\n"
    visible, suppressed = _scan(
        tmp_path,
        {
            "app.py": source,
            "storage.py": "def _store(path):\n    return open(path, 'w')\n",
        },
    )
    _quiet(visible, suppressed, "SKY-D215", "_store")


def test_failed_model_domain_stays_incomplete_without_repeating_type_walk(
    tmp_path, monkeypatch
):
    original = path_provenance._Tracer.__init__

    def exhausted(self, *args, **kwargs):
        original(self, *args, **kwargs)
        self.model_type_work = 500001

    monkeypatch.setattr(path_provenance._Tracer, "__init__", exhausted)
    visible, suppressed = _scan(
        tmp_path,
        {
            "app.py": HTTP,
            "storage.py": "def _store(path):\n    return open(path, 'w')\n",
        },
    )
    rows = _matching(visible, "SKY-D215", "_store")
    assert rows and all(
        row["metadata"]["path_provenance"]["status"] in {"untrusted", "incomplete"}
        for row in rows
    )
    assert not _matching(suppressed, "SKY-D215", "_store")


def test_replaced_temporary_directory_provider_cannot_supply_a_safe_fixture(tmp_path):
    visible, suppressed = _scan(
        tmp_path,
        {
            "tests/test_provider.py": "import unittest, tempfile, foreign\nfrom pathlib import Path\n"
            "tempfile.TemporaryDirectory=foreign.factory\n"
            "class Files(unittest.TestCase):\n"
            '    def make_file(self, root):\n        (root / "fixture").write_text("x")\n'
            "    def test_fixture(self):\n"
            "        with tempfile.TemporaryDirectory() as root:\n"
            "            self.make_file(Path(root))\n"
        },
    )
    _kept(visible, suppressed, "SKY-D324", "make_file")


@pytest.mark.parametrize(
    "mutation", ["foreign.configure(directory)", "directory.cleanup()"]
)
def test_private_temp_object_mutation_or_cleanup_loses_reopen_ownership(
    tmp_path, mutation
):
    visible, suppressed = _scan(
        tmp_path,
        {
            "app.py": "import tempfile, foreign\nfrom pathlib import Path\nfrom storage import _store\n"
            "def main():\n    directory=tempfile.TemporaryDirectory()\n"
            f'    {mutation}\n    _store(Path(directory.name) / "marker")\nmain()\n',
            "storage.py": "def _store(path):\n    return open(path, 'w')\n",
        },
    )
    _kept(visible, suppressed, "SKY-D324", "_store")


def test_temporary_context_name_does_not_own_storage_after_exit(tmp_path):
    visible, suppressed = _scan(
        tmp_path,
        {
            "app.py": "import tempfile\nfrom pathlib import Path\nfrom storage import _store\n"
            "def main():\n    with tempfile.TemporaryDirectory() as directory:\n        pass\n"
            '    _store(Path(directory) / "marker")\nmain()\n',
            "storage.py": "def _store(path):\n    return open(path, 'w')\n",
        },
    )
    _kept(visible, suppressed, "SKY-D324", "_store")


@pytest.mark.parametrize("provider", ["json", "builtins"])
def test_opaque_decoder_or_builtin_provider_mutation_is_not_native_json_proof(
    tmp_path, provider
):
    source = JSON_PID.replace(
        "from pathlib import Path",
        f"import builtins, foreign\nforeign.patch({provider})\nfrom pathlib import Path",
    )
    visible, suppressed = _scan(tmp_path, {"app.py": source})
    _kept(visible, suppressed, "SKY-D215", "_alive")


def test_direct_callback_inside_private_context_retains_its_lifetime_proof(tmp_path):
    visible, suppressed = _scan(
        tmp_path,
        {
            "app.py": "import tempfile\nfrom pathlib import Path\nfrom storage import _store\n"
            "def main():\n    with tempfile.TemporaryDirectory() as directory:\n"
            '        def callback():\n            _store(Path(directory) / "marker")\n'
            "        callback()\nmain()\n",
            "storage.py": "def _store(path):\n    return open(path, 'w')\n",
        },
    )
    _quiet(visible, suppressed, "SKY-D324", "_store")


def test_inline_native_json_integer_guard_survives_process_liveness_probe(tmp_path):
    source = """import json, os
from pathlib import Path
def check(text):
    payload=json.loads(text)
    if not isinstance(payload, dict):
        return False
    pid=payload.get('pid')
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return False, 'bad pid'
    os.kill(pid, 0)
    return Path(f'/proc/{pid}/stat').read_text()
check(input())
"""
    visible, suppressed = _scan(tmp_path, {"app.py": source})
    assert not _matching(visible, "SKY-D215", "check")
    _kept(visible, suppressed, "SKY-D325", "check")


def test_native_json_dictionary_in_reader_tuple_retains_scalar_domain(tmp_path):
    source = JSON_PID.replace(
        "document=json.loads(text)", "document, status=read_document(text)"
    )
    source = source.replace(
        "def positive(document, key):",
        "def read_document(text):\n    payload=json.loads(text)\n    return payload, 1\n\ndef positive(document, key):",
    )
    visible, suppressed = _scan(tmp_path, {"app.py": source})
    _quiet(visible, suppressed, "SKY-D215", "_alive")


@pytest.mark.parametrize(
    ("decoder", "on_error", "safe"),
    [
        ("json.loads(text)", "return None", True),
        ("json.loads(text, parse_int=foreign.number)", "return None", False),
    ],
)
def test_try_decoded_integer_filename_requires_a_single_native_source(
    tmp_path, decoder, on_error, safe
):
    source = f"""import json
from pathlib import Path
def read(text):
    try:
        payload = {decoder}
    except ValueError:
        {on_error}
    value = payload.get("id")
    if not isinstance(value, int):
        return None
    return Path(f"/srv/reports/{{value}}.json").read_text()
read(input())
"""
    visible, suppressed = _scan(tmp_path, {"app.py": source})
    if safe:
        _quiet(visible, suppressed, "SKY-D215", "read")
    else:
        _kept(visible, suppressed, "SKY-D215", "read")
    _kept(visible, suppressed, "SKY-D325", "read")


@pytest.mark.parametrize(
    "decode_block",
    [
        "try:\n    payload = json.loads(text)\nexcept ValueError:\n    if flag:\n        return None",
        "try:\n    payload = json.loads(text)\nexcept ValueError:\n    payload = other",
        "try:\n    payload = json.loads(text)\nexcept ValueError:\n    return None\nfinally:\n    payload = other",
        "if flag:\n    try:\n        payload = json.loads(text)\n    except ValueError:\n        return None",
        "try:\n    payload = json.loads(text)\nexcept ValueError:\n    return None\npayload = other",
        "try:\n    payload = json.loads(text)\nexcept ValueError:\n    return None\nalias = payload\nalias.update(other)",
        "try:\n    foreign.payload = payload = json.loads(text)\nexcept ValueError:\n    return None",
    ],
)
def test_try_decoded_source_rejects_alternative_control_or_mutation(tmp_path, decode_block):
    import ast
    from textwrap import indent

    from skylos.rules.danger.danger_fs.path_json_scalars import JSONScalarProof

    file = tmp_path / "app.py"
    file.write_text(
        "import json\ndef read(text, other, flag):\n"
        + indent(decode_block, "    ")
        + "\n    return payload\n"
    )
    project = path_provenance._Project.load(tmp_path, None, True)
    unit = project.by_path[file.resolve()]
    use = next(node for node in ast.walk(unit.tree)
               if isinstance(node, ast.Name) and isinstance(unit.parents.get(id(node)), ast.Return))
    proof = JSONScalarProof(path_provenance._Tracer(project, "SKY-D215"))
    assert not proof.native(unit, unit.scope_of(use), use)


@pytest.mark.parametrize(
    "change",
    [
        ("json.loads(text)", "json.loads(text, parse_int=foreign.number)"),
        ("return payload, 1", "return payload, payload"),
        (
            "document, status=read_document(text)",
            "document, status=read_document(text)\n    foreign.mutate(status)",
        ),
    ],
)
def test_tuple_json_proof_does_not_borrow_mutated_decoder_or_sibling_alias(
    tmp_path, change
):
    source = JSON_PID.replace(
        "document=json.loads(text)", "document, status=read_document(text)"
    )
    source = source.replace(
        "def positive(document, key):",
        "def read_document(text):\n    payload=json.loads(text)\n    return payload, 1\n\ndef positive(document, key):",
    )
    if "foreign.mutate(status)" in change[1]:
        source = source.replace("return payload, 1", "return payload, payload")
    source = source.replace(*change)
    visible, suppressed = _scan(tmp_path, {"app.py": "import foreign\n" + source})
    _kept(visible, suppressed, "SKY-D215", "_alive")


def test_inline_json_argument_cannot_skip_callee_container_mutation(tmp_path):
    source = JSON_PID.replace(
        "document=json.loads(text)", "document=change(json.loads(text))"
    )
    source = source.replace(
        "def positive(document, key):",
        "def change(value):\n    value['pid']=foreign.number()\n    return value\n\ndef positive(document, key):",
    )
    visible, suppressed = _scan(tmp_path, {"app.py": "import foreign\n" + source})
    _kept(visible, suppressed, "SKY-D215", "_alive")


def test_late_path_parameter_cannot_be_erased_by_explanation_chain_capacity(tmp_path):
    visible, suppressed = _scan(
        tmp_path,
        {
            "app.py": "from flask import Flask, request\nfrom storage import _store\napp=Flask(__name__)\n"
            "def combine(a,b,c,d,e):\n    return a+b+c+d+e\n"
            "@app.get('/save')\ndef save():\n    return _store(combine('a','b','c','d',request.args['path']))\n",
            "storage.py": "def _store(path):\n    return open(path, 'w')\n",
        },
    )
    _kept(visible, suppressed, "SKY-D215", "_store")
    assert all(
        row["metadata"]["path_provenance"]["status"] == "untrusted"
        for row in _matching(visible, "SKY-D215", "_store")
    )


def test_late_resource_parameter_cannot_lose_its_ended_context(tmp_path):
    visible, suppressed = _scan(
        tmp_path,
        {
            "app.py": "import tempfile\nfrom pathlib import Path\nfrom storage import _store\n"
            "def combine(a,b,c,d,e):\n    return Path(a)/b/c/d/e\n"
            "def produce():\n    with tempfile.TemporaryDirectory() as root:\n"
            "        return combine('a','b','c','d',root)\n_store(produce())\n",
            "storage.py": "def _store(path):\n    return open(path, 'w')\n",
        },
    )
    _kept(visible, suppressed, "SKY-D324", "_store")
