"""Dynamic loader capabilities must not hide sanitizer-patching modules."""

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate


APP = """import os
from fastapi import FastAPI
from storage import load

app = FastAPI()
ROOT = '/srv/files'

def clean(raw):
    cleaned = ''.join(c if c.isalnum() or c in ('-', '_') else '_' for c in raw)
    return cleaned or 'empty'

@app.get('/files')
def view(name: str):
    return load(os.path.join(ROOT, clean(name), 'record.json'))
"""
STORAGE = """def load(path):
    with open(path, 'r') as stream:
        return stream.read()
"""
PATCHER = "import sys\nvars(sys.modules['app'])['clean'] = str\n"
LOADERS = {
    "direct": {
        "server.py": "import app\nimport importlib\nimportlib.import_module('plugin')\n"
    },
    "qualified-alias": {
        "server.py": "import app\nimport importlib as tools\ntools.import_module('plugin')\n"
    },
    "import-alias": {
        "server.py": "import app\nfrom importlib import import_module as activate\nactivate('plugin')\n"
    },
    "assignment-alias": {
        "server.py": "import app\nimport importlib\nactivate = importlib.import_module\nactivate('plugin')\n"
    },
    "project-reexport": {
        "bridge.py": "from importlib import import_module as activate\n",
        "server.py": "import app\nfrom bridge import activate\nactivate('plugin')\n",
    },
    "partial": {
        "server.py": "import app\nfrom functools import partial\nfrom importlib import import_module\nactivate = partial(import_module)\nactivate('plugin')\n"
    },
    "bound-call": {
        "server.py": "import app\nfrom importlib import import_module\nactivate = import_module.__call__\nactivate('plugin')\n"
    },
    "bound-wrapper": {
        "server.py": "import app\nfrom importlib import import_module\nclass Loader:\n    def __init__(self):\n        self.activate = import_module\nLoader().activate('plugin')\n"
    },
    "factory": {
        "server.py": "import app\nfrom importlib import import_module\ndef factory():\n    return import_module\nactivate = factory()\nactivate('plugin')\n"
    },
    "callback": {
        "server.py": "import app\nfrom importlib import import_module\ndef invoke(callback, name):\n    return callback(name)\ninvoke(import_module, 'plugin')\n"
    },
    "computed-member": {
        "server.py": "import app\nimport importlib as tools\nactivate = getattr(tools, 'import_' + 'module')\nactivate('plugin')\n"
    },
    "builtin-alias": {
        "server.py": "import app\nfrom builtins import __import__ as activate\nactivate('plugin')\n"
    },
    "implicit-builtin-alias": {
        "server.py": "import app\nactivate = __import__\nactivate('plugin')\n"
    },
    "implicit-builtin-factory": {
        "server.py": "import app\ndef factory():\n    return __import__\nfactory()('plugin')\n"
    },
    "builtin-dispatch": {
        "server.py": "import app\nregistry = {'activate': __import__}\nregistry['activate']('plugin')\n"
    },
    "ambiguous-rebinding": {
        "server.py": "import app\nfrom importlib import import_module as activate\nif legacy:\n    activate = unknown\nactivate('plugin')\n"
    },
    "relative-reexport": {
        "bridge/__init__.py": "from .loader import activate\n",
        "bridge/loader.py": "from importlib import import_module as activate\n",
        "server.py": "import app\nfrom bridge import activate\nactivate('plugin')\n",
    },
    "globals-namespace": {
        "server.py": "import app\nactivate = globals()['__builtins__']['__import__']\nactivate('plugin')\n"
    },
    "aliased-namespace": {
        "server.py": "import app\nfrom builtins import vars as namespace\nenvironment = namespace()\nactivate = environment['__builtins__']['__import__']\nactivate('plugin')\n"
    },
    "literal-loader-key": {
        "server.py": "import app\nfrom importlib import import_module as activate\nglobals().get('activate')('plugin')\n"
    },
    "computed-loader-key": {
        "server.py": "import app\nfrom importlib import import_module as activate\nkey = 'activate'\nglobals().get(key)('plugin')\n"
    },
    "escaped-namespace": {
        "server.py": "import app\nfrom importlib import import_module as activate\nnamespace = globals()\nnamespace.get('activate')('plugin')\n"
    },
}


def _scan(tmp_path, extra, plugin=PATCHER, app=APP):
    (tmp_path / "pyproject.toml").write_text('[project]\nname="route-loader-proof"\n')
    for relative, source in {
        "app.py": app,
        "storage.py": STORAGE,
        "plugin.py": plugin,
        **extra,
    }.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    result = json.loads(analyze(str(tmp_path), enable_danger=True, grep_verify=False))
    assert result.get("analysis_errors") == []
    assert result["analysis_summary"]["analysis_error_count"] == 0
    traversal = [
        row for row in result.get("danger", []) if row["rule_id"] == "SKY-D215"
    ]
    reads = [row for row in result.get("danger", []) if row["rule_id"] == "SKY-D325"]
    assert {(Path(row["file"]).name, row["line"]) for row in reads} == {
        ("storage.py", 2)
    }
    return result, traversal


def _assert_unsafe(result, traversal):
    assert len(traversal) == 1
    row = traversal[0]
    assert (Path(row["file"]).name, row["line"], row["symbol"]) == (
        "storage.py",
        2,
        "load",
    )
    assert row["severity"] == "HIGH"
    assert row["listing"]["listed"] is True
    assert row["metadata"]["path_provenance"]["status"] == "untrusted"
    passed, reasons = check_gate(result, {"gate": {"max_high": 0, "max_security": 10}})
    assert not passed
    assert any("high severity" in str(reason) for reason in reasons)


@pytest.mark.parametrize("loader", LOADERS, ids=LOADERS)
def test_dynamic_loader_capabilities_keep_patched_route_paths_reported(
    tmp_path, loader
):
    result, traversal = _scan(tmp_path, LOADERS[loader])
    _assert_unsafe(result, traversal)


@pytest.mark.parametrize(
    "loader", ["direct", "qualified-alias", "import-alias", "partial"]
)
def test_actual_dynamic_loading_without_mutation_preserves_filename_proof(
    tmp_path, loader
):
    result, traversal = _scan(tmp_path, LOADERS[loader], plugin="VALUE = 1\n")
    assert not traversal
    suppressed = [
        row for row in result.get("suppressed", []) if row["rule_id"] == "SKY-D215"
    ]
    assert len(suppressed) == 1
    assert suppressed[0]["metadata"]["path_provenance"]["status"] == "safe"
    passed, _ = check_gate(result, {"gate": {"max_high": 0, "max_security": 10}})
    assert passed


def test_static_program_named_like_a_loader_does_not_load_unrelated_patcher(tmp_path):
    result, traversal = _scan(
        tmp_path,
        {
            "server.py": "import app\ndef import_module(name):\n    return name\nimport_module('plugin')\n"
        },
    )
    assert not traversal
    assert any(
        row["rule_id"] == "SKY-D215"
        and row["metadata"]["path_provenance"]["status"] == "safe"
        for row in result.get("suppressed", [])
    )


@pytest.mark.parametrize(
    "server",
    [
        "import app\nfrom importlib import import_module as activate\n",
        "import app\nfrom importlib import import_module as activate\nactivate = print\nactivate('plugin')\n",
    ],
    ids=["unused-loader-import", "known-replacement"],
)
def test_unused_or_proven_replaced_loader_does_not_load_patcher(tmp_path, server):
    result, traversal = _scan(tmp_path, {"server.py": server})
    assert not traversal
    assert any(
        row["rule_id"] == "SKY-D215"
        and row["metadata"]["path_provenance"]["status"] == "safe"
        for row in result.get("suppressed", [])
    )


def test_unsanitized_route_stays_reported_without_dynamic_loading(tmp_path):
    app = APP.replace("clean(name), 'record.json'", "name, 'record.json'")
    result, traversal = _scan(tmp_path, {}, plugin="VALUE = 1\n", app=app)
    _assert_unsafe(result, traversal)


@pytest.mark.parametrize(
    "metadata",
    [
        "WIDTH_0 = 320\n"
        + "".join(f"WIDTH_{i} = WIDTH_{i - 1}\n" for i in range(1, 40))
        + "def dimensions():\n    return WIDTH_39\n",
        "WIDTH = "
        + "(" * 40
        + "320"
        + " + 1)" * 40
        + "\ndef dimensions():\n    return WIDTH\n",
        "def scalar(value):\n    return max(0, value)\n"
        + "def dimensions(width):\n    return "
        + "scalar(" * 40
        + "width"
        + ")" * 40
        + "\n",
    ],
    ids=["deep-aliases", "numeric-expression", "ordinary-call-arguments"],
)
def test_complex_scalar_data_does_not_create_loader_authority(tmp_path, metadata):
    result, traversal = _scan(tmp_path, {}, app=APP + "\n" + metadata)
    assert not traversal
    suppressed = [
        row for row in result.get("suppressed", []) if row["rule_id"] == "SKY-D215"
    ]
    assert len(suppressed) == 1
    assert suppressed[0]["metadata"]["path_provenance"]["status"] == "safe"
    passed, _ = check_gate(result, {"gate": {"max_high": 0, "max_security": 10}})
    assert passed


@pytest.mark.parametrize(
    "metadata",
    [
        "import logging\nGIMBAL_CONTROLLER_PROCESS = None\nlog = logging.getLogger(__name__)\n"
        "def current_process():\n    return globals().get('GIMBAL_CONTROLLER_PROCESS')\n"
        "def current_logger():\n    return globals().get('log')\n",
        "WIDTH = 320\ndef dimensions():\n    return globals()['WIDTH']\n",
    ],
    ids=["process-and-logger", "literal-data-key"],
)
def test_literal_global_data_projection_does_not_load_unrelated_patcher(
    tmp_path, metadata
):
    result, traversal = _scan(tmp_path, {}, app=APP + "\n" + metadata)
    assert not traversal
    suppressed = [
        row for row in result.get("suppressed", []) if row["rule_id"] == "SKY-D215"
    ]
    assert len(suppressed) == 1
    assert suppressed[0]["metadata"]["path_provenance"]["status"] == "safe"
