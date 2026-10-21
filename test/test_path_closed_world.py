"""Path findings that rest only on "a caller in another module may pass
untrusted input" are dropped when the whole project shows no such caller.

Per-file analysis keeps a helper parameter as a possible remote source
(test_path_traversal.py pins that). A scan of the complete repository can
prove the module is never imported, named or registered with a framework, so
every caller is in the file the per-file analysis already followed.

A finding this test-code proof does not drop goes on to ``path_provenance``,
which resolves the helper's callers: it is reported when a resolved caller
passes untrusted input, and otherwise recorded in ``suppressed`` as ``safe``
or ``unknown`` (test_path_provenance.py). Several cases here used to assert
that such a finding stayed reported; they now assert that the test-code proof
still refuses it (``_classified`` is not None) and what provenance found.
"""

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.danger.danger_fs.closed_world import (
    TEST_MODULE_REASON,
    _has_computed_loader_call,
)

PATH_RULES = {"SKY-D215", "SKY-D324", "SKY-D325"}

HELPERS = """\
from pathlib import Path


def _write_doc(path, text):
    Path(path).write_text(text)


def _read_doc(path):
    return Path(path).read_text()
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


def _scan(path: Path) -> dict:
    return json.loads(analyze(str(path), enable_danger=True))


def _path_findings(result: dict, key: str = "danger") -> set[tuple[str, str, str]]:
    return {
        (Path(f["file"]).name, f.get("symbol"), f["rule_id"])
        for f in result.get(key) or []
        if f.get("rule_id") in PATH_RULES
    }


def _classified(result: dict, key: tuple[str, str, str]) -> str | None:
    """What ``path_provenance`` made of a finding the test-code proof kept:
    ``reported``, ``safe`` or ``unknown``. None when the finding is missing
    or was dropped as unreferenced test code."""
    if key in _path_findings(result):
        return "reported"
    for finding in result.get("suppressed") or []:
        if (Path(finding["file"]).name, finding.get("symbol"), finding["rule_id"]) != key:
            continue
        if finding.get("reason") == TEST_MODULE_REASON:
            return None
        return finding["metadata"]["path_provenance"]["status"]
    return None


def test_unimported_test_module_helpers_are_dropped(tmp_path):
    root = _project(
        tmp_path,
        {
            "tests/test_docs.py": HELPERS
            + "\n\ndef test_roundtrip(tmp_path):\n"
            "    _write_doc(tmp_path / 'a.txt', 'x')\n"
            "    assert _read_doc(tmp_path / 'a.txt') == 'x'\n",
        },
    )

    result = _scan(root)

    assert _path_findings(result) == set()
    suppressed = [
        f for f in result.get("suppressed") or [] if f.get("rule_id") in PATH_RULES
    ]
    assert {(f.get("symbol"), f["rule_id"]) for f in suppressed} == {
        ("_write_doc", "SKY-D215"),
        ("_write_doc", "SKY-D324"),
        ("_read_doc", "SKY-D215"),
        ("_read_doc", "SKY-D325"),
    }
    assert {f["reason"] for f in suppressed} == {
        "path comes from a helper parameter in test code that no non-test file "
        "imports, so its values come from the tests"
    }


def test_script_helpers_are_kept(tmp_path):
    """Outside test code the test-code proof never applies. Changed: the
    callers now decide. ``sys.argv`` is the operator's input, and nothing
    calls ``_write_doc``, so neither is reported.
    """
    root = _project(
        tmp_path,
        {
            "scripts/prepare-release.py": "import sys\n"
            + HELPERS
            + "\n\nif __name__ == '__main__':\n    print(_read_doc(sys.argv[1]))\n",
        },
    )

    result = _scan(root)
    assert _classified(result, ("prepare-release.py", "_read_doc", "SKY-D325")) == "safe"
    assert _classified(result, ("prepare-release.py", "_write_doc", "SKY-D324")) == "unknown"


def test_helper_imported_by_a_route_module_is_kept(tmp_path):
    """Nothing calls _write_doc. Changed: an unknown caller is not reported."""
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/files.py": HELPERS,
            "app/routes.py": "from flask import Flask, request\n"
            "from app.files import _read_doc\n\n"
            "app = Flask(__name__)\n\n\n"
            "@app.route('/f')\n"
            "def f():\n"
            "    return _read_doc(request.args['name'])\n",
        },
    )

    findings = _path_findings(_scan(root))
    # The route passes request data to _read_doc.
    assert {
        ("files.py", "_read_doc", "SKY-D215"),
        ("files.py", "_read_doc", "SKY-D325"),
    } <= findings
    result = _scan(root)
    assert _classified(result, ("files.py", "_write_doc", "SKY-D215")) == "unknown"
    assert _classified(result, ("files.py", "_write_doc", "SKY-D324")) == "unknown"


def test_relative_import_counts_as_an_importer(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/files.py": HELPERS,
            "app/service.py": "from flask import request\n\nfrom .files import _read_doc\n\n\n"
            "def handle():\n    return _read_doc(request.args['name'])\n",
        },
    )

    assert ("files.py", "_read_doc", "SKY-D325") in _path_findings(_scan(root))


def test_module_named_in_a_string_is_kept(tmp_path):
    """Changed: the helper is not test code; nothing calls it, so provenance
    leaves it unknown rather than reported.
    """
    root = _project(
        tmp_path,
        {
            "plugins/__init__.py": "",
            "plugins/reader.py": HELPERS,
            "main.py": "import importlib\n\n"
            "plugin = importlib.import_module('plugins.reader')\n",
        },
    )

    assert _classified(_scan(root), ("reader.py", "_read_doc", "SKY-D325")) == "unknown"


def test_module_named_in_config_is_kept(tmp_path):
    """Changed: the config names ``handler``, which does not exist; nothing
    calls ``_read_doc``, so it is unknown rather than reported.
    """
    root = _project(
        tmp_path,
        {
            "tools/reader.py": HELPERS,
            "serverless.yml": "functions:\n  read:\n    handler: tools.reader.handler\n",
        },
    )

    assert _classified(_scan(root), ("reader.py", "_read_doc", "SKY-D325")) == "unknown"


def test_module_with_framework_registration_decorator_is_kept(tmp_path):
    """Changed: ``process`` is only reached through the Celery decorator, whose
    callers are not visible, so ``_read`` is unknown rather than reported.
    """
    root = _project(
        tmp_path,
        {
            "worker.py": "from pathlib import Path\n"
            "from celery import Celery\n\n"
            "celery_app = Celery()\n\n\n"
            "@celery_app.task\n"
            "def process(path):\n"
            "    return _read(path)\n\n\n"
            "def _read(path):\n"
            "    return Path(path).read_text()\n",
        },
    )

    result = _scan(root)
    assert _classified(result, ("worker.py", "_read", "SKY-D325")) == "unknown"
    provenance = next(
        f["metadata"]["path_provenance"]
        for f in result["suppressed"]
        if f.get("symbol") == "_read" and f["rule_id"] == "SKY-D325"
    )
    assert any("decorated with `celery_app.task`" in chain[0] for chain in provenance["unknown"])


def test_module_importing_a_web_framework_is_kept(tmp_path):
    root = _project(
        tmp_path,
        {
            "handlers.py": "from pathlib import Path\n"
            "from fastapi import APIRouter\n\n"
            "router = APIRouter()\n\n\n"
            "def read_file(path):\n"
            "    return Path(path).read_text()\n\n\n"
            "router.add_api_route('/r', read_file)\n",
        },
    )

    assert ("handlers.py", "read_file", "SKY-D325") in _path_findings(_scan(root))


def test_subdirectory_scan_is_not_a_closed_world(tmp_path):
    """Changed: not dropped as test code (the scan is partial); provenance
    cannot see every caller either, so it is unknown rather than reported.
    """
    root = _project(tmp_path, {"tests/test_docs.py": HELPERS})

    assert _classified(_scan(root / "tests"), ("test_docs.py", "_read_doc", "SKY-D325")) == "unknown"


def test_remote_source_in_the_same_file_is_kept(tmp_path):
    root = _project(
        tmp_path,
        {
            "app.py": "from pathlib import Path\n"
            "from flask import Flask, request\n\n"
            "app = Flask(__name__)\n\n\n"
            "def _read(name):\n"
            "    return (Path('/srv') / name).read_text()\n\n\n"
            "@app.route('/f')\n"
            "def view():\n"
            "    return _read(request.args['name'])\n",
        },
    )

    assert ("app.py", "_read", "SKY-D215") in _path_findings(_scan(root))


# Entry points invoked from outside the scanned code (review repros).


def test_lambda_handler_named_only_in_terraform_is_kept(tmp_path):
    root = _project(
        tmp_path,
        {
            "main.tf": 'resource "aws_lambda_function" "files" {\n'
            '  handler = "lambda_function.lambda_handler"\n}\n',
            "lambda_function.py": "import os\n\nBASE = '/var/task/static'\n\n\n"
            "def lambda_handler(event, context):\n"
            "    name = event['queryStringParameters']['file']\n"
            "    with open(os.path.join(BASE, name)) as fh:\n"
            "        return {'statusCode': 200, 'body': fh.read()}\n",
        },
    )

    assert ("lambda_function.py", "lambda_handler", "SKY-D215") in _path_findings(
        _scan(root)
    )


def test_wsgi_app_started_from_a_dockerfile_variant_is_kept(tmp_path):
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

    assert ("wsgi_app.py", "application", "SKY-D215") in _path_findings(_scan(root))


def test_helper_called_from_an_extensionless_server_script_is_kept(tmp_path):
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

    assert ("fileutil.py", "read_file", "SKY-D215") in _path_findings(_scan(root))


def test_plugin_loaded_by_pkgutil_is_kept(tmp_path):
    root = _project(
        tmp_path,
        {
            "app.py": "from flask import Flask, request\n"
            "from plugins import REGISTRY\n\n"
            "app = Flask(__name__)\n\n\n"
            "@app.route('/run/<name>')\n"
            "def run_plugin(name):\n"
            "    return REGISTRY[name].run(request.args['arg'])\n",
            "plugins/__init__.py": "import importlib\nimport pkgutil\n\n"
            "REGISTRY = {}\n"
            "for info in pkgutil.iter_modules(__path__):\n"
            "    REGISTRY[info.name] = importlib.import_module(f'{__name__}.{info.name}')\n",
            "plugins/files.py": "import os\n\nBASE = '/srv/data'\n\n\n"
            "def run(arg):\n"
            "    with open(os.path.join(BASE, arg)) as fh:\n"
            "        return fh.read()\n",
        },
    )

    assert ("files.py", "run", "SKY-D215") in _path_findings(_scan(root))


def test_library_function_is_kept(tmp_path):
    """Changed: that is unknown, which is recorded rather than reported."""
    root = _project(
        tmp_path,
        {
            "mylib/__init__.py": '"""mylib."""\n',
            "mylib/storage.py": "import os\n\nROOT = '/srv/assets'\n\n\n"
            "def read_asset(name):\n"
            "    with open(os.path.join(ROOT, name), 'rb') as fh:\n"
            "        return fh.read()\n\n\n"
            "DEFAULT = read_asset('default.bin')\n",
        },
    )

    # Its only visible caller passes a constant, but callers outside the
    # repository (or unseen ones) may not.
    assert _classified(_scan(root), ("storage.py", "read_asset", "SKY-D215")) == "unknown"


def test_script_helper_passed_as_a_callback_is_kept(tmp_path):
    """Changed: a callback's callers are not visible, so it is unknown."""
    root = _project(
        tmp_path,
        {
            "scripts/serve.py": "import sys\n"
            + HELPERS
            + "\n\ndef main():\n"
            "    register(_read_doc)\n\n\n"
            "if __name__ == '__main__':\n    main()\n",
        },
    )

    assert _classified(_scan(root), ("serve.py", "_read_doc", "SKY-D325")) == "unknown"


def test_script_helper_reached_through_main_is_kept(tmp_path):
    """Changed: ``build(sys.argv[1])`` passes the operator's CLI argument and
    nothing calls ``_write_doc``; neither is reported.
    """
    root = _project(
        tmp_path,
        {
            "scripts/report.py": "import sys\n"
            + HELPERS
            + "\n\ndef build(path):\n"
            "    return _read_doc(path)\n\n\n"
            "def main():\n"
            "    print(build(sys.argv[1]))\n\n\n"
            "if __name__ == '__main__':\n    main()\n",
        },
    )

    result = _scan(root)
    assert _classified(result, ("report.py", "_read_doc", "SKY-D325")) == "safe"
    assert _classified(result, ("report.py", "_write_doc", "SKY-D324")) == "unknown"


# Dynamic loaders block the proof only when they can point at the module.

SCRIPT = (
    "import sys\n"
    + HELPERS
    + "\n\ndef main():\n"
    "    print(_read_doc(sys.argv[1]))\n\n\n"
    "if __name__ == '__main__':\n    main()\n"
)


def test_loader_for_another_folder_named_tests_does_not_block(tmp_path):
    root = _project(
        tmp_path,
        {
            # Test code (it holds a test); a script with no test in a tests
            # folder is production code and keeps its findings.
            "researcher/tests/test_validate.py": SCRIPT
            + "\n\ndef test_main(monkeypatch):\n    main()\n",
            "skills/compress/loader.py": "import importlib.util\n"
            "from pathlib import Path\n\n"
            "SPEC = importlib.util.spec_from_file_location(\n"
            "    'evaluator', Path(__file__).resolve().parent / 'tests' / 'evaluator.py'\n"
            ")\n",
        },
    )

    # The loader names a "tests" folder, but not researcher/tests.
    assert ("test_validate.py", "_read_doc", "SKY-D325") not in _path_findings(_scan(root))


def test_loader_naming_the_module_folder_path_blocks(tmp_path):
    """Changed: the only caller passes ``sys.argv``, so provenance finds it
    safe.
    """
    root = _project(
        tmp_path,
        {
            "researcher/scripts/validate.py": SCRIPT,
            "tools/load_all.py": "import importlib.util\n"
            "from pathlib import Path\n\n"
            "FOLDER = Path(__file__).parents[1] / 'researcher' / 'scripts'\n"
            "for path in FOLDER.glob('*.py'):\n"
            "    importlib.util.spec_from_file_location(path.stem, path)\n",
        },
    )

    assert _classified(_scan(root), ("validate.py", "_read_doc", "SKY-D325")) == "safe"


def test_loader_in_the_same_folder_blocks(tmp_path):
    """Changed: the only caller passes ``sys.argv``, so provenance finds it
    safe.
    """
    root = _project(
        tmp_path,
        {
            "researcher/scripts/validate.py": SCRIPT,
            "researcher/scripts/run_all.py": "import importlib.util\n"
            "from pathlib import Path\n\n"
            "for path in Path(__file__).parent.glob('*.py'):\n"
            "    importlib.util.spec_from_file_location(path.stem, path)\n",
        },
    )

    assert _classified(_scan(root), ("validate.py", "_read_doc", "SKY-D325")) == "safe"


def test_helper_in_a_test_package_imported_by_non_test_code_is_kept(tmp_path):
    """Changed: not dropped as test code; ``show`` has no caller, so unknown."""
    # ``tests/__init__.py`` defines the helper; app code imports the package.
    root = _project(
        tmp_path,
        {
            "tests/__init__.py": HELPERS,
            "app/routes.py": "from tests import _read_doc\n\n\n"
            "def show(name):\n    return _read_doc(name)\n",
        },
    )

    assert _classified(_scan(root), ("__init__.py", "_read_doc", "SKY-D325")) == "unknown"


def test_helper_reexported_by_a_test_package_is_kept(tmp_path):
    """Changed: not dropped as test code; ``show`` has no caller, so unknown."""
    # ``tests/__init__.py`` re-exports from a submodule app code never names.
    root = _project(
        tmp_path,
        {
            "tests/docs_support.py": HELPERS,
            "tests/__init__.py": "from .docs_support import _read_doc\n",
            "app/routes.py": "import tests\n\n\n"
            "def show(name):\n    return tests._read_doc(name)\n",
        },
    )

    assert _classified(_scan(root), ("docs_support.py", "_read_doc", "SKY-D325")) == "unknown"


def test_relative_import_of_a_nested_test_package_is_kept(tmp_path):
    """Changed: not dropped as test code; ``show`` is public API with no
    visible caller, so unknown.
    """
    root = _project(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/tests/__init__.py": "",
            "pkg/tests/support.py": HELPERS,
            "pkg/api.py": "from .tests import support\n\n\n"
            "def show(name):\n    return support._read_doc(name)\n",
        },
    )

    assert _classified(_scan(root), ("support.py", "_read_doc", "SKY-D325")) == "unknown"


def test_test_package_import_from_test_code_still_drops(tmp_path):
    root = _project(
        tmp_path,
        {
            "tests/__init__.py": "",
            "tests/support.py": "import pytest\n\n" + HELPERS,
            "tests/test_docs.py": "from tests.support import _read_doc\n\n\n"
            "def test_read(tmp_path):\n    assert _read_doc(tmp_path / 'a') == ''\n",
            "app/routes.py": "def show():\n    return 'ok'\n",
        },
    )

    assert ("support.py", "_read_doc", "SKY-D325") not in _path_findings(_scan(root))


def test_test_module_run_with_exec_by_app_code_is_kept(tmp_path):
    """Changed: not dropped as test code; computed ``exec`` code may call it,
    so it is unknown.
    """
    root = _project(
        tmp_path,
        {
            "tests/test_docs.py": HELPERS,
            "app.py": "from pathlib import Path\n\n"
            "scope = {}\n"
            "script = Path(__file__).parent / 'tests' / ('test_' + 'docs.py')\n"
            "exec(script.read_text(), scope)\n\n\n"
            "def download(name):\n    return scope['_read_doc'](name)\n",
        },
    )

    assert _classified(_scan(root), ("test_docs.py", "_read_doc", "SKY-D325")) == "unknown"


def test_production_module_named_like_a_test_is_kept(tmp_path):
    """Changed: not dropped as test code; nothing calls them, so unknown."""
    # An Airflow DAG and a Django command: test-like names, no tests in them.
    root = _project(
        tmp_path,
        {
            "dags/model_ab_test.py": HELPERS,
            "app/management/commands/smoke_test.py": HELPERS,
        },
    )

    result = _scan(root)
    assert _classified(result, ("model_ab_test.py", "_read_doc", "SKY-D325")) == "unknown"
    assert _classified(result, ("smoke_test.py", "_read_doc", "SKY-D325")) == "unknown"


def test_backslash_continued_import_of_a_test_module_is_kept(tmp_path):
    """Changed: not dropped as test code; ``show`` has no caller, so unknown."""
    root = _project(
        tmp_path,
        {
            "tests/__init__.py": "",
            "tests/support/__init__.py": "from .fsutil import _read_doc\n",
            "tests/support/fsutil.py": "import pytest\n\n" + HELPERS,
            "app/routes.py": "from tests.support \\\n    import _read_doc as read\n\n\n"
            "def show(name):\n    return read(name)\n",
        },
    )

    assert _classified(_scan(root), ("fsutil.py", "_read_doc", "SKY-D325")) == "unknown"


LOADER_APP = (
    "import importlib\n\nfrom flask import Flask, request\n\n"
    "app = Flask(__name__)\n\n\n"
)
TEST_DOCS = HELPERS + "\n\ndef test_roundtrip(tmp_path):\n    _write_doc(tmp_path / 'a.txt', 'x')\n"


@pytest.mark.parametrize(
    "loader",
    [
        "@app.route('/diag')\n"
        "def diag():\n"
        "    module = importlib.import_module(request.args['m'])\n"
        "    return getattr(module, request.args['f'])(request.args['p'], 'x')\n",
        "@app.route('/run', methods=['POST'])\n"
        "def run():\n"
        "    exec(request.form['code'])\n"
        "    return 'ok'\n",
        "def load(name):\n    return __import__(name)\n",
        "from importlib import import_module as load_mod\n\n\n"
        "def diag(name):\n    return load_mod(name)\n",
        # A constant another module (or a star import) can rebind is not fixed.
        "TARGET = 'app_plugins.default'\n\n\n"
        "def diag():\n    return importlib.import_module(TARGET)\n",
        "import builtins as py\n\n"
        "def diag(source):\n    py.exec(source)\n",
        "import importlib.util\n\n"
        "def diag(path):\n"
        "    str = lambda unused: path\n"
        "    return importlib.util.spec_from_file_location('runtime', str(__file__))\n",
        "from importlib import import_module as load\n"
        "from importlib import import_module as load\n\n"
        "def diag(name):\n    return load(name)\n",
        "import builtins as py\n\n"
        "def diag(source, fallback):\n"
        "    if fallback:\n        py = object()\n"
        "    else:\n        import builtins as py\n"
        "    py.exec(source)\n",
        "from pathlib import Path\nfrom plugins import *\n"
        "import importlib.util\n\n"
        "def diag():\n"
        "    return importlib.util.spec_from_file_location('runtime', Path('default.py'))\n",
        "import os\nimport importlib.util\n\n"
        "def diag(path):\n"
        "    os.path.join = lambda *unused: path\n"
        "    return importlib.util.spec_from_file_location('runtime', os.path.join('a', 'b.py'))\n",
        "import importlib.util\n\n"
        "def diag(path):\n"
        "    globals()['__file__'] = path\n"
        "    return importlib.util.spec_from_file_location('runtime', str(__file__))\n",
        "def diag(loader, name):\n"
        "    return getattr(importlib, loader)(name)\n",
        "from importlib import util as tools\n\n"
        "def diag(loader, path):\n"
        "    return getattr(tools, loader)('runtime', path)\n",
        "def diag(loader, name):\n"
        "    sources = [importlib]\n"
        "    return getattr(sources[0], loader)(name)\n",
    ],
    ids=[
        "import_module_request",
        "exec_request",
        "dunder_import_parameter",
        "aliased_loader",
        "module_constant",
        "aliased_builtins_module",
        "shadowed_path_builder",
        "repeated_loader_import",
        "conditionally_rebound_loader_module",
        "star_replaces_path_builder",
        "mutated_path_module_attribute",
        "mutated_module_namespace",
        "computed_loader_attribute",
        "computed_attribute_from_imported_module",
        "escaped_loader_module",
    ],
)
def test_computed_dynamic_import_in_shipped_code_keeps_test_helpers(tmp_path, loader):
    """Changed: the finding still escapes the test-code proof, and provenance
    then classifies it (unknown when a computed call may reach it).
    """
    # A loader whose module name or source is computed can load tests/ too.
    root = _project(
        tmp_path, {"app.py": LOADER_APP + loader, "tests/test_docs.py": TEST_DOCS}
    )

    assert _classified(_scan(root), ("test_docs.py", "_write_doc", "SKY-D324")) is not None


@pytest.mark.parametrize(
    "files",
    [
        {"app.py": LOADER_APP + "def load():\n    return importlib.import_module('app_plugins.extra')\n"},
        {"app.py": LOADER_APP + "def users(session, select, User):\n    return session.exec(select(User)).all()\n"},
        {
            "app.py": LOADER_APP + "def ping():\n    # fixtures: tests/test_docs.py\n    return 'pong'\n",
            "tests/conftest.py": "import importlib\n\n\ndef load(name):\n    return importlib.import_module(name)\n",
        },
    ],
    ids=["fixed_module_name", "not_a_loader", "comment_and_test_only_loader"],
)
def test_fixed_or_test_only_loaders_still_prove_test_helpers(tmp_path, files):
    root = _project(tmp_path, {**files, "tests/test_docs.py": TEST_DOCS})

    assert not {f for f in _path_findings(_scan(root)) if f[0] == "test_docs.py"}


@pytest.mark.parametrize(
    ("code", "computed"),
    [
        ("import importlib\nload = importlib.import_module\nload('app.x')", True),
        ("getattr(importlib, 'import_module')('app.x')", True),
        ("import importlib\ngetattr(importlib, attr)('app.x')", True),
        ("import builtins\nbuiltins.exec(code)", True),
        ("from helpers import *\nbuiltins.exec(code)", True),
        ("PathFinder.find_spec('test_docs', [folder])", True),
        ("__import__('tests', fromlist=[name])", True),
        ("SourceFileLoader('m', '/srv/m.py').load_module()", False),
        ("from pathlib import Path\nspec_from_file_location('e', Path(__file__).resolve().parent / 'e.py')", False),
        ("importlib.import_module(" + " + ".join(["'a'"] * 5000) + ")", True),
        ("BANNER = " + " + ".join(["'a'"] * 5000) + "\nimportlib.import_module('x')", False),
        ("session.exec(select(User))", False),
        ("getattr(settings, 'DEBUG')", False),
        ("import builtins as py\npy.exec(source)", True),
        ("from importlib.util import spec_from_file_location\n"
         "def str(x):\n    return x\nspec_from_file_location('e', str('e.py'))", True),
        ("from importlib.util import spec_from_file_location\nimport evil as os\n"
         "spec_from_file_location('e', os.path.join('a', 'e.py'))", True),
        # A variable or local function named like a loader is not one.
        ("from pathlib import Path\nrun_path = Path(out) / rid\nrun_path.exists()", False),
        ("def run_path(p):\n    return p\nrun_path(x)", False),
        ("from runpy import run_path\nrun_path(x)", True),
        ("import builtins, gettext\nsetattr(builtins, '_', gettext.gettext)", False),
        ("import importlib as m\ngetattr(m, attr)(x)", True),
        ("import pydoc\npydoc.locate(x)", True),
        ("from kombu.utils.imports import symbol_by_name\nsymbol_by_name(x)", True),
        ("page.locate(x)", False),
        # Code that does not parse is judged by its text.
        ("print 'x'\nnote = 'import_module'", False),
        ("print 'x'\nimportlib.import_module(name)", True),
        ("import os\nspec_from_file_location('e', os.path.join(os.path.dirname(__file__), 'e.py'))", False),
        ('from importlib import import_module as load\nfrom importlib import import_module as load\nload(name)', True),
        ('import builtins as py\nif flag:\n    py = object()\npy.exec(source)', True),
        ("from importlib.util import spec_from_file_location\nfrom pathlib import Path\nfrom plugins import *\nspec_from_file_location('e', Path('e.py'))", True),
        ("from importlib.util import spec_from_file_location\nimport os\nos.path.join = factory\nspec_from_file_location('e', os.path.join('a', 'e.py'))", True),
        ("from importlib.util import spec_from_file_location\nimport os\nsetattr(os.path, 'join', factory)\nspec_from_file_location('e', os.path.join('a', 'e.py'))", True),
        ("from importlib.util import spec_from_file_location\nglobals()['__file__'] = path\nspec_from_file_location('e', str(__file__))", True),
        ("from importlib.util import spec_from_file_location\nglobals().update(__file__=path)\nspec_from_file_location('e', str(__file__))", True),
        ("from importlib.util import spec_from_file_location\nfrom pathlib import Path\nsettings.mode = 'safe'\nspec_from_file_location('e', Path('e.py'))", False),
        ('from importlib import util as tools\ngetattr(tools, loader)(name, path)', True),
        ('import importlib\nsources = [importlib]\ngetattr(sources[0], loader)(name)', True),
    ],
)
def test_loader_targets_chosen_at_run_time(code, computed):
    assert _has_computed_loader_call(code) is computed


def test_deep_expression_in_a_loader_file_does_not_stop_the_scan(tmp_path):
    banner = " + ".join(["'a'"] * 1200)
    root = _project(
        tmp_path,
        {
            "app.py": LOADER_APP
            + f"BANNER = {banner}\n\n\n"
            "def load():\n    return importlib.import_module('app_plugins.extra')\n",
            "tests/test_docs.py": TEST_DOCS,
        },
    )

    # The scan finishes (other analyzers record app.py as too deep to
    # process, as before) and the fixed loader still proves the helper.
    result = _scan(root)

    assert not {f for f in _path_findings(result) if f[0] == "test_docs.py"}
    assert ("test_docs.py", "_write_doc", "SKY-D324") in _path_findings(result, "suppressed")
    for error in result.get("analysis_errors", []):
        assert Path(error["file"]).name == "app.py"
        assert error.get("error_type") == "RecursionError"

    computed_root = _project(
        tmp_path / "computed",
        {
            "app.py": LOADER_APP
            + f"BANNER = {banner}\n\n\n"
            "def load(name):\n    return importlib.import_module(name)\n",
            "tests/test_docs.py": TEST_DOCS,
        },
    )
    computed = _scan(computed_root)
    assert _classified(computed, ("test_docs.py", "_write_doc", "SKY-D324")) is not None
