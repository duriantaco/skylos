"""Framework helpers stay trusted when the strict effects proof cannot finish
(plugin loaders, literal ``__import__`` reads, ``exec``, large projects), and
lose trust whenever project code literally names, rewrites or could redirect
them. Measured through SKY-D230 on ``redirect(url_for(...))``: a trusted
``url_for`` builds a local URL, an untrusted one is reported."""

import ast
import errno
import io
import json
import os
import zipfile
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.analysis.errors import analysis_result_incomplete
from test.fixture_paths import write_fixture

VIEW = (
    "from flask import Flask, redirect, request, url_for\n"
    "app = Flask(__name__)\n"
    "@app.route('/private')\n"
    "def private():\n"
    "    return redirect(url_for('login', next=request.full_path))\n"
)
LOADER = (
    "import importlib\n"
    "def load(name):\n"
    "    return importlib.import_module(name, package='shop.plugins')\n"
)
FAKE = "def url_for(endpoint, **values):\n    return values['next']\n"
ZIP = object()
REPORTED = [("shop/views.py", 6)]


def _zip_bytes(preamble=b"", comment=b""):
    buffer = io.BytesIO()
    buffer.write(preamble)
    with zipfile.ZipFile(buffer, "a") as archive:
        archive.writestr("flask.py", FAKE)
        archive.comment = comment
    return buffer.getvalue()


def _scan_result(root, monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    if not (root / "pyproject.toml").exists():
        write_fixture(root, "pyproject.toml", '[project]\nname="shop"\n')
    return json.loads(
        analyze(
            str(root),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            enable_sca=False,
            grep_verify=False,
            grep_cache=False,
            all_advice=False,
        )
    )


def _redirect_locations(result, root):
    return sorted(
        (f["file"].replace(str(root), "").lstrip("/"), f["line"])
        for f in result.get("danger", [])
        if f["rule_id"] == "SKY-D230"
    )


def _redirects(root, monkeypatch):
    result = _scan_result(root, monkeypatch)
    assert not result.get("analysis_errors")
    return _redirect_locations(result, root)


def _assert_permission_incomplete(result, root):
    errors = result["analysis_errors"]
    assert errors
    for error in errors:
        assert error["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"
        assert error["severity"] == "HIGH"
        assert error["kind"] == "security_scan_error"
        assert error["error_type"] == "PermissionError"
        assert Path(error["file"]).is_relative_to(root)
    assert analysis_result_incomplete(result)
    assert result["analysis_summary"]["analysis_error_count"] == len(errors)
    assert result["analysis_summary"]["grade_unavailable_reason"] == (
        "analysis_incomplete"
    )
    assert "grade" not in result


def _plugin_app(root, helper, plugin, extra=None):
    write_fixture(root, "shop/__init__.py", "")
    write_fixture(root, "shop/views.py", "from shop import helpers, plugins\n" + VIEW)
    write_fixture(root, "shop/helpers.py", helper)
    write_fixture(root, "shop/plugins/__init__.py", LOADER)
    write_fixture(root, "shop/plugins/extra.py", plugin)
    if extra is None:
        return
    name, content = extra
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if content is ZIP:
        path.write_bytes(_zip_bytes())
    elif isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content)


@pytest.mark.parametrize(
    "helper, plugin",
    [
        ("VALUE = 1\n", "VALUE = 2\n"),
        (
            "def context():\n    return __import__('ssl').create_default_context()\n",
            "VALUE = 2\n",
        ),
        ("def run(code):\n    exec(code)\n", "VALUE = 2\n"),
        ("VALUE = 1\n", "import os, sys\nsys.path.append(os.getcwd())\n"),
        (
            "VALUE = 1\n",
            "import os, sys\nfrom pathlib import Path\n"
            "sys.path.insert(0, str(Path(__file__).parent.parent))\n"
            "sys.path.insert(0, os.path.join('vendor', 'lib'))\n",
        ),
        ("import sys as runtime\nused = runtime.argv\n", "VALUE = 2\n"),
        (
            "VALUE = 1\n",
            "import sys\nfrom unittest import mock\n"
            "def patch(monkeypatch, stream, fake):\n"
            "    monkeypatch.setattr(sys, 'stdout', stream)\n"
            "    monkeypatch.setitem(sys.modules, 'xhtml2pdf', None)\n"
            "    return mock.patch.dict(sys.modules, {'ctypes': fake})\n",
        ),
        ("import flask\nlink = flask.url_for('index')\n", "VALUE = 2\n"),
        ("import flask\nbuilder = flask.url_for\n", "VALUE = 2\n"),
        (
            "VALUE = 1\n",
            "from flask import url_for as link\ndef keep(fn):\n    return fn\nkeep(link)\n",
        ),
        (
            "VALUE = 1\n",
            "import builtins, re\nreal_open = open\npattern = re.compile\n"
            "def quiet(monkeypatch):\n"
            "    monkeypatch.setattr(builtins, 'print', lambda *a, **k: None)\n",
        ),
        (
            "VALUE = 1\n",
            "from re import compile as regex_compile\npattern = regex_compile('x')\n"
            "import os.path as path\ndef sign(path, model, app):\n"
            "    evaluate = model.eval\n    app.jinja_env.globals['x'] = 1\n"
            "    return [path, evaluate]\n",
        ),
    ],
)
def test_url_for_stays_trusted_when_nothing_names_or_ships_a_fake(
    tmp_path, monkeypatch, helper, plugin
):
    _plugin_app(tmp_path, helper, plugin)
    assert _redirects(tmp_path, monkeypatch) == []


@pytest.mark.parametrize(
    "plugin",
    [
        "import flask\ndef install(evil):\n    flask.url_for = evil\n",
        "def install(evil):\n"
        "    __import__('os').sys.modules['flask'].__dict__.update(url_for=evil)\n",
        "import sys\ndef install(fake):\n    sys.modules['flask'] = fake\n",
        "import sys\ndef install(fake):\n    sys.modules.update(flask=fake)\n",
        "import sys, vendor\nsys.modules.update(((b'flask', vendor),))\n",
        "import sys\ndef install(fake):\n    sys.modules.setdefault('flask', fake)\n",
        "import flask\nfrom builtins import setattr as patch\n"
        "def install(evil):\n    patch(flask, 'url_for', evil)\n",
        "import flask\ndef evil(endpoint, **values):\n    return values['next']\n"
        "getattr = setattr\ngetattr(flask, 'url_for', evil)\n",
        "import flask.helpers\ndef install(evil):\n"
        "    flask.helpers.__dict__['url_for'] = evil\n",
        "import flask\ndef install(evil):\n    flask.__dict__.__ior__({'url_for': evil})\n",
        "import flask\ndef install(evil):\n    flask.__dict__.update(dict(url_for=evil))\n",
        "from importlib.machinery import SourceFileLoader\n"
        "SourceFileLoader('flask', 'vendor.py').load_module()\n",
        "import importlib\nimportlib.import_module('flask.helpers')\n",
        "def write(code):\n    open('cache/flask.py', 'w').write(code)\n",
        "exec(\"import sys\\nsys.modules['flask'] = sys.modules['os']\")\n",
        "import sys\ndef install(finder):\n    sys.meta_path.insert(0, finder)\n",
        "from sys import meta_path\ndef install(finder):\n"
        "    meta_path.insert(0, finder)\n",
        "import sys\ndef install(finder):\n"
        "    getattr(sys, 'meta_path').insert(0, finder)\n",
        "import site\nsite.addsitedir('vendor')\n",
    ],
)
def test_literal_naming_or_rewriting_the_provider_removes_trust(
    tmp_path, monkeypatch, plugin
):
    _plugin_app(tmp_path, "VALUE = 1\n", plugin)
    assert _redirects(tmp_path, monkeypatch) == REPORTED


@pytest.mark.parametrize(
    "plugin, extra",
    [
        ("import sys\nsys.path.insert(0, 'vendor')\n", ("vendor/flask.py", FAKE)),
        ("VALUE = 2\n", ("vendor/flask/__init__.py", FAKE)),
        ("VALUE = 2\n", ("vendor/flask.pyc", "compiled")),
        ("VALUE = 2\n", ("vendor/flask.cpython-312-darwin.so", "native")),
        ("VALUE = 2\n", ("asset/__pycache__/flask.cpython-312.pyc", "compiled")),
        ("VALUE = 2\n", ("node_modules/flask.py", FAKE)),
        ("import sys\nsys.path.insert(0, 'vendor.zip')\n", ("vendor.zip", ZIP)),
        ("import sys\nsys.path.insert(0, 'vendor.dat')\n", ("vendor.dat", ZIP)),
        ("VALUE = 2\n", ("static/images/logo.png", ZIP)),
        (
            "import os, sys\nos.chdir('node_modules')\nsys.path.insert(0, os.getcwd())\n",
            ("node_modules/flask.py", FAKE),
        ),
        (
            "from os import sys\nsys.path.insert(0, 'node_modules')\n",
            ("node_modules/flask.py", FAKE),
        ),
        (
            "import sys\nfrom pathlib import Path\n"
            "Path.parent = property(lambda self: Path('node_modules'))\n"
            "sys.path.insert(0, str(Path(__file__).parent))\n",
            ("node_modules/flask.py", FAKE),
        ),
        (
            "VALUE = 2\n",
            ("node_modules/pkg/patch.py", "import sys\nsys.modules['flask'] = sys\n"),
        ),
        ("VALUE = 2\n", ("vendor.pyc", ZIP)),
        (
            "VALUE = 2\n",
            ("asset.png", _zip_bytes(b"MZ" + b"x" * 20, b"comment")),
        ),
        (
            "from importlib.machinery import SourceFileLoader\n"
            "SourceFileLoader('shop.patch', 'node_modules/patch.pyi').load_module()\n",
            ("node_modules/patch.pyi", "import flask\nflask.url_for = None\n"),
        ),
        (
            "from importlib.machinery import SourceFileLoader\n"
            "SourceFileLoader('shop.patch', 'data/patch.txt').load_module()\n",
            ("data/patch.txt", "import flask\nflask.url_for = None\n"),
        ),
        (
            "exec(open('data/boot.cfg').read())\n",
            (
                "data/boot.cfg",
                "import sys\nsys.modules.pop('fl' + 'ask')\nimport flask\nflask.url_for = None\n",
            ),
        ),
        (
            "import flask\nfrom types import ModuleType\n"
            "class Evil(ModuleType):\n    pass\nflask.__class__ = Evil\n",
            None,
        ),
        (
            "from importlib.machinery import SourceFileLoader\nfrom pathlib import Path\n"
            "SourceFileLoader('shop.patch', str(Path(__file__).parents[2] / 'node_modules/patch.py')).load_module()\n",
            (
                "node_modules/patch.py",
                "f = __import__('fl' 'ask')\nsetattr(f, 'url_' 'for', None)\n",
            ),
        ),
        (
            "from importlib.machinery import SourceFileLoader\nfrom pathlib import Path\n"
            "SourceFileLoader('shop.patch', str(Path(__file__).parents[2] / 'node_modules' / 'patch')).load_module()\n",
            ("node_modules/patch", "import flask\nflask.url_for = None\n"),
        ),
        (
            "from importlib.machinery import SourceFileLoader as Loader\nfrom pathlib import Path\n"
            "Loader('shop.patch', str(Path(__file__).parents[2] / 'data/patch.txt')).load_module()\n",
            ("data/patch.txt", "import flask\nflask.url_for = None\n"),
        ),
        (
            "from pathlib import Path\nPATH = str(Path(__file__).parents[2] / 'data/patch.txt')\n"
            "exec(\"from importlib.machinery import SourceFileLoader; SourceFileLoader('shop.patch', PATH).load_module()\")\n",
            ("data/patch.txt", "import flask\nflask.url_for = None\n"),
        ),
        (
            "import flask as f\nfrom types import ModuleType\n"
            "class Evil(ModuleType):\n    pass\nholder = f\nholder.__class__ = Evil\n",
            None,
        ),
        (
            "def later(evil):\n    f.__class__ = evil\nimport flask as f\n",
            None,
        ),
        (
            "import os\nfrom importlib.machinery import SourceFileLoader\n"
            "os.path.join = lambda *parts: 'data/patch.txt'\n"
            "SourceFileLoader('x', os.path.join('safe.py')).load_module()\n",
            ("data/patch.txt", "import flask\nflask.url_for = None\n"),
        ),
        (
            "import runpy\nrunpy.run_path(compute_path())\n",
            None,
        ),
        (
            "from importlib.machinery import SourceFileLoader\nfrom os.path import join\n"
            "from pathlib import Path\n"
            "join = lambda _: str(Path(__file__).parents[2] / 'data/patch.txt')\n"
            "SourceFileLoader('shop.patch', join('safe.py')).load_module()\n",
            ("data/patch.txt", "import flask\nflask.url_for = None\n"),
        ),
        (
            "import builtins\nfrom pathlib import Path\n"
            "p = Path(__file__).parents[2] / 'data/patch.txt'\n"
            "builtins.exec(open(p).read())\n",
            ("data/patch.txt", "import flask\nflask.url_for = None\n"),
        ),
        (
            "from importlib.machinery import SourceFileLoader\nfrom pathlib import Path\n"
            "(__file__ := str(Path(__file__).parents[2] / 'data/patch.txt'))\n"
            "SourceFileLoader('shop.patch', __file__).load_module()\n",
            ("data/patch.txt", "import flask\nflask.url_for = None\n"),
        ),
        (
            "import flask\nfrom types import ModuleType\n"
            "class Evil(ModuleType):\n    pass\n(holder := flask).__class__ = Evil\n",
            None,
        ),
        (
            "import os\nfrom pathlib import Path\n"
            "from importlib.machinery import SourceFileLoader\n"
            "os.chdir(Path(__file__).parents[2] / 'data')\n"
            "SourceFileLoader('shop.patch', 'patch.txt').load_module()\n",
            ("data/patch.txt", "import flask\nflask.url_for = None\n"),
        ),
        (
            "from pathlib import Path\nfrom importlib.machinery import SourceFileLoader\n"
            "SourceFileLoader('x', str(Path(__file__).parents[1000000000000] / 'p.py')).load_module()\n",
            None,
        ),
        (
            "import flask\nfrom types import ModuleType\n"
            "class Evil(ModuleType):\n    pass\n(holder := flask)\nholder.__class__ = Evil\n",
            None,
        ),
        (
            "from pathlib import Path\nfrom importlib.machinery import SourceFileLoader\n"
            "match str(Path(__file__).parents[2] / 'data/patch.txt'):\n"
            "    case __file__:\n        pass\n"
            "SourceFileLoader('x', __file__).load_module()\n",
            ("data/patch.txt", "import flask\nflask.url_for = None\n"),
        ),
        (
            "from importlib.machinery import SourceFileLoader as L\nfrom pathlib import Path\n"
            "M = L\nM('shop.patch', str(Path(__file__).parents[2] / 'data/patch.txt')).load_module()\n",
            ("data/patch.txt", "import flask\nflask.url_for = None\n"),
        ),
        (
            "from builtins import exec as run\nrun(open('data/patch.txt').read())\n",
            ("data/patch.txt", "import flask\nflask.url_for = None\n"),
        ),
        (
            "import builtins\nget = getattr\nrun = get(builtins, 'exec')\n"
            "run(open('data/patch.txt').read())\n",
            ("data/patch.txt", "import flask\nflask.url_for = None\n"),
        ),
        (
            "import os\nfrom pathlib import Path\n"
            "from importlib.machinery import SourceFileLoader\n"
            "evil = str(Path(__file__).parents[2] / 'data/patch.txt')\n"
            "setattr(os.path, 'join', lambda *parts: evil)\n"
            "p = os.path.join(str(Path(__file__).parents[2]), 'safe.py')\n"
            "SourceFileLoader('x', p).load_module()\n",
            ("data/patch.txt", "import flask\nflask.url_for = None\n"),
        ),
        (
            "import os\nvars(os.path).update(join=lambda *parts: 'x')\n",
            None,
        ),
        (
            "(run,) = (exec,)\nrun(open('data/patch.txt').read())\n",
            ("data/patch.txt", "import flask\nflask.url_for = None\n"),
        ),
        (
            "import flask\nfrom types import ModuleType\n"
            "class Evil(ModuleType):\n    pass\n(holder,) = (flask,)\nholder.__class__ = Evil\n",
            None,
        ),
        (
            "import os\nfrom pathlib import Path\nfrom importlib.machinery import SourceFileLoader\n"
            "p = os.path\nsetattr(p, 'join', lambda *parts: 'x')\n"
            "SourceFileLoader('x', os.path.join(str(Path(__file__).parents[2]), 'safe.py')).load_module()\n",
            None,
        ),
        ("import os\nns = os.path.__dict__\nns['join'] = None\n", None),
        ("import os\nns = vars(os.path)\nns.update(join=None)\n", None),
        (
            "import os.path as p\ndef outer():\n    def inner(p):\n        return p\n"
            "    setattr(p, 'join', None)\n",
            None,
        ),
        (
            "from types import ModuleType\nclass Evil(ModuleType):\n    pass\ndef install():\n    import flask\n    (holder,) = (flask,)\n"
            "    holder.__class__ = Evil\n",
            None,
        ),
        (
            "import flask\nfrom types import ModuleType\nclass Evil(ModuleType):\n    pass\ndef install(module):\n    module.__class__ = Evil\n"
            "class C:\n    flask = None\n    def run(self):\n        install(flask)\n",
            None,
        ),
        (
            "import flask\nfrom types import ModuleType\nclass Evil(ModuleType):\n    pass\ndef install(module):\n    module.__class__ = Evil\n"
            "def outer(flask):\n    def inner():\n        global flask\n"
            "        install(flask)\n    inner()\n",
            None,
        ),
        (
            "import flask\nfrom types import ModuleType\nclass Evil(ModuleType):\n    pass\ndef install(module):\n    module.__class__ = Evil\n"
            "    return lambda fn: fn\n@install(flask)\ndef route(flask):\n    pass\n",
            None,
        ),
        (
            "from os import path\nholder = (path,)\nholder[0].join = lambda *parts: 'x'\n",
            None,
        ),
        (
            "import os\nos.path.join.__code__ = (lambda *parts: 'x').__code__\n",
            None,
        ),
        (
            "import flask\nfrom types import ModuleType\nclass Evil(ModuleType):\n    pass\n(holder,) = (flask,)\nflask = None\n"
            "holder.__class__ = Evil\n",
            None,
        ),
        (
            "import flask\nfrom types import ModuleType\nclass Evil(ModuleType):\n    pass\nclass C:\n    (holder,) = (flask,)\n    flask = None\n"
            "    holder.__class__ = Evil\n",
            None,
        ),
        (
            "import flask\nfrom types import ModuleType\nclass Evil(ModuleType):\n    pass\ndef patch(module):\n    module.__class__ = Evil\n"
            "    return 0\nclass C:\n    flask = None\n"
            "    hit = [patch(flask) for _ in range(1)]\n",
            None,
        ),
        (
            "from types import ModuleType\nclass Evil(ModuleType):\n    pass\ndef patch(module):\n    module.__class__ = Evil\n"
            "def run():\n    import flask\n    [(flask := patch(flask)) for _ in range(1)]\n",
            None,
        ),
        (
            "from pathlib import Path\nfrom importlib.machinery import SourceFileLoader\n"
            "SourceFileLoader('x', str(Path(__file__).parent / 'tools' / 'helper.py')).load_module()\n",
            ("shop/plugins/tools/helper.py", "VALUE = 3\n"),
        ),
        (
            "import builtins\nrun = getattr(builtins, 'exec')\nrun(open('data/patch.txt').read())\n",
            ("data/patch.txt", "import flask\nflask.url_for = None\n"),
        ),
        (
            "from types import ModuleType\nclass Evil(ModuleType):\n    pass\ndef patch(module):\n    module.__class__ = Evil\n"
            "def run():\n    import flask\n"
            "    [[(flask := patch(flask)) for _ in range(1)] for _ in range(1)]\n",
            None,
        ),
        (
            "from shop.helpers import flask\nfrom types import ModuleType\nclass Evil(ModuleType):\n    pass\n(holder,) = (flask,)\n"
            "holder.__class__ = Evil\n",
            ("shop/helpers.py", "import flask\n"),
        ),
        (
            "from shop.helpers import flask as f\nfrom types import ModuleType\nclass Evil(ModuleType):\n    pass\nf.__class__ = Evil\n",
            None,
        ),
        (
            "from ..helpers import flask\nfrom types import ModuleType\nclass Evil(ModuleType):\n    pass\n(holder,) = (flask,)\n"
            "holder.__class__ = Evil\n",
            ("shop/helpers.py", "import flask\n"),
        ),
        ("import flask\nflask.url_for.__globals__['current_app'] = None\n", None),
        (
            "import shop.helpers as h\nfrom types import ModuleType\nclass Evil(ModuleType):\n    pass\nh.flask.__class__ = Evil\n",
            None,
        ),
        (
            "import shop.helpers as h\nfrom types import ModuleType\nclass Evil(ModuleType):\n    pass\n(holder,) = (h.flask,)\nholder.__class__ = Evil\n",
            ("shop/helpers.py", "import flask\n"),
        ),
        ("import shop.helpers as h\nh.os.path.join = None\n", None),
    ],
)
def test_anything_loadable_as_the_provider_in_the_tree_removes_trust(
    tmp_path, monkeypatch, plugin, extra
):
    _plugin_app(tmp_path, "VALUE = 1\n", plugin, extra)
    assert _redirects(tmp_path, monkeypatch) == REPORTED


def test_subscript_store_keyed_by_a_path_does_not_unprove_it(tmp_path, monkeypatch):
    _plugin_app(
        tmp_path,
        "VALUE = 1\n",
        "import os\nfrom importlib.machinery import SourceFileLoader\n"
        "base = os.path.dirname(__file__)\ncache = {}\ncache[base] = 1\n"
        "SourceFileLoader('x', os.path.join(base, 'tools', 'helper.py')).load_module()\n",
        ("shop/plugins/tools/helper.py", "VALUE = 3\n"),
    )
    assert _redirects(tmp_path, monkeypatch) == []


def test_source_loader_with_a_harmless_literal_target_stays_trusted(
    tmp_path, monkeypatch
):
    _plugin_app(
        tmp_path,
        "VALUE = 1\n",
        "import importlib.util, os\n"
        "PATH = os.path.join(os.path.dirname(__file__), 'tools', 'helper.py')\n"
        "spec = importlib.util.spec_from_file_location('helper', PATH)\n"
        "module = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(module)\n",
        ("shop/plugins/tools/helper.py", "VALUE = 3\n"),
    )
    assert _redirects(tmp_path, monkeypatch) == []


def test_unreadable_directory_or_special_file_fails_closed(tmp_path, monkeypatch):
    _plugin_app(tmp_path, "VALUE = 1\n", "VALUE = 2\n", ("hidden/flask.py", FAKE))
    hidden = tmp_path / "hidden"
    hidden.chmod(0)
    try:
        result = _scan_result(tmp_path, monkeypatch)
        assert _redirect_locations(result, tmp_path) == REPORTED
        if result.get("analysis_errors"):
            _assert_permission_incomplete(result, tmp_path)
        else:
            # Permission checks can be suppressed by pathlib or bypassed by
            # the runtime; unreadable context must still revoke provider trust.
            assert result["analysis_summary"]["analysis_error_count"] == 0
    finally:
        hidden.chmod(0o755)
    other = tmp_path / "other"
    other.mkdir()
    (tmp_path / "hidden" / "flask.py").unlink()
    os.mkfifo(other / "input.pipe")
    assert _redirects(tmp_path, monkeypatch) == REPORTED


def test_permission_error_preserves_findings_and_marks_analysis_incomplete(
    tmp_path, monkeypatch
):
    from skylos.rules.danger import danger

    _plugin_app(tmp_path, "VALUE = 1\n", "VALUE = 2\n", ("hidden/flask.py", FAKE))
    real_scan = danger.scan_file_with_tree

    def denied_context(tree, file, findings, **kwargs):
        real_scan(tree, file, findings, **kwargs)
        if file == tmp_path / "shop/views.py":
            raise PermissionError(
                errno.EACCES, "Permission denied", str(tmp_path / "hidden")
            )

    monkeypatch.setattr(danger, "scan_file_with_tree", denied_context)
    result = _scan_result(tmp_path, monkeypatch)

    assert _redirect_locations(result, tmp_path) == REPORTED
    _assert_permission_incomplete(result, tmp_path)


def test_provider_module_escaping_from_an_imported_module_removes_trust(
    tmp_path, monkeypatch
):
    _plugin_app(
        tmp_path,
        "import flask as framework\ndef share(register):\n    register(framework)\n",
        "VALUE = 2\n",
    )
    assert _redirects(tmp_path, monkeypatch) == REPORTED


def test_skipped_and_loader_target_sources_are_scanned_within_caps(tmp_path):
    from skylos.rules.danger.import_proof import _sources_mention_provider

    write_fixture(tmp_path, "node_modules/pkg/old.py", "print 'python 2'\n")
    assert _sources_mention_provider(tmp_path, [], "flask", "url_for") is False
    write_fixture(
        tmp_path, "node_modules/pkg/patch.pyi", "import flask\nflask.url_for = 1\n"
    )
    assert _sources_mention_provider(tmp_path, [], "flask", "url_for") is True


def test_extra_source_budget_is_charged_on_every_check(tmp_path, monkeypatch):
    from skylos.analysis.ast_cache import python_ast_cache_session
    from skylos.rules.danger import import_proof
    from skylos.rules.danger.import_proof import _sources_mention_provider

    for index in range(3):
        write_fixture(tmp_path, f"node_modules/m{index}.py", "VALUE = 0\n")
    monkeypatch.setattr(import_proof, "_MAX_EXTRA_TOTAL_BYTES", 20)
    with python_ast_cache_session():
        assert _sources_mention_provider(tmp_path, [], "flask", "url_for") is True
        assert _sources_mention_provider(tmp_path, [], "flask", "url_for") is True


def test_oversized_skipped_source_fails_closed(tmp_path):
    from skylos.rules.danger.import_proof import _sources_mention_provider

    write_fixture(tmp_path, "node_modules/large.py", "#" + "x" * 2_100_000 + "\n")
    assert _sources_mention_provider(tmp_path, [], "flask", "url_for") is True


@pytest.mark.parametrize(
    "helpers, plugin",
    [
        (
            "import flask as f\n",
            "import shop.helpers as h\nfrom types import ModuleType\n"
            "class Evil(ModuleType):\n    pass\nh.f.__class__ = Evil\n",
        ),
        (
            "import builtins as b\n",
            "import shop.helpers as h\nh.b.open = None\n",
        ),
        (
            "from os import path as p\n",
            "import shop.helpers as h\nh.p.join = None\n",
        ),
        (
            "import flask as f\n",
            "from shop.helpers import f as provider\nfrom types import ModuleType\n"
            "class Evil(ModuleType):\n    pass\nprovider.__class__ = Evil\n",
        ),
        (
            "import builtins as b\n",
            "from shop.helpers import b as base\nbase.open = None\n",
        ),
        (
            'exec("import flask as f\\n")\n',
            "import shop.helpers as h\nfrom types import ModuleType\n"
            "class Evil(ModuleType):\n    pass\nh.f.__class__ = Evil\n",
        ),
    ],
)
def test_aliased_re_export_reached_by_attribute_removes_trust(
    tmp_path, monkeypatch, helpers, plugin
):
    _plugin_app(tmp_path, helpers, plugin)
    assert _redirects(tmp_path, monkeypatch) == REPORTED


def test_long_re_export_chain_is_followed_to_the_end(tmp_path, monkeypatch):
    _plugin_app(
        tmp_path,
        "VALUE = 1\n",
        "from shop.z01 import f1 as f0\nfrom types import ModuleType\n"
        "class Evil(ModuleType):\n    pass\nf0.__class__ = Evil\n",
    )
    for index in range(1, 40):
        write_fixture(
            tmp_path,
            f"shop/z{index:02}.py",
            f"from shop.z{index + 1:02} import f{index + 1} as f{index}\n",
        )
    write_fixture(tmp_path, "shop/z40.py", "import flask as f40\n")
    assert _redirects(tmp_path, monkeypatch) == REPORTED


def test_renamed_provider_member_can_be_passed_around(tmp_path, monkeypatch):
    _plugin_app(
        tmp_path,
        "from flask import request as req\n",
        "from shop.helpers import req\ndef consume(value):\n"
        "    return value is None\nconsume(req)\n",
    )
    assert _redirects(tmp_path, monkeypatch) == []


YAML_VIEW = (
    "import yaml\n"
    "def parse(payload):\n"
    "    return yaml.load(payload, Loader=yaml.SafeLoader)\n"
)


def _yaml_findings(root, monkeypatch, plugin):
    write_fixture(root, "shop/__init__.py", "")
    write_fixture(root, "shop/views.py", "from shop import plugins\n" + YAML_VIEW)
    write_fixture(root, "shop/plugins/__init__.py", LOADER)
    write_fixture(root, "shop/plugins/extra.py", plugin)
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    write_fixture(root, "pyproject.toml", '[project]\nname="shop"\n')
    result = json.loads(
        analyze(
            str(root),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            enable_sca=False,
            grep_verify=False,
            grep_cache=False,
            all_advice=False,
        )
    )
    assert not result.get("analysis_errors")
    return [
        f["line"]
        for f in result.get("danger", [])
        if f["rule_id"] == "SKY-D206" and f["file"].endswith("shop/views.py")
    ]


@pytest.mark.parametrize(
    "plugin",
    [
        "VALUE = 2\n",
        "from yaml import SafeLoader as SL\ndef weaken(cls):\n"
        "    cls.add_multi_constructor('tag:yaml.org,2002:python/object/apply:', None)\nweaken(SL)\n",
        "import yaml\nyaml.SafeLoader.add_constructor('!x', lambda loader, node: None)\n",
        "import yaml\nclass Child(yaml.SafeLoader):\n    pass\n"
        "Child.yaml_multi_constructors['tag:yaml.org,2002:python/object/apply:'] = None\n",
        "from yaml import *\nSafeLoader.add_multi_constructor('tag:yaml.org,2002:python/object/apply:', None)\n",
    ],
)
def test_class_provider_keeps_the_strict_result_when_the_proof_cannot_finish(
    tmp_path, monkeypatch, plugin
):
    assert _yaml_findings(tmp_path, monkeypatch, plugin)


def test_class_provider_stays_trusted_when_the_strict_proof_finishes(
    tmp_path, monkeypatch
):
    write_fixture(tmp_path, "shop/__init__.py", "")
    write_fixture(tmp_path, "shop/views.py", YAML_VIEW)
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    write_fixture(tmp_path, "pyproject.toml", '[project]\nname="shop"\n')
    result = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            enable_sca=False,
            grep_verify=False,
            grep_cache=False,
            all_advice=False,
        )
    )
    assert not result.get("analysis_errors")
    assert not [f for f in result.get("danger", []) if f["rule_id"] == "SKY-D206"]


def test_store_on_an_explicitly_imported_provider_submodule_removes_trust(
    tmp_path, monkeypatch
):
    _plugin_app(
        tmp_path,
        "VALUE = 1\n",
        "import flask.helpers\nclass Fake:\n    pass\nflask.helpers.current_app = Fake()\n",
    )
    assert _redirects(tmp_path, monkeypatch) == REPORTED


def test_unrelated_object_spelled_like_a_provider_alias_stays_trusted(
    tmp_path, monkeypatch
):
    _plugin_app(
        tmp_path,
        "import flask as app\n",
        "from shop.other import app\napp.user = 1\ndef consume(value):\n"
        "    return value\nconsume(app)\n",
        ("shop/other.py", "app = type('Box', (), {})()\n"),
    )
    assert _redirects(tmp_path, monkeypatch) == []


@pytest.mark.parametrize(
    "helpers, plugin, extra, expected",
    [
        (
            "VALUE = 1\n",
            "from flask import helpers\nclass Fake:\n    pass\nhelpers.current_app = Fake()\n",
            None,
            REPORTED,
        ),
        (
            "VALUE = 1\n",
            "import flask.helpers\ndef unrelated(flask):\n    return flask\n"
            "class Fake:\n    pass\nflask.helpers.current_app = Fake()\n",
            None,
            REPORTED,
        ),
        (
            "import flask as f\nimport flask.helpers\n",
            "from shop.helpers import f\nclass Fake:\n    pass\nf.helpers.current_app = Fake()\n",
            None,
            REPORTED,
        ),
        (
            "VALUE = 1\n",
            "import flask.helpers\nclass Fake:\n    pass\ngetattr(flask, 'helpers').current_app = Fake()\n",
            None,
            REPORTED,
        ),
        (
            "import flask as app\n",
            "from shop import other\nuse = other.app\n",
            ("shop/other.py", "app = object()\n"),
            [],
        ),
        (
            "app = type('Box', (), {})()\ndef unused():\n    import flask as app\n",
            "from shop.helpers import app\napp.user = 1\n",
            None,
            [],
        ),
        (
            "from flask import helpers as h\n",
            "from shop.helpers import h\nclass Fake:\n    pass\nh.current_app = Fake()\n",
            None,
            REPORTED,
        ),
        (
            "import flask as f\nimport flask.helpers\n",
            "import shop.helpers as h\nclass Fake:\n    pass\nh.f.helpers.current_app = Fake()\n",
            None,
            REPORTED,
        ),
        (
            "VALUE = 1\n",
            "from flask import helpers\nclass Fake:\n    pass\nalias = helpers\nalias.current_app = Fake()\n",
            None,
            REPORTED,
        ),
        (
            "class Box:\n    pass\nh = Box()\ndef outer():\n    global h\n"
            "    def nested():\n        from flask import helpers as h\n    nested()\nouter()\n",
            "from shop.helpers import h\nh.current_app = 1\n",
            None,
            [],
        ),
        (
            "def expose():\n    global f\n    import flask as f\nexpose()\n",
            "from shop.helpers import f\nclass Fake:\n    pass\nf.helpers.current_app = Fake()\n",
            None,
            REPORTED,
        ),
        (
            "VALUE = 1\n",
            "import flask\nfrom flask import g, session\n"
            "def save(user):\n    g.user = user\n    flask.g.name = 'x'\n    session.modified = True\n",
            None,
            [],
        ),
    ],
)
def test_writes_inside_the_provider_package_remove_trust(
    tmp_path, monkeypatch, helpers, plugin, extra, expected
):
    _plugin_app(tmp_path, helpers, plugin, extra)
    assert _redirects(tmp_path, monkeypatch) == expected


def test_installed_environment_packages_are_not_project_fakes(tmp_path, monkeypatch):
    _plugin_app(
        tmp_path,
        "VALUE = 1\n",
        "VALUE = 2\n",
        (".venv/lib/python3.12/site-packages/flask/__init__.py", FAKE),
    )
    write_fixture(tmp_path, ".venv/pyvenv.cfg", "home = /usr/bin\n")
    assert _redirects(tmp_path, monkeypatch) == []


def test_site_packages_outside_an_environment_is_project_code(tmp_path, monkeypatch):
    _plugin_app(
        tmp_path,
        "VALUE = 1\n",
        "import sys\nsys.path.insert(0, 'site-packages')\n",
        ("site-packages/flask.py", FAKE),
    )
    assert _redirects(tmp_path, monkeypatch) == REPORTED


def test_a_fake_added_between_scans_removes_trust(tmp_path, monkeypatch):
    _plugin_app(tmp_path, "VALUE = 1\n", "VALUE = 2\n")
    assert _redirects(tmp_path, monkeypatch) == []
    write_fixture(tmp_path, "vendor/flask.pyc", "compiled")
    assert _redirects(tmp_path, monkeypatch) == REPORTED


def _large_project(root, size, tail):
    write_fixture(root, "shop/__init__.py", "")
    write_fixture(
        root,
        "shop/views.py",
        "from shop import m0\nfrom shop.common import settings\n" + VIEW,
    )
    write_fixture(root, "shop/common.py", "settings = {}\n")
    for index in range(size):
        following = tail
        if index + 1 < size:
            following = f"from shop import m{index + 1}\n"
        write_fixture(
            root,
            f"shop/m{index}.py",
            "import json\nimport os.path\nfrom shop.common import settings\n"
            + following
            + f"VALUE_{index} = json.dumps(settings)\n",
        )


def test_url_for_stays_trusted_past_the_import_walk_limits(tmp_path, monkeypatch):
    _large_project(tmp_path, 180, "")
    assert _redirects(tmp_path, monkeypatch) == []


def test_rewrite_deep_in_a_large_project_still_removes_trust(tmp_path, monkeypatch):
    _large_project(
        tmp_path, 180, "import flask\ndef install(evil):\n    flask.url_for = evil\n"
    )
    assert _redirects(tmp_path, monkeypatch) == [("shop/views.py", 7)]


def test_mention_scan_finishes_on_a_deep_chain_and_nested_code_strings():
    from skylos.rules.danger.import_proof import _provider_mentions

    deep = "import sys\nfrom pathlib import Path\nx = Path(__file__)" + ".parent" * 350
    assert isinstance(_provider_mentions(ast.parse(deep), "flask", "url_for"), bool)
    inner = repr("import sys; sys.modules['fl' + 'ask'] = 1; print('flask')")
    nested = "exec(" + repr("exec(" + inner + ")") + ")"
    assert _provider_mentions(ast.parse(nested), "flask", "url_for") is True
