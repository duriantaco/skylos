"""``codecs.open`` and ``io.open`` open a filesystem path exactly like ``open``.

Path traversal (SKY-D215), symlink-following writes (SKY-D324) and reads
(SKY-D325) use the same mode semantics for them as for the builtin.
"""

import json
from pathlib import Path

from skylos.analyzer import analyze
from skylos.core.safe_cache_io import write_text_no_symlink

PATH_RULES = {"SKY-D215", "SKY-D324", "SKY-D325"}


def _project(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "proj"
    (root / ".git").mkdir(parents=True)
    assert write_text_no_symlink(root / "pyproject.toml", '[project]\nname = "proj"\n')
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(path, text)
    return root


def _reported(root: Path, symbol: str) -> set[str]:
    result = json.loads(analyze(str(root), enable_danger=True))
    return {
        finding["rule_id"]
        for finding in result.get("danger") or []
        if finding.get("rule_id") in PATH_RULES and finding.get("symbol") == symbol
    }


ROUTE = """\
{imports}
from flask import Flask, request

app = Flask(__name__)


@app.route("/files")
def serve():
    name = request.args.get("name")
{body}
"""


def _route(tmp_path, imports, body):
    return _project(
        tmp_path,
        {"app.py": ROUTE.format(imports=imports, body=body)},
    )


def test_codecs_open_read_reports_traversal_and_symlink_read(tmp_path):
    root = _route(
        tmp_path,
        "import codecs",
        '    with codecs.open(name, "r", "utf-8") as handle:\n        return handle.read()\n',
    )
    assert _reported(root, "serve") == {"SKY-D215", "SKY-D325"}


def test_aliased_io_module_write_reports_traversal_and_symlink_write(tmp_path):
    root = _route(
        tmp_path,
        "import io as _io",
        '    with _io.open(name, "w") as handle:\n        handle.write("x")\n',
    )
    assert _reported(root, "serve") == {"SKY-D215", "SKY-D324"}


def test_imported_codecs_open_alias_reports_like_open(tmp_path):
    root = _route(
        tmp_path,
        "from codecs import open as copen",
        "    return copen(name).read()\n",
    )
    assert _reported(root, "serve") == {"SKY-D215", "SKY-D325"}


def test_codecs_open_keyword_path_and_append_mode_report_write(tmp_path):
    root = _route(
        tmp_path,
        "import codecs",
        '    handle = codecs.open(filename=name, mode="a")\n    handle.write("x")\n',
    )
    assert _reported(root, "serve") == {"SKY-D215", "SKY-D324"}


def test_io_open_binary_read_is_a_read_not_a_write(tmp_path):
    root = _route(
        tmp_path,
        "import io",
        '    return io.open(name, "rb").read()\n',
    )
    assert _reported(root, "serve") == {"SKY-D215", "SKY-D325"}


def test_helper_wrapping_codecs_open_reports_through_its_route_caller(tmp_path):
    root = _project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/store.py": "import codecs\n\n\n"
            "def load(path):\n    return codecs.open(path, encoding='utf-8').read()\n",
            "app/web.py": "from flask import Flask, request\n\nfrom app.store import load\n\n"
            "app = Flask(__name__)\n\n\n@app.route('/doc')\ndef doc():\n"
            "    return load(request.args['name'])\n",
        },
    )
    assert "SKY-D215" in _reported(root, "load")


def test_constant_codecs_and_io_paths_stay_quiet(tmp_path):
    root = _route(
        tmp_path,
        "import codecs\nimport io",
        '    with codecs.open("static/help.txt", "r", "utf-8") as handle:\n'
        '        text = handle.read()\n'
        '    with io.open("static/log.txt", "a") as log:\n'
        "        log.write(name)\n"
        "    return text\n",
    )
    assert _reported(root, "serve") == set()


def test_local_object_named_codecs_is_not_the_codecs_module(tmp_path):
    root = _route(
        tmp_path,
        "class Vault:\n    def open(self, key):\n        return {'key': key}\n\n\ncodecs = Vault()\n",
        "    return codecs.open(name)\n",
    )
    assert _reported(root, "serve") == set()
