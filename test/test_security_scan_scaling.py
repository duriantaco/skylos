"""Project-wide security facts are derived once, not once per reader.

Both checks count work instead of timing it, so they do not depend on the
machine. Each also asserts the finding itself, so a cache that returned the
wrong answer would fail here too.
"""

import json
from pathlib import Path

from skylos.analyzer import analyze
from skylos.rules.danger.danger import scan_ctx
from skylos.rules.danger.danger_cmd import cmd_flow
from skylos.rules.danger.danger_fs import path_provenance
from test.fixture_paths import write_fixture


def test_command_factory_facts_scale_with_modules_not_with_their_square(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    root = tmp_path.resolve()
    modules = 12
    paths = []
    for index in range(modules):
        source = (
            "import os\n\n\n"
            f"class Job{index}:\n    pass\n\n\n"
            f"def make{index}():\n    return Job{index}()\n\n\n"
            f"def run{index}(user):\n    os.system('echo ' + user)\n"
        )
        paths.append(write_fixture(root, f"job{index}.py", source))

    built = []
    original = cmd_flow.UntrustedSourceIndex

    def counting(tree):
        built.append(tree)
        return original(tree)

    monkeypatch.setattr(cmd_flow, "UntrustedSourceIndex", counting)

    rows = [row for row in scan_ctx(root, paths) if row["rule_id"] == "SKY-D212"]

    assert sorted((Path(row["file"]).name, row["line"]) for row in rows) == sorted(
        (f"job{index}.py", 13) for index in range(modules)
    )
    assert len(built) <= 4 * modules


def test_reexport_chain_is_followed_once_per_import(tmp_path, monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    root = tmp_path.resolve()
    (root / ".git").mkdir()
    write_fixture(root, "pyproject.toml", '[project]\nname = "proj"\n')
    depth = 12
    write_fixture(root, "m0.py", 'BASE = "/srv/data"\n')
    for index in range(1, depth + 1):
        write_fixture(
            root,
            f"m{index}.py",
            f"try:\n    from m{index - 1} import BASE\n"
            f"except ImportError:\n    from m{index - 1} import BASE\n",
        )
    write_fixture(
        root,
        "store.py",
        f"import os\nfrom m{depth} import BASE\n\n\n"
        "def read_doc(name):\n"
        "    with open(os.path.join(BASE, name)) as handle:\n"
        "        return handle.read()\n",
    )
    write_fixture(
        root,
        "app.py",
        "from flask import Flask, request\nfrom store import read_doc\n\n"
        "app = Flask(__name__)\n\n\n"
        "@app.route('/doc')\ndef doc():\n"
        "    return read_doc(request.args['name'])\n",
    )

    followed = []
    original = path_provenance._Tracer._imported_uncached

    def counting(self, unit, bind, name):
        followed.append(name)
        return original(self, unit, bind, name)

    monkeypatch.setattr(path_provenance._Tracer, "_imported_uncached", counting)

    report = json.loads(analyze(str(root), enable_danger=True))

    reported = {
        (row["rule_id"], Path(row["file"]).name, row["line"])
        for row in report["danger"]
    }
    assert ("SKY-D215", "store.py", 6) in reported
    assert len(followed) <= 8 * depth


def test_import_cycle_does_not_hide_a_traversal(tmp_path, monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    root = tmp_path.resolve()
    (root / ".git").mkdir()
    write_fixture(root, "pyproject.toml", '[project]\nname = "proj"\n')
    write_fixture(root, "left.py", "from right import BASE\n")
    write_fixture(root, "right.py", "from left import BASE\n")
    write_fixture(
        root,
        "store.py",
        "import os\nfrom left import BASE\n\n\n"
        "def read_doc(name):\n"
        "    with open(os.path.join(BASE, name)) as handle:\n"
        "        return handle.read()\n",
    )
    write_fixture(
        root,
        "app.py",
        "from flask import Flask, request\nfrom store import read_doc\n\n"
        "app = Flask(__name__)\n\n\n"
        "@app.route('/doc')\ndef doc():\n"
        "    return read_doc(request.args['name'])\n",
    )

    report = json.loads(analyze(str(root), enable_danger=True))

    reported = {
        (row["rule_id"], Path(row["file"]).name, row["line"])
        for row in report["danger"]
    }
    assert ("SKY-D215", "store.py", 6) in reported


def test_import_cycle_through_an_assignment_still_settles(tmp_path, monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    root = tmp_path.resolve()
    (root / ".git").mkdir()
    write_fixture(root, "pyproject.toml", '[project]\nname = "proj"\n')
    write_fixture(root, "a.py", "from b import x\n")
    write_fixture(
        root,
        "b.py",
        "from a import x as y\n\nx = {'a': 'r.txt'}\nif y:\n    x = y\n",
    )
    write_fixture(
        root,
        "store.py",
        "import os\nfrom a import x\n\n\n"
        "def read_doc(name):\n"
        "    with open(os.path.join('/srv', x[name])) as handle:\n"
        "        return handle.read()\n",
    )
    write_fixture(
        root,
        "app.py",
        "from flask import Flask, request\nfrom store import read_doc\n\n"
        "app = Flask(__name__)\n\n\n"
        "@app.route('/doc')\ndef doc():\n"
        "    return read_doc(request.args['name'])\n",
    )

    report = json.loads(analyze(str(root), enable_danger=True))

    assert not [
        row
        for row in report.get("danger", [])
        if row["rule_id"] in {"SKY-D215", "SKY-D325"}
        and row["file"].endswith("store.py")
    ]
