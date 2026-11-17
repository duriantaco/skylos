"""Acceptance cases: path uncertainty remains visible without inventing taint.

These fixtures are parsed by Skylos; none of their programs are executed.
"""

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.rules.danger.danger_fs import path_provenance

PATH_RULES = {"SKY-D215", "SKY-D324", "SKY-D325"}
READER = (
    "from pathlib import Path\n"
    "def _read(name):\n"
    "    return (Path('/srv/documents') / name).read_text()\n"
)


def _project(tmp_path, files):
    root = tmp_path / "project"
    (root / ".git").mkdir(parents=True)
    (root / "pyproject.toml").write_text('[project]\nname="path-acceptance"\n')
    for name, source in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source)
    return root


def _scan(root):
    return json.loads(analyze(str(root), enable_danger=True, grep_verify=False))


def _rows(report, section, symbol="_read"):
    return {
        row["rule_id"]: row
        for row in report.get(section, [])
        if row.get("rule_id") in PATH_RULES and row.get("symbol") == symbol
    }


def _status(row):
    return row["metadata"]["path_provenance"]["status"]


def _file_rows(report, section, relative_path, root):
    return {
        row["rule_id"]: row
        for row in report.get(section, [])
        if row.get("rule_id") in PATH_RULES
        and row.get("symbol") == "_read"
        and Path(row["file"]).relative_to(root).as_posix() == relative_path
    }


@pytest.mark.parametrize(
    "files",
    [
        {"library/__init__.py": "", "library/files.py": READER},
        {
            "files.py": READER,
            "plugins.py": "from plugin_host import register\nfrom files import _read\nregister(_read)\n",
        },
        {
            "files.py": READER,
            "app.py": "from external_data import fetch_name\nfrom files import _read\n_read(fetch_name())\n",
        },
    ],
    ids=["public-library-boundary", "escaped-callback", "opaque-return"],
)
def test_unresolved_path_is_visible_with_its_missing_edge(tmp_path, files):
    report = _scan(_project(tmp_path, files))
    visible = _rows(report, "danger")
    assert {"SKY-D215", "SKY-D325"} <= visible.keys()
    for rule in ("SKY-D215", "SKY-D325"):
        assert _status(visible[rule]) == "unknown"
        assert visible[rule]["metadata"]["path_provenance"]["unknown"]
        assert rule not in _rows(report, "suppressed")


def test_partial_scan_does_not_turn_unseen_callers_into_safety(tmp_path):
    root = _project(tmp_path, {"library/files.py": READER + "\n_read('index.txt')\n"})
    report = _scan(root / "library")
    row = _rows(report, "danger")["SKY-D215"]
    assert _status(row) == "unknown"
    assert row["metadata"]["path_provenance"]["complete_project"] is False
    assert "SKY-D215" not in _rows(report, "suppressed")


def test_untrusted_caller_wins_over_literal_and_unresolved_callers(tmp_path):
    root = _project(
        tmp_path,
        {
            "files.py": READER,
            "web.py": "from flask import Flask, request\nfrom files import _read\n"
            "from plugin_host import register\napp=Flask(__name__)\n"
            "register(_read)\n_read('index.txt')\n@app.get('/document')\n"
            "def document():\n    return _read(request.args['name'])\n",
        },
    )
    report = _scan(root)
    row = _rows(report, "danger")["SKY-D215"]
    assert _status(row) == "untrusted"
    assert row["metadata"]["path_provenance"]["untrusted"]
    assert "SKY-D215" not in _rows(report, "suppressed")


def test_request_arguments_reach_the_launched_script_sink(tmp_path):
    root = _project(
        tmp_path,
        {
            "worker.py": READER
            + "import sys\nif __name__=='__main__':\n    _read(sys.argv[1])\n",
            "web.py": "import subprocess, sys\nfrom flask import Flask, request\n"
            "app=Flask(__name__)\n@app.get('/document')\ndef document():\n"
            "    return subprocess.run([sys.executable, 'worker.py', request.args['name']])\n",
        },
    )
    report = _scan(root)
    row = _rows(report, "danger")["SKY-D215"]
    assert _status(row) == "untrusted"
    chain = row["metadata"]["path_provenance"]["untrusted"][0]
    assert any("web.py:" in step for step in chain)
    assert any("worker.py:" in step for step in chain)
    assert "SKY-D215" not in _rows(report, "suppressed")


def test_unrelated_remote_process_does_not_taint_an_operator_script(tmp_path):
    cwd = repr(str(tmp_path / "project"))
    root = _project(
        tmp_path,
        {
            "operator.py": READER
            + "import sys\nif __name__=='__main__':\n    _read(sys.argv[1])\n",
            "worker.py": "import sys\nprint(sys.argv[1])\n",
            "web.py": "import subprocess, sys\nfrom flask import Flask, request\n"
            "app=Flask(__name__)\n@app.get('/echo')\ndef echo():\n"
            f"    return subprocess.run([sys.executable, 'worker.py', request.args['text']], cwd={cwd})\n",
        },
    )
    report = _scan(root)
    assert "SKY-D215" not in _rows(report, "danger")
    assert _status(_rows(report, "suppressed")["SKY-D215"]) == "safe"


def test_proven_filename_guard_does_not_erase_symlink_read_review(tmp_path):
    root = _project(
        tmp_path,
        {
            "files.py": READER,
            "web.py": "import os\nfrom flask import request\nfrom files import _read\n"
            "def document():\n    return _read(os.path.basename(request.args['name']))\n",
        },
    )
    report = _scan(root)
    visible = _rows(report, "danger")
    assert "SKY-D215" not in visible
    assert "SKY-D325" in visible
    assert _status(visible["SKY-D325"]) == "untrusted"


@pytest.mark.parametrize(
    "body",
    [
        "    name=request.args['name']\n    result=_read(name)\n    name=os.path.basename(name)\n    return result\n",
        "    name=os.path.basename(request.args['name'])\n    name=request.args['other']\n    return _read(name)\n",
        "    return _read(basename(request.args['name']))\n",
    ],
    ids=["guard-after-sink", "reassigned-after-guard", "forged-guard"],
)
def test_ineffective_guard_cannot_hide_the_remote_path(tmp_path, body):
    root = _project(
        tmp_path,
        {
            "files.py": READER,
            "web.py": "import os\nfrom flask import request\nfrom files import _read\n"
            "def basename(value):\n    return value\n"
            "def document():\n" + body,
        },
    )
    report = _scan(root)
    assert _status(_rows(report, "danger")["SKY-D215"]) == "untrusted"


def test_exhausted_analysis_cannot_turn_a_path_safe(tmp_path, monkeypatch):
    monkeypatch.setattr(path_provenance, "_MAX_CALLER_DEPTH", 1)
    root = _project(
        tmp_path,
        {
            "files.py": READER,
            "entry.py": "import sys\nfrom files import _read\n"
            "def first(name):\n    return _read(name)\n"
            "def second(name):\n    return first(name)\n"
            "if __name__=='__main__':\n    second(sys.argv[1])\n",
        },
    )
    report = _scan(root)
    assert _status(_rows(report, "danger")["SKY-D215"]) == "incomplete"
    assert "SKY-D215" not in _rows(report, "suppressed")


def test_proven_private_literal_path_can_still_be_suppressed(tmp_path):
    root = _project(tmp_path, {"files.py": READER + "\n_read('index.txt')\n"})
    report = _scan(root)
    assert _rows(report, "danger") == {}
    assert _status(_rows(report, "suppressed")["SKY-D215"]) == "safe"


def test_child_path_does_not_inherit_taint_from_a_different_argv_slot(tmp_path):
    cwd = repr(str(tmp_path / "project"))
    root = _project(
        tmp_path,
        {
            "worker.py": READER
            + "import sys\nif __name__=='__main__':\n    _read(sys.argv[1])\n",
            "web.py": "import subprocess, sys\nfrom flask import Flask, request\n"
            "app=Flask(__name__)\n@app.get('/document')\ndef document():\n"
            f"    return subprocess.run([sys.executable, 'worker.py', 'index.txt', request.args['comment']], cwd={cwd})\n",
        },
    )
    report = _scan(root)
    assert "SKY-D215" not in _rows(report, "danger")
    assert _status(_rows(report, "suppressed")["SKY-D215"]) == "safe"


def test_process_target_identity_is_the_full_script_path(tmp_path):
    worker = READER + "import sys\nif __name__=='__main__':\n    _read(sys.argv[1])\n"
    cwd = repr(str(tmp_path / "project"))
    root = _project(
        tmp_path,
        {
            "jobs/worker.py": worker,
            "tools/worker.py": worker,
            "web.py": "import subprocess, sys\nfrom flask import Flask, request\n"
            "app=Flask(__name__)\n@app.get('/document')\ndef document():\n"
            f"    return subprocess.run([sys.executable, 'jobs/worker.py', request.args['name']], cwd={cwd})\n",
        },
    )
    report = _scan(root)
    assert (
        _status(_file_rows(report, "danger", "jobs/worker.py", root)["SKY-D215"])
        == "untrusted"
    )
    assert "SKY-D215" not in _file_rows(report, "danger", "tools/worker.py", root)
    assert (
        _status(_file_rows(report, "suppressed", "tools/worker.py", root)["SKY-D215"])
        == "safe"
    )


@pytest.mark.parametrize(
    "absolute_cwd", [False, True], ids=["relative-cwd", "absolute-cwd"]
)
def test_literal_process_cwd_selects_a_possible_or_exact_script(tmp_path, absolute_cwd):
    cwd = repr(str(tmp_path / "project" / "jobs") if absolute_cwd else "jobs")
    worker = READER + "import sys\nif __name__=='__main__':\n    _read(sys.argv[1])\n"
    root = _project(
        tmp_path,
        {
            "worker.py": worker,
            "jobs/worker.py": worker,
            "web.py": "import subprocess, sys\nfrom flask import Flask, request\n"
            "app=Flask(__name__)\n@app.get('/document')\ndef document():\n"
            f"    return subprocess.run([sys.executable, 'worker.py', request.args['name']], cwd={cwd})\n",
        },
    )
    report = _scan(root)
    assert (
        _status(_file_rows(report, "danger", "jobs/worker.py", root)["SKY-D215"])
        == "untrusted"
    )
    if absolute_cwd:
        assert "SKY-D215" not in _file_rows(report, "danger", "worker.py", root)
        assert (
            _status(_file_rows(report, "suppressed", "worker.py", root)["SKY-D215"])
            == "safe"
        )
    else:
        assert _status(_file_rows(report, "danger", "worker.py", root)["SKY-D215"]) in {
            "unknown",
            "incomplete",
        }
        assert "SKY-D215" not in _file_rows(report, "suppressed", "worker.py", root)


@pytest.mark.parametrize(
    "command",
    [
        "[sys.executable, '-c', request.args['code']]",
        "[sys.executable, '-m', 'opaque_worker_module', request.args['name']]",
    ],
    ids=["inline-code", "unindexed-module"],
)
def test_unmapped_python_launch_cannot_establish_operator_safety(tmp_path, command):
    root = _project(
        tmp_path,
        {
            "worker.py": READER
            + "import sys\nif __name__=='__main__':\n    _read(sys.argv[1])\n",
            "web.py": "import subprocess, sys\nfrom flask import Flask, request\n"
            "app=Flask(__name__)\n@app.get('/run')\ndef run():\n"
            f"    return subprocess.run({command})\n",
        },
    )
    report = _scan(root)
    row = _rows(report, "danger")["SKY-D215"]
    assert _status(row) in {"unknown", "incomplete"}
    assert "SKY-D215" not in _rows(report, "suppressed")


@pytest.mark.parametrize(
    "mutation, invocation",
    [
        ("subprocess.run = opaque_launch\n", "subprocess.run"),
        ("sys.executable = opaque_executable\n", "subprocess.run"),
        ("from subprocess import run\nrun = opaque_launch\n", "run"),
    ],
    ids=["replaced-subprocess-api", "replaced-interpreter", "rebound-launch-alias"],
)
def test_mutated_launch_provider_cannot_prove_child_safety(
    tmp_path, mutation, invocation
):
    root = _project(
        tmp_path,
        {
            "worker.py": READER
            + "import sys\nif __name__=='__main__':\n    _read(sys.argv[1])\n",
            "web.py": "import subprocess, sys\nfrom external_runner import opaque_launch, opaque_executable\n"
            "from flask import Flask, request\n"
            + mutation
            + "app=Flask(__name__)\n@app.get('/run')\ndef run():\n"
            f"    return {invocation}([sys.executable, 'worker.py', request.args['name']])\n",
        },
    )
    report = _scan(root)
    row = _rows(report, "danger")["SKY-D215"]
    assert _status(row) in {"unknown", "incomplete"}
    assert "SKY-D215" not in _rows(report, "suppressed")


def test_parent_filename_guard_remains_specific_to_traversal_after_transport(tmp_path):
    cwd = repr(str(tmp_path / "project"))
    root = _project(
        tmp_path,
        {
            "worker.py": READER
            + "import sys\nif __name__=='__main__':\n    _read(sys.argv[1])\n",
            "web.py": "import subprocess, sys, os\nfrom flask import Flask, request\n"
            "app=Flask(__name__)\n@app.get('/document')\ndef document():\n"
            "    name=os.path.basename(request.args['name'])\n"
            f"    return subprocess.run([sys.executable, 'worker.py', name], cwd={cwd})\n",
        },
    )
    report = _scan(root)
    assert "SKY-D215" not in _rows(report, "danger")
    assert _status(_rows(report, "danger")["SKY-D325"]) == "untrusted"


@pytest.mark.parametrize(
    "mutation",
    [
        "sys.argv[1] = request.args['name']\n",
        "sys.argv = request.args.getlist('paths')\n",
        "sys = opaque_provider\n",
    ],
    ids=["replaced-argv-item", "replaced-argv", "rebound-sys-provider"],
)
def test_mutated_child_argv_is_not_trusted_as_operator_input(tmp_path, mutation):
    root = _project(
        tmp_path,
        {
            "worker.py": READER
            + "import sys\nfrom flask import request\nfrom external_state import opaque_provider\n"
            + mutation
            + "if __name__=='__main__':\n    _read(sys.argv[1])\n",
        },
    )
    report = _scan(root)
    row = _rows(report, "danger")["SKY-D215"]
    assert _status(row) in {"untrusted", "unknown", "incomplete"}
    assert "SKY-D215" not in _rows(report, "suppressed")


def test_request_path_crosses_two_known_process_argument_edges(tmp_path):
    cwd = repr(str(tmp_path / "project"))
    root = _project(
        tmp_path,
        {
            "worker.py": READER
            + "import sys\nif __name__=='__main__':\n    _read(sys.argv[1])\n",
            "relay.py": "import subprocess, sys\n"
            "if __name__=='__main__':\n"
            f"    subprocess.run([sys.executable, 'worker.py', sys.argv[1]], cwd={cwd})\n",
            "web.py": "import subprocess, sys\nfrom flask import Flask, request\n"
            "app=Flask(__name__)\n@app.get('/document')\ndef document():\n"
            f"    return subprocess.run([sys.executable, 'relay.py', request.args['name']], cwd={cwd})\n",
        },
    )
    report = _scan(root)
    row = _rows(report, "danger")["SKY-D215"]
    assert _status(row) == "untrusted"
    chain = row["metadata"]["path_provenance"]["untrusted"][0]
    assert all(
        any(f"{name}:" in step for step in chain)
        for name in ("web.py", "relay.py", "worker.py")
    )
    assert "SKY-D215" not in _rows(report, "suppressed")


@pytest.mark.parametrize(
    "child", ["worker.py", "worker\n.py"], ids=["ordinary-name", "newline-name"]
)
def test_unmapped_argparse_field_keeps_review_for_every_valid_script_path(
    tmp_path, child
):
    cwd = repr(str(tmp_path / "project"))
    root = _project(
        tmp_path,
        {
            child: READER + "import argparse\nif __name__=='__main__':\n"
            "    parser=argparse.ArgumentParser()\n    parser.add_argument('name')\n"
            "    options=parser.parse_args()\n    _read(options.name)\n",
            "web.py": "import subprocess, sys\nfrom flask import Flask, request\n"
            "app=Flask(__name__)\n@app.get('/document')\ndef document():\n"
            f"    return subprocess.run([sys.executable, {child!r}, request.args['name']], cwd={cwd})\n",
        },
    )
    report = _scan(root)
    row = _rows(report, "danger")["SKY-D215"]
    assert _status(row) in {"unknown", "incomplete", "untrusted"}
    assert "SKY-D215" not in _rows(report, "suppressed")


def test_unmapped_click_parameter_does_not_become_operator_proof(tmp_path):
    cwd = repr(str(tmp_path / "project"))
    root = _project(
        tmp_path,
        {
            "worker.py": READER
            + "import click\n@click.command()\n@click.argument('name')\n"
            "def cli(name):\n    return _read(name)\n"
            "if __name__=='__main__':\n    cli()\n",
            "web.py": "import subprocess, sys\nfrom flask import Flask, request\n"
            "app=Flask(__name__)\n@app.get('/document')\ndef document():\n"
            f"    return subprocess.run([sys.executable, 'worker.py', request.args['name']], cwd={cwd})\n",
        },
    )
    report = _scan(root)
    row = _rows(report, "danger")["SKY-D215"]
    assert _status(row) in {"unknown", "incomplete", "untrusted"}
    assert "SKY-D215" not in _rows(report, "suppressed")


@pytest.mark.parametrize(
    "selector, launch_options",
    [
        ("os.environ['DOCUMENT']", "env={'DOCUMENT': request.args['name']}"),
        ("os.path.join(os.getcwd(), 'index.txt')", "cwd=request.args['folder']"),
    ],
    ids=["forwarded-environment", "forwarded-working-directory"],
)
def test_child_nonargv_operator_origin_can_be_controlled_by_parent(
    tmp_path, selector, launch_options
):
    worker = repr(str(tmp_path / "project" / "worker.py"))
    root = _project(
        tmp_path,
        {
            "worker.py": READER + "import os\nif __name__=='__main__':\n"
            f"    _read({selector})\n",
            "web.py": "import subprocess, sys\nfrom flask import Flask, request\n"
            "app=Flask(__name__)\n@app.get('/document')\ndef document():\n"
            f"    return subprocess.run([sys.executable, {worker}], {launch_options})\n",
        },
    )
    report = _scan(root)
    row = _rows(report, "danger")["SKY-D215"]
    assert _status(row) in {"unknown", "incomplete", "untrusted"}
    assert "SKY-D215" not in _rows(report, "suppressed")


@pytest.mark.parametrize(
    "selector",
    ["os.environ['DOCUMENT']", "os.path.join(os.getcwd(), 'index.txt')"],
    ids=["independent-environment", "independent-working-directory"],
)
def test_remote_argv_does_not_invent_taint_in_child_environment_or_cwd(
    tmp_path, selector
):
    cwd = repr(str(tmp_path / "project"))
    root = _project(
        tmp_path,
        {
            "worker.py": READER + "import os\nif __name__=='__main__':\n"
            f"    _read({selector})\n",
            "web.py": "import subprocess, sys\nfrom flask import Flask, request\n"
            "app=Flask(__name__)\n@app.get('/document')\ndef document():\n"
            f"    return subprocess.run([sys.executable, 'worker.py', request.args['unrelated']], cwd={cwd})\n",
        },
    )
    report = _scan(root)
    assert "SKY-D215" not in _rows(report, "danger")
    assert _status(_rows(report, "suppressed")["SKY-D215"]) == "safe"


def test_bounded_explanations_do_not_erase_a_later_process_controlled_origin(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(path_provenance, "_MAX_CHAINS", 4)
    cwd = repr(str(tmp_path / "project"))
    cli = (
        "import argparse\nfrom files import _read\n"
        "if __name__=='__main__':\n    parser=argparse.ArgumentParser()\n"
        "    parser.add_argument('name')\n    options=parser.parse_args()\n"
        "    _read(options.name)\n"
    )
    root = _project(
        tmp_path,
        {
            **{f"cli_{index}.py": cli for index in range(5)},
            "files.py": READER,
            "web.py": "import subprocess, sys\nfrom flask import Flask, request\n"
            "app=Flask(__name__)\n@app.get('/document')\ndef document():\n"
            f"    return subprocess.run([sys.executable, 'cli_4.py', request.args['name']], cwd={cwd})\n",
        },
    )
    report = _scan(root)
    row = _rows(report, "danger")["SKY-D215"]
    assert _status(row) in {"unknown", "incomplete", "untrusted"}
    proof = row["metadata"]["path_provenance"]
    assert len(proof.get("operator", [])) <= 4
    assert not any("cli_4.py:" in chain[0] for chain in proof.get("operator", []))
    assert "SKY-D215" not in _rows(report, "suppressed")


@pytest.mark.parametrize("lost_authority", ["missing", "truncated"])
def test_lost_operator_origin_authority_cannot_become_a_safety_proof(
    tmp_path, monkeypatch, lost_authority
):
    original_leaf = path_provenance._Facts.leaf.__func__

    def leaf(cls, kind, step, *, operator_origin=None):
        facts = original_leaf(cls, kind, step, operator_origin=operator_origin)
        if kind == path_provenance.OPERATOR:
            if lost_authority == "missing":
                facts.operator_origins.clear()
            facts.operator_origins_complete = False
        return facts

    monkeypatch.setattr(path_provenance._Facts, "leaf", classmethod(leaf))
    root = _project(
        tmp_path,
        {
            "worker.py": READER + "import argparse\nif __name__=='__main__':\n"
            "    parser=argparse.ArgumentParser()\n    parser.add_argument('name')\n"
            "    options=parser.parse_args()\n    _read(options.name)\n",
        },
    )
    report = _scan(root)
    row = _rows(report, "danger")["SKY-D215"]
    assert _status(row) in {"unknown", "incomplete"}
    assert "SKY-D215" not in _rows(report, "suppressed")


@pytest.mark.parametrize(
    "selector, arguments, launch_options",
    [
        ("os.environ['DOCUMENT']", "", "env={'DOCUMENT': request.args['name']}"),
        ("os.path.join(os.getcwd(), 'index.txt')", "", "cwd=request.args['folder']"),
        ("sys.argv[1]", ", request.args['name']", "cwd={cwd}"),
    ],
    ids=["imported-environment-return", "imported-cwd-return", "imported-argv-return"],
)
def test_operator_return_summary_keeps_the_calling_process_context(
    tmp_path, selector, arguments, launch_options
):
    worker = repr(str(tmp_path / "project" / "worker.py"))
    cwd = repr(str(tmp_path / "project"))
    launch_options = (
        launch_options.format(cwd=cwd) if "{cwd}" in launch_options else launch_options
    )
    root = _project(
        tmp_path,
        {
            "worker.py": READER + "from settings import get_document\n"
            "if __name__=='__main__':\n    _read(get_document())\n",
            "settings.py": "import os, sys\ndef get_document():\n"
            f"    return {selector}\n",
            "web.py": "import subprocess, sys\nfrom flask import Flask, request\n"
            "app=Flask(__name__)\n@app.get('/document')\ndef document():\n"
            f"    return subprocess.run([sys.executable, {worker}{arguments}], {launch_options})\n",
        },
    )
    report = _scan(root)
    row = _rows(report, "danger")["SKY-D215"]
    assert _status(row) in {"unknown", "incomplete", "untrusted"}
    assert "SKY-D215" not in _rows(report, "suppressed")


@pytest.mark.parametrize(
    "consumer",
    [
        "from settings import DOCUMENT\n_read(DOCUMENT)\n",
        "import settings\n_read(settings.DOCUMENT)\n",
    ],
    ids=["imported-constant", "imported-module-attribute"],
)
def test_imported_operator_value_keeps_the_importing_process_context(
    tmp_path, consumer
):
    worker = repr(str(tmp_path / "project" / "worker.py"))
    root = _project(
        tmp_path,
        {
            "worker.py": READER + consumer,
            "settings.py": "import os\nDOCUMENT=os.environ['DOCUMENT']\n",
            "web.py": "import subprocess, sys\nfrom flask import Flask, request\n"
            "app=Flask(__name__)\n@app.get('/document')\ndef document():\n"
            f"    return subprocess.run([sys.executable, {worker}], env={{'DOCUMENT':request.args['name']}})\n",
        },
    )
    report = _scan(root)
    row = _rows(report, "danger")["SKY-D215"]
    assert _status(row) in {"unknown", "incomplete", "untrusted"}
    assert "SKY-D215" not in _rows(report, "suppressed")
