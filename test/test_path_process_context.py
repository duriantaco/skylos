"""Static subprocess argument edges preserve scope and unresolved boundaries."""

import ast
import json

import pytest

from skylos.analyzer import analyze
from skylos.rules.danger.danger_fs import path_process as process
from skylos.rules.danger.danger_fs.path_provenance import _Project
from skylos.rules.danger.import_proof import provider_binding_is_stable


def _project(
    tmp_path,
    command,
    *,
    extra="",
    children=("child.py",),
    launcher="web.py",
    extra_files=None,
):
    root = tmp_path.resolve()
    files = {
        launcher: (
            "import subprocess, sys\nfrom flask import request\n"
            + extra
            + "\ndef run_report():\n    "
            + command
            + "\n"
        ),
        **{name: "import sys\nprint(sys.argv[1])\n" for name in children},
    }
    files.update(extra_files or {})
    project = _Project(root, complete=True)
    for name, source in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        project._add_python(path, source)
    project._index()
    return project, {name: project.by_path[root / name] for name in files}


@pytest.mark.parametrize(
    "command",
    [
        "subprocess.run([sys.executable, 'child.py', request.args['doc']])",
        "subprocess.Popen((sys.executable, 'child.py', request.args['doc']))",
        "subprocess.check_output(args=[sys.executable, 'child.py', request.args['doc']])",
        "subprocess.call([sys.executable, 'child.py', request.args['doc']], shell=False, cwd=None, env=None)",
    ],
)
def test_fixed_argv_maps_the_parent_expression_in_its_original_scope(tmp_path, command):
    project, units = _project(tmp_path, command)

    edges = process.python_argv_sources(project, units["child.py"], 1)

    assert len(edges) == 1
    edge = edges[0]
    assert edge.unit is units["web.py"]
    assert edge.scope.kind == "function" and edge.scope.node.name == "run_report"
    assert ast.unparse(edge.argument) == "request.args['doc']"
    assert edge.argv_index == 1 and edge.command_index == 2
    assert edge.script_path == units["child.py"].path
    assert edge.exact_target is False


@pytest.mark.parametrize(
    "index, expected",
    [
        (0, "'child.py'"),
        (1, "'fixed'"),
        (2, "request.args['doc']"),
        (-1, "request.args['doc']"),
        (-2, "'fixed'"),
    ],
)
def test_argv_position_does_not_taint_an_unrelated_argument(tmp_path, index, expected):
    project, units = _project(
        tmp_path,
        "subprocess.run([sys.executable, 'child.py', 'fixed', request.args['doc']])",
    )

    (edge,) = process.python_argv_sources(project, units["child.py"], index)

    assert ast.unparse(edge.argument) == expected


def test_import_aliases_keep_the_actual_runtime_provider(tmp_path):
    project, units = _project(
        tmp_path,
        "launch([interpreter, 'child.py', request.args['doc']])",
        extra="from subprocess import run as launch\nfrom sys import executable as interpreter\n",
    )

    assert len(process.python_argv_sources(project, units["child.py"], 1)) == 1


@pytest.mark.parametrize("mode", ["absolute_script", "absolute_cwd"])
def test_an_explicit_absolute_target_has_exact_target_evidence(tmp_path, mode):
    root = tmp_path.resolve()
    if mode == "absolute_script":
        command = f"subprocess.run([sys.executable, {str(root / 'child.py')!r}, request.args['doc']])"
    else:
        command = f"subprocess.run([sys.executable, 'child.py', request.args['doc']], cwd={str(root)!r})"
    project, units = _project(tmp_path, command)

    (edge,) = process.python_argv_sources(project, units["child.py"], 1)

    assert edge.exact_target is True


def test_unknown_cwd_keeps_suffix_candidates_instead_of_assuming_scan_root(tmp_path):
    project, units = _project(
        tmp_path,
        "subprocess.run([sys.executable, 'child.py', request.args['doc']])",
        children=("one/child.py", "two/child.py", "operator.py"),
    )

    for name in ("one/child.py", "two/child.py"):
        (edge,) = process.python_argv_sources(project, units[name], 1)
        assert edge.exact_target is False
    assert process.python_argv_launches(project, units["operator.py"]) == ()
    assert process.python_argv_ambiguous_launches(project) == ()


@pytest.mark.parametrize(
    "command, reason",
    [
        ("subprocess.run([sys.executable, 'child.py', *values])", "starred"),
        (
            "subprocess.run([sys.executable, 'child.py', request.args['doc']], **options)",
            "unpacked",
        ),
        (
            "subprocess.run([sys.executable, 'child.py', request.args['doc']], shell=True)",
            "shell",
        ),
        (
            "subprocess.run([sys.executable, 'child.py', request.args['doc']], executable=other)",
            "overridden",
        ),
        (
            "subprocess.run([sys.executable, 'child.py', request.args['doc']], env=environment)",
            "environment",
        ),
        (
            "subprocess.run([sys.executable, 'child.py', request.args['doc']], cwd=directory)",
            "working directory",
        ),
    ],
)
def test_unsupported_launch_options_keep_a_targeted_uncertainty(
    tmp_path, command, reason
):
    project, units = _project(tmp_path, command)
    child = units["child.py"]

    assert process.python_argv_sources(project, child, 1) == ()
    (launch,) = process.python_argv_launches(project, child)
    assert reason in launch.uncertainty
    (uncertainty,) = process.python_argv_uncertainties(project, child)
    assert reason in uncertainty.reason
    assert uncertainty.call is launch.call


@pytest.mark.parametrize(
    "command",
    [
        "subprocess.run(command)",
        "subprocess.run(['python3', 'child.py', request.args['doc']])",
        "subprocess.run([sys.executable, target, request.args['doc']])",
        "subprocess.run([sys.executable, '-m', request.args['module']])",
    ],
)
def test_unresolved_process_target_is_not_an_absence_of_possible_launches(
    tmp_path, command
):
    project, units = _project(tmp_path, command)

    assert process.python_argv_sources(project, units["child.py"], 1) == ()
    (ambiguous,) = process.python_argv_ambiguous_launches(project)
    assert ambiguous.script_path is None and ambiguous.uncertainty
    assert ambiguous.command is not None


def test_modified_subprocess_provider_does_not_create_a_precise_argv_edge(tmp_path):
    project, units = _project(
        tmp_path,
        "subprocess.run([sys.executable, 'child.py', request.args['doc']])",
        extra="subprocess.run = replacement\n",
    )

    assert process.python_argv_sources(project, units["child.py"], 1) == ()
    (launch,) = process.python_argv_launches(project, units["child.py"])
    assert "provider" in launch.uncertainty


def test_a_mixed_callable_keeps_the_possible_process_launch_unresolved(tmp_path):
    project, units = _project(
        tmp_path,
        "launch([sys.executable, 'child.py', request.args['doc']])",
        extra="launch = subprocess.run if enabled else print\n",
    )

    assert process.python_argv_sources(project, units["child.py"], 1) == ()
    (launch,) = process.python_argv_launches(project, units["child.py"])
    assert "mixed targets" in launch.uncertainty


def test_an_imported_interpreter_mutation_does_not_create_a_precise_edge(tmp_path):
    (tmp_path / "patcher.py").write_text("import sys\nsys.executable = replacement\n")
    project, units = _project(
        tmp_path,
        "subprocess.run([sys.executable, 'child.py', request.args['doc']])",
        extra="import patcher\n",
    )

    assert process.python_argv_sources(project, units["child.py"], 1) == ()
    assert process.python_argv_ambiguous_launches(project)


@pytest.mark.parametrize(
    "mutation",
    ["sys.executable = replacement", "setattr(sys, 'executable', replacement)"],
)
def test_modified_interpreter_never_creates_a_precise_argv_edge(tmp_path, mutation):
    project, units = _project(
        tmp_path,
        "subprocess.run([sys.executable, 'child.py', request.args['doc']])",
        extra=mutation + "\n",
    )

    assert process.python_argv_sources(project, units["child.py"], 1) == ()
    assert process.python_argv_ambiguous_launches(project)


def test_completed_index_is_reused_for_other_argument_queries(tmp_path, monkeypatch):
    project, units = _project(
        tmp_path,
        "subprocess.run([sys.executable, 'child.py', request.args['doc'], 'fixed'])",
    )
    process.python_argv_sources(project, units["child.py"], 1)

    def resolve_again(*_args, **_kwargs):
        raise AssertionError("completed process index was rebuilt")

    monkeypatch.setattr(project, "values", resolve_again)
    (edge,) = process.python_argv_sources(project, units["child.py"], 2)
    assert ast.unparse(edge.argument) == "'fixed'"


def test_launch_budget_does_not_publish_a_partial_index(tmp_path, monkeypatch):
    project, units = _project(
        tmp_path,
        "subprocess.run([sys.executable, 'child.py', request.args['doc']]); "
        "subprocess.run([sys.executable, 'child.py', 'fixed'])",
    )
    monkeypatch.setattr(process, "_MAX_LAUNCHES", 1)

    with pytest.raises(ValueError, match="budget"):
        process.python_argv_sources(project, units["child.py"], 1)

    assert not hasattr(project, "_python_process_launch_index")


def test_python_directory_execution_maps_its_main_source(tmp_path):
    project, units = _project(
        tmp_path,
        "subprocess.run([sys.executable, '.', request.args['doc']])",
        children=("__main__.py", "operator.py"),
    )

    (edge,) = process.python_argv_sources(project, units["__main__.py"], 1)
    assert ast.unparse(edge.argument) == "request.args['doc']"
    assert process.python_argv_launches(project, units["operator.py"]) == ()


@pytest.mark.parametrize(
    "command",
    [
        "os.system(request.args['command'])",
        "os.execv('/usr/bin/python3', ['python3', 'child.py', request.args['doc']])",
        "asyncio.create_subprocess_exec(sys.executable, 'child.py', request.args['doc'])",
    ],
)
def test_other_recognized_transports_remain_ambiguous(tmp_path, command):
    project, units = _project(tmp_path, command, extra="import os, asyncio\n")

    assert process.python_argv_sources(project, units["child.py"], 1) == ()
    assert process.python_argv_ambiguous_launches(project)


def test_an_unindexed_child_does_not_publish_an_empty_launch_set(tmp_path):
    project, units = _project(
        tmp_path,
        "subprocess.run([sys.executable, 'missing.py', request.args['doc']])",
    )

    assert process.python_argv_launches(project, units["child.py"]) == ()
    (ambiguous,) = process.python_argv_ambiguous_launches(project)
    assert "outside the indexed" in ambiguous.uncertainty


@pytest.mark.parametrize("expression", ["sys.argv[1]", "sys.argv[-1]", "arguments[1]"])
def test_native_argv_element_read_does_not_escape_the_mutable_list(
    tmp_path, expression
):
    path = tmp_path / "worker.py"
    source = (
        "import sys\narguments=sys.argv\ndef main():\n    sink(" + expression + ")\n"
    )
    path.write_text(source)

    assert provider_binding_is_stable("sys.argv", ast.parse(source), path, tmp_path)


@pytest.mark.parametrize(
    "effect",
    [
        "sink(sys.argv)",
        "arguments=sys.argv\nsink(arguments)",
        "sys.argv[1]=replacement",
        "del sys.argv[1]",
        "sys.argv=replacement",
        "arguments=sys.argv\narguments.append(replacement)",
        "arguments=sys.argv\narguments[1]=replacement",
        "setattr(sys, 'argv', replacement)",
        "sink(sys.argv[index])",
        "sink(sys.argv[:])",
    ],
)
def test_argv_mutation_or_whole_list_escape_still_invalidates_provider_proof(
    tmp_path, effect
):
    path = tmp_path / "worker.py"
    source = "import sys\n" + effect + "\nsink(sys.argv[1])\n"
    path.write_text(source)

    assert not provider_binding_is_stable("sys.argv", ast.parse(source), path, tmp_path)


@pytest.mark.parametrize("remote", [False, True])
def test_positional_exec_environment_cannot_be_mistaken_for_operator_input(
    tmp_path, remote
):
    root = tmp_path.resolve()
    (root / ".git").mkdir()
    (root / "pyproject.toml").write_text('[project]\nname="exec-env-proof"\n')
    (root / "worker.py").write_text(
        "import os\nfrom pathlib import Path\n"
        "def _read(name):\n    return (Path('/srv') / name).read_text()\n"
        "if __name__ == '__main__':\n    _read(os.environ['DOCUMENT'])\n"
    )
    value = "request.args['name']" if remote else "'index.txt'"
    (root / "web.py").write_text(
        "import os, sys\nfrom flask import Flask, request\napp=Flask(__name__)\n"
        "@app.get('/report')\ndef report():\n"
        "    return os.execve(sys.executable, [sys.executable, 'worker.py'], "
        "{'DOCUMENT': " + value + "})\n"
    )

    report = json.loads(analyze(str(root), enable_danger=True, grep_verify=False))
    rows = {
        section: [
            row
            for row in report.get(section, [])
            if row.get("symbol") == "_read" and row.get("rule_id") == "SKY-D215"
        ]
        for section in ("danger", "suppressed")
    }
    if remote:
        assert len(rows["danger"]) == 1
        assert rows["danger"][0]["metadata"]["path_provenance"]["status"] == "unknown"
        assert rows["suppressed"] == []
    else:
        assert rows["danger"] == []
        assert rows["suppressed"][0]["metadata"]["path_provenance"]["status"] == "safe"


def test_runtime_context_follows_imports_without_joining_shared_importers(tmp_path):
    project, units = _project(
        tmp_path,
        "subprocess.run([sys.executable, 'worker.py'], env={'DOCUMENT':request.args['name']})",
        children=("worker.py", "operator.py"),
        extra_files={
            "worker.py": "import middle\n",
            "middle.py": "import settings\n",
            "settings.py": "import os\nDOCUMENT=os.environ['DOCUMENT']\n",
            "operator.py": "import settings\n",
        },
    )

    (launch,) = process.python_process_context_launches(project, units["settings.py"])
    assert launch.script_path == units["worker.py"].path
    assert process.python_process_context_launches(project, units["operator.py"]) == ()
    assert process.python_argv_launches(project, units["settings.py"]) == ()


def test_completed_runtime_context_index_is_reused(tmp_path, monkeypatch):
    project, units = _project(
        tmp_path,
        "subprocess.run([sys.executable, 'child.py'])",
        extra_files={
            "child.py": "import settings\n",
            "settings.py": "VALUE='index.txt'\n",
        },
    )
    process.python_process_context_launches(project, units["settings.py"])

    def imports_again(*_args):
        raise AssertionError("completed runtime context index was rebuilt")

    monkeypatch.setattr(project, "imported_units", imports_again)
    assert process.python_process_context_launches(project, units["child.py"])


def test_runtime_context_budget_cannot_publish_partial_negative_answers(
    tmp_path, monkeypatch
):
    project, units = _project(
        tmp_path,
        "subprocess.run([sys.executable, 'child.py'])",
        extra_files={
            "child.py": "import settings\n",
            "settings.py": "VALUE='index.txt'\n",
        },
    )
    monkeypatch.setattr(process, "_MAX_CONTEXT_WORK", 1)

    for _ in range(2):
        with pytest.raises(ValueError, match="context budget"):
            process.python_process_context_launches(project, units["settings.py"])
    assert not hasattr(project, "_python_process_context_index")


@pytest.mark.parametrize(
    "implicit", [False, True], ids=["dynamic-loader", "startup-hook"]
)
def test_opaque_runtime_context_is_uncertain_instead_of_a_safety_proof(
    tmp_path, implicit
):
    extra_files = {"unrelated.py": "VALUE='index.txt'\n"}
    if implicit:
        extra_files["sitecustomize.py"] = "import unrelated\n"
    else:
        extra_files["child.py"] = (
            "import importlib\nimportlib.import_module(module_name)\n"
        )
    project, units = _project(
        tmp_path,
        "subprocess.run([sys.executable, 'child.py'])",
        extra_files=extra_files,
    )

    (launch,) = process.python_process_context_launches(project, units["unrelated.py"])
    assert launch.uncertainty
    assert ("startup" if implicit else "dynamic loader") in launch.uncertainty
