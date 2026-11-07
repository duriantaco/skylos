import ast
import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.core.linter import LinterVisitor
from skylos.rules.danger.calls import DangerousCallsRule
from skylos.rules.danger.callable_bindings import _CallableIndex, callable_names
from skylos.rules.danger.danger import scan_ctx


CASES = [
    (
        "pickle_capture",
        "import pickle\nload = pickle.loads\ndef run(data):\n    return load(data)\n",
        {"SKY-D205"},
    ),
    (
        "pickle_capture_rebound_module",
        "import pickle, json\nload = pickle.loads\npickle = json\ndef run(data):\n    return load(data)\n",
        {"SKY-D205"},
    ),
    (
        "pickle_local_capture",
        "import pickle\ndef run(data):\n    load = pickle.loads\n    return load(data)\n",
        {"SKY-D205"},
    ),
    (
        "pickle_annotated_capture",
        "import pickle\nload: object = pickle.loads\ndef run(data):\n    return load(data)\n",
        {"SKY-D205"},
    ),
    (
        "pickle_tuple_capture",
        "import pickle, json\nload, other = pickle.loads, json.loads\ndef run(data):\n    return load(data)\n",
        {"SKY-D205"},
    ),
    (
        "pickle_branch_retains_unsafe",
        "import pickle, json\ndef run(data, flag):\n    load = json.loads\n    if flag:\n        load = pickle.loads\n    return load(data)\n",
        {"SKY-D205"},
    ),
    (
        "pickle_loop_retains_unsafe",
        "import pickle, json\ndef run(data, values):\n    load = pickle.loads\n    for item in values:\n        load = json.loads\n    return load(data)\n",
        {"SKY-D205"},
    ),
    (
        "pickle_closure_capture",
        "import pickle\ndef outer(data):\n    load = pickle.loads\n    def inner():\n        return load(data)\n    return inner()\n",
        {"SKY-D205"},
    ),
    (
        "pickle_late_import",
        "def run(data):\n    return load(data)\nfrom pickle import loads as load\n",
        {"SKY-D205"},
    ),
    (
        "pickle_source_order",
        "import pickle, json\ndef run(data):\n    load = pickle.loads\n    load(data)\n    load = json.loads\n    return load(data)\n",
        {"SKY-D205"},
    ),
    (
        "pickle_json_module_rebind",
        "import pickle, json\npickle = json\ndef run(data):\n    return pickle.loads(data)\n",
        set(),
    ),
    (
        "pickle_json_local_rebind",
        "import pickle, json\ndef run(data):\n    pickle = json\n    return pickle.loads(data)\n",
        set(),
    ),
    (
        "pickle_alias_rebind",
        "import pickle, json\nload = pickle.loads\nload = json.loads\ndef run(data):\n    return load(data)\n",
        set(),
    ),
    (
        "json_capture",
        "import json\nload = json.loads\ndef run(data):\n    return load(data)\n",
        set(),
    ),
    (
        "eval_capture",
        "calculate = eval\ndef run(data):\n    return calculate(data)\n",
        {"SKY-D201"},
    ),
    (
        "exec_capture",
        "execute = exec\ndef run(data):\n    execute(data)\n",
        {"SKY-D202"},
    ),
    (
        "builtin_import_capture",
        "from builtins import eval as calculate\ndef run(data):\n    return calculate(data)\n",
        {"SKY-D201"},
    ),
    (
        "eval_source_owned",
        "def eval(data):\n    return data\ndef run(data):\n    return eval(data)\n",
        set(),
    ),
    (
        "eval_source_owned_capture",
        "def eval(data):\n    return data\ncalculate = eval\ndef run(data):\n    return calculate(data)\n",
        set(),
    ),
    (
        "eval_other_scope_shadow",
        "def other(eval):\n    return eval\ndef run(data):\n    return eval(data)\n",
        {"SKY-D201"},
    ),
    (
        "command_capture",
        "import subprocess\nexecute = subprocess.run\ndef run(data):\n    execute(data, shell=True)\n",
        {"SKY-D209"},
    ),
    (
        "command_capture_no_shell",
        'import subprocess\nexecute = subprocess.run\ndef run(data):\n    execute(["/usr/bin/printf", "%s", data], shell=False)\n',
        set(),
    ),
    (
        "os_capture",
        "import os\nexecute = os.system\ndef run(data):\n    execute(data)\n",
        {"SKY-D203"},
    ),
    (
        "capture_mixed_families",
        "import pickle\ndef run(data, flag):\n    load = pickle.loads if flag else eval\n    return load(data)\n",
        {"SKY-D201", "SKY-D205"},
    ),
    (
        "pickle_capture_before_member_patch",
        "import pickle\nload = pickle.loads\npickle.loads = lambda data: data\ndef run(data):\n    return load(data)\n",
        {"SKY-D205"},
    ),
    (
        "pickle_capture_after_member_patch",
        "import pickle\npickle.loads = lambda data: data\nload = pickle.loads\ndef run(data):\n    return load(data)\n",
        set(),
    ),
    (
        "pickle_direct_after_member_patch",
        "import pickle\npickle.loads = lambda data: data\ndef run(data):\n    return pickle.loads(data)\n",
        set(),
    ),
    (
        "command_capture_before_member_patch",
        "import subprocess\nexecute = subprocess.run\nsubprocess.run = lambda data, shell=False: data\ndef run(data):\n    execute(data, shell=True)\n",
        {"SKY-D209"},
    ),
    (
        "command_capture_after_member_patch",
        "import subprocess\nsubprocess.run = lambda data, shell=False: data\nexecute = subprocess.run\ndef run(data):\n    execute(data, shell=True)\n",
        set(),
    ),
    (
        "builtin_capture_before_name_rebind",
        "calculate = eval\ndef eval(data):\n    return data\ndef run(data):\n    return calculate(data)\n",
        {"SKY-D201"},
    ),
]


@pytest.mark.parametrize("engine", ["rule", "scan_ctx"])
@pytest.mark.parametrize("name,source,expected", CASES, ids=[row[0] for row in CASES])
def test_captured_callable_identity(tmp_path, engine, name, source, expected):
    app = tmp_path / "app.py"
    app.write_text(source)
    if engine == "rule":
        linter = LinterVisitor([DangerousCallsRule()], str(app))
        linter.visit(ast.parse(source))
        findings = linter.findings
    else:
        findings = scan_ctx(tmp_path, [app])
    actual = {f["rule_id"] for f in findings}
    selected = {"SKY-D201", "SKY-D202", "SKY-D203", "SKY-D205", "SKY-D209"}
    assert actual & selected == expected
    if name == "pickle_source_order":
        assert {f["line"] for f in findings if f["rule_id"] == "SKY-D205"} == {4}


@pytest.mark.parametrize("unsafe", [False, True])
def test_captured_shell_api_survives_complete_output_and_gate(
    tmp_path, monkeypatch, unsafe
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    app = tmp_path / "app.py"
    app.write_text(
        "import subprocess\nfrom flask import Flask, request\napp=Flask(__name__)\n"
        + (
            "execute=subprocess.run\n"
            if unsafe
            else "class DataSink:\n    def run(self, text, shell=False):\n        return text\nsubprocess=DataSink()\nexecute=subprocess.run\n"
        )
        + '@app.post("/run")\ndef run():\n    return str(execute(request.data.decode(), shell=True))\n'
    )
    result = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
            grep_cache=False,
        )
    )
    assert result.get("analysis_summary", {}).get("total_files") == 1
    assert result.get("analysis_summary", {}).get("analysis_error_count") == 0
    assert not result.get("analysis_errors")
    rows = [
        f for f in result.get("danger", []) if f["rule_id"] in {"SKY-D209", "SKY-D212"}
    ]
    assert {f["rule_id"] for f in rows} == (
        {"SKY-D209", "SKY-D212"} if unsafe else set()
    )
    assert all(f["listing"]["listed"] for f in rows)
    passed, reasons = check_gate(result, {"gate": {"max_high": 0, "max_critical": 0}})
    assert passed is not unsafe, reasons


def test_capture_does_not_invent_installed_pickle_provider(tmp_path):
    (tmp_path / "pickle.py").write_text("def loads(data):\n    return data\n")
    app = tmp_path / "app.py"
    app.write_text(
        "import pickle\nload=pickle.loads\ndef run(data):\n    return load(data)\n"
    )
    rows = scan_ctx(tmp_path, [app, tmp_path / "pickle.py"])
    assert not any(row["rule_id"] == "SKY-D205" for row in rows)


def test_callable_work_limit_retains_existing_warning(tmp_path):
    tree = ast.parse(
        "import pickle, json\npickle=json\ndef run(data):\n    return pickle.loads(data)\n"
    )
    call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call))
    index = _CallableIndex(tree)
    index.remaining = 0
    tree._skylos_danger_callable_index = index
    assert callable_names(call, "pickle.loads", tree, str(tmp_path / "app.py")) == (
        "pickle.loads",
    )


def test_dynamic_namespace_does_not_certify_a_rebound_provider_safe(tmp_path):
    source = "import pickle, json\npickle=json\nglobals().update(providers)\ndef run(data):\n    return pickle.loads(data)\n"
    app = tmp_path / "app.py"
    app.write_text(source)
    rows = scan_ctx(tmp_path, [app])
    assert any(row["rule_id"] == "SKY-D205" for row in rows)
