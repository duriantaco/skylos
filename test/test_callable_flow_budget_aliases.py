"""The bounded callable flow must keep captured native identities."""

import ast
import json

import pytest

from skylos.core.linter import LinterVisitor
from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.reporting.listing import is_listed
from skylos.rules.danger.calls import DangerousCallsRule
from skylos.rules.danger.callable_bindings import _CallableIndex
from skylos.rules.danger.danger import scan_ctx


MODULES = ("os", "sys", "json", "pathlib", "math", "statistics", "socket", "random")
PADDING = (
    "    mod=os\n"
    + "".join(
        f"    if flag == {index}: mod={module}\n"
        for index, module in enumerate(MODULES[1:], 1)
    )
    + "    unused=mod.__doc__\n" * 3000
)

CASES = [
    ("eval", "", "invoke=eval", "invoke(data)", {"SKY-D201"}),
    ("exec", "", "invoke=exec", "invoke(data)", {"SKY-D202"}),
    ("pickle", "import pickle\n", "invoke=pickle.loads", "invoke(data)", {"SKY-D205"}),
    ("dill", "import dill\n", "invoke=dill.loads", "invoke(data)", {"SKY-D233"}),
    ("os", "", "invoke=os.system", "invoke(data)", {"SKY-D203"}),
    (
        "subprocess",
        "import subprocess\n",
        "invoke=subprocess.run",
        "invoke(data, shell=True)",
        {"SKY-D209"},
    ),
    (
        "source_owned",
        "def eval(data): return data\n",
        "invoke=eval",
        "invoke(data)",
        set(),
    ),
    (
        "json",
        "import pickle\npickle=json\n",
        "invoke=pickle.loads",
        "invoke(data)",
        set(),
    ),
    (
        "rebound_alias",
        "import pickle\n",
        "invoke=pickle.loads\n    invoke=json.loads",
        "invoke(data)",
        set(),
    ),
    (
        "different_subprocess_member",
        "import subprocess\nsubprocess.run=lambda *args, **kw: None\n",
        "invoke=subprocess.Popen",
        "invoke(data, shell=True)",
        {"SKY-D209"},
    ),
    (
        "patched_subprocess_member",
        "import subprocess\nsubprocess.run=lambda *args, **kw: None\n",
        "invoke=subprocess.run",
        "invoke(data, shell=True)",
        set(),
    ),
    (
        "direct_rebound_pickle",
        "import pickle\npickle=json\n",
        "ignored=None",
        "pickle.loads(data)",
        set(),
    ),
    (
        "direct_rebound_subprocess",
        "import subprocess\nsubprocess.run=lambda *args, **kw: None\n",
        "ignored=None",
        "subprocess.run(data, shell=True)",
        set(),
    ),
]


def _findings(root, source, engine):
    app = root / "app.py"
    app.write_text(source)
    if engine == "rule":
        visitor = LinterVisitor([DangerousCallsRule()], str(app))
        visitor.context["project_root"] = str(root)
        visitor.visit(ast.parse(source))
        return visitor.findings
    return scan_ctx(root, [app, *root.glob("pickle.py")])


@pytest.mark.parametrize("engine", ["rule", "scan_ctx"])
@pytest.mark.parametrize("capture_first", [True, False])
@pytest.mark.parametrize("case", CASES, ids=[case[0] for case in CASES])
def test_budget_keeps_native_aliases_and_safe_rebindings(
    tmp_path, engine, capture_first, case
):
    _name, setup, capture, call, expected = case
    source = "import " + ",".join(MODULES) + "\n" + setup + "def run(data, flag):\n"
    if capture_first:
        source += "    " + capture + "\n"
    source += PADDING
    if not capture_first:
        source += "    " + capture + "\n"
    source += "    return " + call + "\n"
    findings = _findings(tmp_path, source, engine)
    selected = {"SKY-D201", "SKY-D202", "SKY-D203", "SKY-D205", "SKY-D209", "SKY-D233"}
    assert {
        row["rule_id"] for row in findings if row["rule_id"] in selected
    } == expected


@pytest.mark.parametrize("engine", ["rule", "scan_ctx"])
def test_budget_does_not_invent_a_native_pickle_provider(tmp_path, engine):
    (tmp_path / "pickle.py").write_text("def loads(data): return data\n")
    source = (
        "import "
        + ",".join(MODULES)
        + "\nimport pickle\ndef run(data, flag):\n"
        + PADDING
        + "    invoke=pickle.loads\n    return invoke(data)\n"
    )
    assert not any(
        row["rule_id"] == "SKY-D205" for row in _findings(tmp_path, source, engine)
    )


def test_budgeted_alias_survives_listing_and_security_gate(tmp_path):
    source = (
        "import tensorlib\n"
        "from flask import Flask, request\napp=Flask(__name__)\n"
        "@app.get('/run')\ndef run(batches=None, flag=None):\n"
        "    stats=[]\n"
        "    for batch in batches:\n"
        "        for item in batch:\n"
        "            first=tensorlib.zeros(item, dtype=tensorlib.kind, device=flag)\n"
        "            second=tensorlib.zeros(item, dtype=tensorlib.mode, device=flag)\n"
        "            tensorlib.cat((first, second), tensorlib.axis)\n"
        "            stats.append((first, second, tensorlib.width))\n"
        "            merged=tensorlib.as_tensor(second, dtype=tensorlib.depth)\n"
        "            tensorlib.stack(merged, tensorlib.order)\n"
        "    invoke=eval\n    return invoke(request.args['code'])\n"
    )
    (tmp_path / "app.py").write_text(source)
    result = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
            grep_cache=False,
            all_advice=False,
        )
    )
    findings = [row for row in result.get("danger", []) if row["rule_id"] == "SKY-D201"]
    assert len(findings) == 1
    assert is_listed(findings[0], "danger")
    passed, reasons = check_gate(result, {"gate": {"max_high": 0, "max_critical": 0}})
    assert not passed, reasons


@pytest.mark.parametrize(
    "setup,capture,call,expected",
    [
        ("import builtins\n", "builtins.eval", "invoke(data)", "SKY-D201"),
        ("import pickle\n", "pickle.load", "invoke(data)", "SKY-D204"),
        ("import cloudpickle\n", "cloudpickle.load", "invoke(data)", "SKY-D204"),
        ("import cloudpickle\n", "cloudpickle.loads", "invoke(data)", "SKY-D205"),
        ("import dill\n", "dill.load", "invoke(data)", "SKY-D233"),
        ("import dill\n", "dill.loads", "invoke(data)", "SKY-D233"),
        ("import os\n", "os.popen", "invoke(data)", "SKY-D203"),
        ("import subprocess\n", "subprocess.getoutput", "invoke(data)", "SKY-D209"),
        (
            "import subprocess\n",
            "subprocess.getstatusoutput",
            "invoke(data)",
            "SKY-D209",
        ),
        (
            "import asyncio\n",
            "asyncio.create_subprocess_shell",
            "invoke(data)",
            "SKY-D209",
        ),
        (
            "import asyncio.subprocess\n",
            "asyncio.subprocess.create_subprocess_shell",
            "invoke(data)",
            "SKY-D209",
        ),
        (
            "import _pickle\nclass U(_pickle.Unpickler): pass\n",
            "U(data).load",
            "invoke()",
            "SKY-D204",
        ),
    ],
)
def test_exhausted_precise_flow_recovers_supported_providers(
    tmp_path, setup, capture, call, expected
):
    source = setup + f"def run(data):\n    invoke={capture}\n    return {call}\n"
    (tmp_path / "app.py").write_text(source)
    tree = ast.parse(source)
    index = _CallableIndex(tree)
    index.remaining = 1
    tree._skylos_danger_callable_index = index
    visitor = LinterVisitor([DangerousCallsRule()], str(tmp_path / "app.py"))
    visitor.context["project_root"] = str(tmp_path)
    visitor.visit(tree)
    assert {row["rule_id"] for row in visitor.findings} == {expected}
