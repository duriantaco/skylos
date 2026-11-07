"""D250 resolves RNG bindings without trusting stale import aliases.

Sources and expected locations are fixed before changing the detector.  These
programs are parsed and scanned; none of their application code is executed.
"""

import ast
import json

import pytest

from skylos.analyzer import analyze
from skylos.rules.danger.danger import _DangerousCallsChecker


CASES = {
    "module_strong": (
        "import random as rng\nimport secrets\nrng = secrets.SystemRandom()\n"
        "def issue(response):\n    response.set_cookie('sid', str(rng.getrandbits(128)))\n",
        [],
    ),
    "module_weak": (
        "import secrets as rng\nimport random\nrng = random.Random()\n"
        "def issue(response):\n    response.set_cookie('sid', str(rng.getrandbits(128)))\n",
        [5],
    ),
    "parameter_shadow": (
        "import random as rng\ndef issue(response, rng):\n"
        "    response.set_cookie('sid', str(rng.getrandbits(128)))\n",
        [],
    ),
    "local_shadow": (
        "import random as rng\ndef issue(response, provider):\n"
        "    rng = provider\n    response.set_cookie('sid', str(rng.getrandbits(128)))\n",
        [],
    ),
    "local_strong": (
        "import random as rng\nimport secrets\ndef issue(response):\n"
        "    rng = secrets.SystemRandom()\n"
        "    response.set_cookie('sid', str(rng.getrandbits(128)))\n",
        [],
    ),
    "local_weak": (
        "import secrets as rng\nimport random\ndef issue(response):\n"
        "    rng = random.Random()\n"
        "    response.set_cookie('sid', str(rng.getrandbits(128)))\n",
        [5],
    ),
    "branch_weak": (
        "import secrets as rng\nimport random\ndef issue(response, flag):\n"
        "    rng = random.SystemRandom()\n    if flag:\n        rng = random.Random()\n"
        "    response.set_cookie('sid', str(rng.getrandbits(128)))\n",
        [7],
    ),
    "branches_strong": (
        "import random as rng\nimport secrets\ndef issue(response, flag):\n"
        "    if flag:\n        rng = random.SystemRandom()\n    else:\n"
        "        rng = secrets.SystemRandom()\n"
        "    response.set_cookie('sid', str(rng.getrandbits(128)))\n",
        [],
    ),
    "module_later_strong": (
        "import random as rng\nimport secrets\ndef issue(response):\n"
        "    response.set_cookie('sid', str(rng.getrandbits(128)))\n"
        "issue(response)\nrng = secrets.SystemRandom()\n",
        [4],
    ),
    "module_later_weak": (
        "import random\nimport secrets as rng\nrng = random.SystemRandom()\n"
        "def issue(response):\n    response.set_cookie('sid', str(rng.getrandbits(128)))\n"
        "rng = random.Random()\nissue(response)\n",
        [5],
    ),
    "call_before_assignment": (
        "import random as rng\nimport secrets\n"
        "response.set_cookie('sid', str(rng.getrandbits(128)))\n"
        "rng = secrets.SystemRandom()\n",
        [3],
    ),
    # An opaque constructor is not source-proven safe. Preserve the legacy
    # warning; this case is deliberately not labelled a corpus true negative.
    "opaque_constructor": (
        "import random as rng\nrng = build_generator()\ndef issue(response):\n"
        "    response.set_cookie('sid', str(rng.getrandbits(128)))\n",
        [4],
    ),
    "opaque_after_strong": (
        "import random as rng\nimport secrets\nrng = secrets.SystemRandom()\n"
        "rng = build_generator()\ndef issue(response):\n"
        "    response.set_cookie('sid', str(rng.getrandbits(128)))\n",
        [6],
    ),
    "constructor_alias_strong": (
        "import random as rng\nfrom secrets import SystemRandom as Generator\n"
        "rng = Generator()\ndef issue(response):\n"
        "    response.set_cookie('sid', str(rng.getrandbits(128)))\n",
        [],
    ),
    "constructor_alias_weak": (
        "import secrets as rng\nfrom random import Random as Generator\n"
        "rng = Generator()\ndef issue(response):\n"
        "    response.set_cookie('sid', str(rng.getrandbits(128)))\n",
        [5],
    ),
    "reimport_weak": (
        "import random as rng\nimport secrets\nrng = secrets.SystemRandom()\n"
        "import random as rng\ndef issue(response):\n"
        "    response.set_cookie('sid', str(rng.getrandbits(128)))\n",
        [6],
    ),
    "import_after_definition": (
        "def issue(response):\n    response.set_cookie('sid', str(rng.getrandbits(128)))\n"
        "import random as rng\nissue(response)\n",
        [2],
    ),
    "module_branch_weak": (
        "import random\nimport secrets as rng\nrng = random.SystemRandom()\n"
        "if feature_flag:\n    rng = random.Random()\ndef issue(response):\n"
        "    response.set_cookie('sid', str(rng.getrandbits(128)))\n",
        [7],
    ),
    "alias_copy_weak": (
        "import secrets as rng\nimport random\nrng = random.Random()\n"
        "copied = rng\ndef issue(response):\n"
        "    response.set_cookie('sid', str(copied.getrandbits(128)))\n",
        [6],
    ),
    "alias_copy_strong": (
        "import random as rng\nimport secrets\nrng = secrets.SystemRandom()\n"
        "copied = rng\ndef issue(response):\n"
        "    response.set_cookie('sid', str(copied.getrandbits(128)))\n",
        [],
    ),
    "global_rebind": (
        "import random as rng\nimport secrets\nrng = secrets.SystemRandom()\n"
        "def reset():\n    global rng\n    rng = random.Random()\n"
        "def issue(response):\n    response.set_cookie('sid', str(rng.getrandbits(128)))\n"
        "reset()\nissue(response)\n",
        [8],
    ),
    "global_instance_patch": (
        "import random as rng\nimport secrets\nrng = secrets.SystemRandom()\n"
        "def reset():\n    rng.getrandbits = random.getrandbits\n"
        "def issue(response):\n    response.set_cookie('sid', str(rng.getrandbits(128)))\n"
        "reset()\nissue(response)\n",
        [7],
    ),
    "bound_method_weak": (
        "import secrets as rng\nimport random\nrng = random.Random()\n"
        "draw = rng.getrandbits\ndef issue(response):\n"
        "    response.set_cookie('sid', str(draw(128)))\n",
        [6],
    ),
    "bound_method_strong": (
        "import random as rng\nimport secrets\nrng = secrets.SystemRandom()\n"
        "draw = rng.getrandbits\ndef issue(response):\n"
        "    response.set_cookie('sid', str(draw(128)))\n",
        [],
    ),
    "bound_method_copies_weak": (
        "import secrets as rng\nimport random\nrng = random.Random()\n"
        "draw = rng.getrandbits\nnext_draw = draw\ndef issue(response):\n"
        "    response.set_cookie('sid', str(next_draw(128)))\n",
        [7],
    ),
    "bound_method_before_rebind": (
        "import random as rng\nimport secrets\ndraw = rng.getrandbits\n"
        "rng = secrets.SystemRandom()\ndef issue(response):\n"
        "    response.set_cookie('sid', str(draw(128)))\n",
        [6],
    ),
    "class_method_outer_patch": (
        "import random as rng\nimport secrets\nrng = secrets.SystemRandom()\n"
        "class Reset:\n    def apply(self):\n        rng.getrandbits = random.getrandbits\n"
        "def issue(response):\n    response.set_cookie('sid', str(rng.getrandbits(128)))\n"
        "Reset().apply()\nissue(response)\n",
        [8],
    ),
}


@pytest.fixture(scope="module")
def binding_reports(tmp_path_factory):
    root = tmp_path_factory.mktemp("rng_bindings")
    (root / "pyproject.toml").write_text("[project]\nname = 'rng-demo'\n")
    for name, (source, _) in CASES.items():
        (root / f"{name}.py").write_text(source)
    report = json.loads(analyze(str(root), enable_danger=True, grep_verify=False))
    assert not report.get("analysis_errors")
    native = {}
    for row in report.get("danger", []):
        if row.get("rule_id") == "SKY-D250":
            native.setdefault(
                row["file"].replace("\\", "/").rsplit("/", 1)[-1], []
            ).append(row["line"])
    direct = {}
    for name, (source, _) in CASES.items():
        findings = []
        _DangerousCallsChecker(root / f"{name}.py", findings, root).visit(
            ast.parse(source)
        )
        direct[name + ".py"] = [
            row["line"] for row in findings if row["rule_id"] == "SKY-D250"
        ]
    return native, direct


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            case,
            marks=pytest.mark.xfail(
                strict=True,
                reason=(
                    "Known D250 false negative: a module bound method captured before "
                    "rebinding its import alias cannot use the whole-project provider proof"
                ),
            ),
        )
        if case == "bound_method_before_rebind"
        else case
        for case in sorted(CASES)
    ],
)
@pytest.mark.parametrize("path", [0, 1], ids=["native", "direct-checker"])
def test_rng_binding_expected_locations(binding_reports, case, path):
    assert binding_reports[path].get(case + ".py", []) == CASES[case][1]


def test_local_systemrandom_provider_cannot_clear_warning(tmp_path):
    source = (
        "import random as rng\nimport secrets\nrng = secrets.SystemRandom()\n"
        "def issue(response):\n    response.set_cookie('sid', str(rng.getrandbits(128)))\n"
    )
    (tmp_path / "app.py").write_text(source)
    (tmp_path / "secrets.py").write_text(
        "from random import Random\ndef SystemRandom():\n    return Random()\n"
    )
    result = json.loads(analyze(str(tmp_path), enable_danger=True, grep_verify=False))
    assert not result.get("analysis_errors")
    assert [
        row["line"] for row in result.get("danger", []) if row["rule_id"] == "SKY-D250"
    ] == [5]
    findings = []
    _DangerousCallsChecker(tmp_path / "app.py", findings, tmp_path).visit(
        ast.parse(source)
    )
    assert [row["line"] for row in findings if row["rule_id"] == "SKY-D250"] == [5]
