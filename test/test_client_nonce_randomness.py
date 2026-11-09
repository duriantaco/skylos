"""Client-nonce material is security-sensitive; unrelated random uses are not."""

import ast
import json

import pytest

from skylos.core.linter import LinterVisitor
from skylos.rules.danger.calls import DangerousCallsRule


CASES = {
    "literal_digit_index": (
        "import random, time\nfrom hashlib import md5 as _md5\n"
        "def _cnonce():\n"
        "    dig = _md5(('%s:%s' % (time.ctime(), ['0123456789'[random.randrange(10)] for _ in range(20)])).encode()).hexdigest()\n"
        "    return dig[:16]\n",
        True,
    ),
    "direct_return": (
        "import random\ndef _cnonce():\n    return str(random.random())\n",
        True,
    ),
    "local_value": (
        "import random\ndef _cnonce():\n    value = str(random.getrandbits(128))\n    return value\n",
        True,
    ),
    "unrelated_jitter": (
        "import random, secrets, time\ndef _cnonce():\n"
        "    time.sleep(random.uniform(0, 1))\n    return secrets.token_hex(16)\n",
        False,
    ),
    "strong_length": (
        "import random, secrets\ndef _cnonce():\n"
        "    return secrets.token_hex(16 + random.randrange(16))\n",
        False,
    ),
    "aliased_strong_length": (
        "import random\nfrom secrets import token_hex as fresh\ndef _cnonce():\n"
        "    return fresh(16 + random.randrange(16))\n",
        False,
    ),
    "strong_source": (
        "import random\ndef _cnonce():\n    return str(random.SystemRandom().getrandbits(128))\n",
        False,
    ),
    "name_lookalike": (
        "import random\ndef cnonce_metrics():\n    return random.random()\n",
        False,
    ),
    "theme_index": (
        "import random\nfrom flask import session\ndef choose():\n"
        "    session['theme'] = ['dark', 'light'][random.randrange(2)]\n",
        False,
    ),
    "rebound_to_strong": (
        "import random, secrets\ndef _cnonce():\n"
        "    value = str(random.random())\n    value = secrets.token_hex(16)\n    return value\n",
        False,
    ),
    "mixed_strong_entropy": (
        "import random, secrets\ndef _cnonce():\n"
        "    return '0123456789'[random.randrange(10)] + secrets.token_hex(16)\n",
        False,
    ),
    "opaque_transform": (
        "import random\ndef ignore(value):\n    return 'fixed'\n"
        "def _cnonce():\n    return ignore(random.randrange(10))\n",
        False,
    ),
    "opaque_entropy_helper": (
        "import random, secrets\ndef fresh():\n    return secrets.token_hex(16)\n"
        "def _cnonce():\n    return '0123456789'[random.randrange(10)] + fresh()\n",
        False,
    ),
    "opaque_global_entropy": (
        "import random\nSTORED = 'private-value'\ndef _cnonce():\n"
        "    return '0123456789'[random.randrange(10)] + STORED\n",
        False,
    ),
    "opaque_parameter_entropy": (
        "import random\ndef _cnonce(entropy):\n"
        "    return '0123456789'[random.randrange(10)] + entropy\n",
        False,
    ),
    "opaque_formatted_receiver": (
        "import random, secrets\nclass Private:\n"
        "    def __str__(self):\n        return secrets.token_hex(16)\n"
        "opaque = Private()\ndef _cnonce():\n"
        "    return ('%s:%s' % (random.getrandbits(128), opaque)).encode().hex()\n",
        False,
    ),
    "opaque_method_receiver": (
        "import random, secrets\nopaque = secrets.token_bytes(16)\ndef _cnonce():\n"
        "    return str(random.getrandbits(128)) + opaque.hex()\n",
        False,
    ),
    "rebound_secrets_is_not_proof": (
        "import random, secrets\nclass Fake:\n"
        "    def token_hex(self, value):\n        return str(value)\n"
        "secrets = Fake()\ndef _cnonce():\n"
        "    return secrets.token_hex(16 + random.randrange(16))\n",
        True,
    ),
}


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            case,
            marks=pytest.mark.xfail(
                strict=True,
                reason="Custom wrapper return flow is deferred; the bounded nonce proof requires transparent transforms.",
            ),
        )
        if case == "rebound_secrets_is_not_proof"
        else case
        for case in CASES
    ],
)
def test_client_nonce_material_and_safe_controls(case):
    code, expected = CASES[case]
    visitor = LinterVisitor([DangerousCallsRule()], "client_nonce_fixture.py")
    visitor.visit(ast.parse(code))
    rows = [row for row in visitor.findings if row["rule_id"] == "SKY-D250"]
    assert bool(rows) is expected
    if rows:
        assert len(rows) == 1
        assert rows[0]["severity"] == "MEDIUM"


def test_client_nonce_is_listed_through_production_analysis(tmp_path):
    from skylos.analyzer import analyze
    from skylos.reporting.listing import is_listed

    (tmp_path / "pyproject.toml").write_text('[project]\nname="nonce-demo"\n')
    (tmp_path / "client.py").write_text(CASES["literal_digit_index"][0])
    result = json.loads(analyze(str(tmp_path), enable_danger=True, grep_verify=False))
    rows = [row for row in result.get("danger", []) if row["rule_id"] == "SKY-D250"]
    assert len(rows) == 1
    assert is_listed(rows[0], "danger")


def test_nonce_proof_does_not_spend_existing_flow_budget(monkeypatch):
    import skylos.rules.danger.calls as calls

    code = CASES["local_value"][0]

    def remaining():
        tree = ast.parse(code)
        visitor = LinterVisitor([DangerousCallsRule()], "client_nonce_fixture.py")
        visitor.visit(tree)
        return calls._module_calls(tree).budget

    with_proof = remaining()
    monkeypatch.setattr(
        calls, "_client_nonce_material_reaches_return", lambda *_: False
    )
    assert with_proof == remaining()


def test_native_hash_copy_passive_star_and_instance_state_do_not_hide_nonce(tmp_path):
    package = tmp_path / "client"
    package.mkdir()
    path = package / "__init__.py"
    (package / "error.py").write_text("class Failure(Exception):\n    pass\n")
    code = (
        "from hashlib import md5 as _md5\nfrom .error import *\n"
        "class Holder:\n"
        "    def remember(self):\n        self.hashmod = _md5\n"
        "    def restore(self, state):\n        self.__dict__.update(state)\n"
        + CASES["literal_digit_index"][0].replace(
            "from hashlib import md5 as _md5\n", ""
        )
    )
    path.write_text(code)
    visitor = LinterVisitor([DangerousCallsRule()], str(path))
    visitor.context["project_root"] = str(tmp_path)
    visitor.visit(ast.parse(code))
    assert len([row for row in visitor.findings if row["rule_id"] == "SKY-D250"]) == 1


@pytest.mark.parametrize(
    "binding",
    [
        "range = object()\n",
        "def replace():\n    global range\n    range = object()\n",
        "namespace = globals()\nnamespace['range'] = object()\n",
    ],
)
def test_ambiguous_builtin_does_not_gain_nonce_finding(tmp_path, binding):
    code = CASES["literal_digit_index"][0] + binding
    path = tmp_path / "client.py"
    path.write_text(code)
    visitor = LinterVisitor([DangerousCallsRule()], str(path))
    visitor.context["project_root"] = str(tmp_path)
    visitor.visit(ast.parse(code))
    assert not [row for row in visitor.findings if row["rule_id"] == "SKY-D250"]


@pytest.mark.parametrize(
    "case", [case for case in CASES if case != "rebound_secrets_is_not_proof"]
)
def test_standalone_checker_keeps_bounded_nonce_precision(tmp_path, case):
    from skylos.rules.danger.danger import _DangerousCallsChecker

    code, expected = CASES[case]
    path = tmp_path / "client.py"
    path.write_text(code)
    findings = []
    _DangerousCallsChecker(path, findings, tmp_path).visit(ast.parse(code))
    rows = [row for row in findings if row["rule_id"] == "SKY-D250"]
    assert bool(rows) is expected


@pytest.mark.parametrize(
    "binding",
    [
        "range = object()\n",
        "def replace():\n    global range\n    range = object()\n",
        "namespace = globals()\nnamespace['range'] = object()\n",
    ],
)
def test_standalone_nonce_proof_rejects_ambiguous_builtins(tmp_path, binding):
    from skylos.rules.danger.danger import _DangerousCallsChecker

    code = CASES["literal_digit_index"][0] + binding
    path = tmp_path / "client.py"
    path.write_text(code)
    findings = []
    _DangerousCallsChecker(path, findings, tmp_path).visit(ast.parse(code))
    assert not [row for row in findings if row["rule_id"] == "SKY-D250"]


def test_all_nonce_provider_probes_leave_shared_effect_budget_unchanged(tmp_path):
    from skylos.rules.danger.calls import _client_nonce_material_reaches_return
    from skylos.rules.danger.import_proof import _effects, provider_binding_is_stable

    code = CASES["literal_digit_index"][0]
    path = tmp_path / "client.py"
    path.write_text(code)
    tree = ast.parse(code)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent
    assert provider_binding_is_stable("ssl.CERT_NONE", tree, path, tmp_path)
    effects = _effects(tree)
    effects.ref_work = 65535
    call = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "randrange"
    )
    assert _client_nonce_material_reaches_return(
        call, {"filename": str(path), "project_root": str(tmp_path)}
    )
    assert effects.ref_work == 65535
    assert effects.complete
    assert provider_binding_is_stable("ssl.CERT_NONE", tree, path, tmp_path)
