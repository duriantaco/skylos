"""Provider capabilities cannot be handed to implicit Python callbacks."""

import ast

import pytest

from skylos.rules.danger.import_proof import project_provider_effects_are_stable
from test.fixture_paths import write_fixture
from test.test_security_sanitizer_identity import _analyze


@pytest.mark.parametrize(
    "operation",
    [
        "Carrier()==shlex",
        "Carrier()+shlex",
        "Carrier()[shlex]",
        "{key:0, shlex:0}",
        "{key, shlex}",
        "shlex == Carrier()",
    ],
)
def test_implicit_protocol_use_cannot_preserve_quote_proof(
    tmp_path, monkeypatch, operation
):
    source = (
        "import subprocess,shlex\n"
        "class Carrier:\n"
        "    def __eq__(self,other):\n        return other\n"
        "    def __add__(self,other):\n        setter=other.__setattr__\n        setter('quote',lambda value:value)\n        return 0\n"
        "    def __getitem__(self,other):\n        setter=other.__setattr__\n        setter('quote',lambda value:value)\n        return 0\n"
        "def configure(key):\n    " + operation + "\n"
        "from shlex import quote as encode\ndef run(value):\n"
        '    subprocess.run("echo "+encode(value),shell=True)\n'
    )
    result = _analyze(tmp_path, monkeypatch, source)
    assert any(row["rule_id"] == "SKY-D212" for row in result.get("danger", []))


@pytest.mark.parametrize(
    "operation",
    [
        "shlex is None",
        "saved=shlex\n    holder=[saved]\n    copied=holder+[]",
        "data={'key':shlex}",
        "data=(1+2)==3",
    ],
)
def test_callback_free_provider_data_uses_remain_safe(tmp_path, monkeypatch, operation):
    result = _analyze(
        tmp_path,
        monkeypatch,
        "import subprocess,shlex\ndef configure():\n    "
        + operation
        + '\ndef run(value):\n    subprocess.run("echo "+shlex.quote(value),shell=True)\n',
    )
    assert not any(row["rule_id"] == "SKY-D212" for row in result.get("danger", []))


def test_src_import_effects_are_followed_and_snapshot_changes_invalidate_cache(
    tmp_path,
):
    source = "import pkg.mutator\nfrom shlex import quote\n"
    path = write_fixture(tmp_path, "app.py", source)
    write_fixture(tmp_path, "src/pkg/__init__.py", "")
    mutator = write_fixture(tmp_path, "src/pkg/mutator.py", "pass\n")
    tree = ast.parse(source)
    assert project_provider_effects_are_stable("shlex.quote", tree, path, tmp_path)
    mutator.write_text("import shlex\nshlex.quote=lambda value:value\n")
    assert not project_provider_effects_are_stable("shlex.quote", tree, path, tmp_path)


def test_project_effects_require_actual_caller_source(tmp_path):
    path = write_fixture(tmp_path, "app.py", "pass\n")
    assert not project_provider_effects_are_stable(
        "shlex.quote", ast.parse("import shlex\n"), path, tmp_path
    )


@pytest.mark.parametrize(
    "setup",
    [
        "get_provider=lambda:shlex\nsetter=get_provider().__setattr__\nsetter('quote',identity)\n",
        "cap=shlex.quote.__get__(None,object)\nsetter=cap.__setattr__\nsetter('__code__',identity.__code__)\n",
        "class Install:\n    def __eq__(self,other):\n        other.__code__=identity.__code__\n        return False\nmatch Install():\n    case shlex.quote:\n        pass\n",
        "class Install(dict):\n    def get(self,key,default=None):\n        key.__code__=identity.__code__\n        return None\nmatch Install({None:None}):\n    case {shlex.quote:value}:\n        pass\n",
    ],
)
def test_implicit_returns_and_patterns_cannot_hide_provider_mutation(
    tmp_path, monkeypatch, setup
):
    result = _analyze(
        tmp_path,
        monkeypatch,
        "import subprocess,shlex\ndef identity(value):\n    return value\n"
        + setup
        + 'from shlex import quote as encode\ndef run(value):\n    subprocess.run("echo "+encode(value),shell=True)\n',
    )
    assert any(row["rule_id"] == "SKY-D212" for row in result.get("danger", []))


def test_unimported_vendor_provider_does_not_shadow_native_import(
    tmp_path, monkeypatch
):
    result = _analyze(
        tmp_path,
        monkeypatch,
        'import subprocess,shlex\ndef run(value):\n    subprocess.run("echo "+shlex.quote(value),shell=True)\n',
        (("vendor/shlex.py", "pass\n"),),
    )
    assert not any(row["rule_id"] == "SKY-D212" for row in result.get("danger", []))


@pytest.mark.parametrize(
    "projection",
    [
        "provider=providers[0]\nprint(provider.__name__)\n",
        "for provider in providers:\n    print(provider.__name__)\n",
    ],
)
def test_native_provider_list_reads_preserve_identity(
    tmp_path, monkeypatch, projection
):
    result = _analyze(
        tmp_path,
        monkeypatch,
        "import subprocess,shlex\nproviders=[shlex]\n"
        + projection
        + 'def run(value):\n    subprocess.run("echo "+shlex.quote(value),shell=True)\n',
    )
    assert not any(row["rule_id"] == "SKY-D212" for row in result.get("danger", []))


@pytest.mark.parametrize(
    "setup",
    [
        "providers[0]=replacement\nprovider=providers[0]\nprint(provider.__name__)\n",
        "configure(providers)\nprovider=providers[0]\nprint(provider.__name__)\n",
        "providers.append(replacement)\nfor provider in providers:\n    print(provider.__name__)\n",
        "provider=providers[choose()]\nprint(provider.__name__)\n",
    ],
)
def test_uncertain_provider_list_effects_still_refute_identity(
    tmp_path, monkeypatch, setup
):
    result = _analyze(
        tmp_path,
        monkeypatch,
        "import subprocess,shlex\nproviders=[shlex]\n"
        + setup
        + 'def run(value):\n    subprocess.run("echo "+shlex.quote(value),shell=True)\n',
    )
    assert any(row["rule_id"] == "SKY-D212" for row in result.get("danger", []))
