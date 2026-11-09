"""Independent review counterexamples keep native proofs bounded and stable."""

import contextlib
import io

import pytest

from skylos.rules.danger.danger import scan_ctx
from test.fixture_paths import write_fixture
from test.test_security_sanitizer_identity import _analyze


@pytest.mark.parametrize(
    "setup",
    [
        "import sys\nsys.path.insert(0, 'providers')\n",
        "import sys as runtime\nruntime.path[:0]=['providers']\n",
        "from sys import path as lookup\nlookup.insert(0,'providers')\n",
        "import sys\nlookup=sys.path\nmore=lookup\nmore[:0]=['providers']\n",
        "import sys\nconfigure(sys.path)\n",
        "import sys\nhooks=sys.meta_path\nhooks.append(finder)\n",
        "import sys\ncache=sys.modules\ncache['shlex']=replacement\n",
    ],
)
def test_import_environment_changes_cannot_sanitize_alias(tmp_path, monkeypatch, setup):
    result = _analyze(
        tmp_path,
        monkeypatch,
        setup + "import subprocess\nfrom shlex import quote as encode\n"
        'def run(value):\n    subprocess.run("echo "+encode(value), shell=True)\n',
        (("providers/shlex.py", "def quote(value):\n    return value\n"),),
    )
    assert any(f["rule_id"] == "SKY-D212" for f in result.get("danger", []))


@pytest.mark.parametrize(
    "setup",
    [
        "setter=shlex.__setattr__\nsetter('quote',lambda value:value)\n",
        "setter=shlex.__setattr__\nother=setter\nother('quote',lambda value:value)\n",
        "setter=getattr(shlex,'__setattr__')\nsetter('quote',lambda value:value)\n",
        "configure(shlex)\n",
        "configure(shlex.quote)\n",
    ],
)
def test_native_provider_capabilities_cannot_escape(tmp_path, monkeypatch, setup):
    result = _analyze(
        tmp_path,
        monkeypatch,
        "import subprocess,shlex\n"
        + setup
        + 'def run(value):\n    subprocess.run("echo "+shlex.quote(value), shell=True)\n',
    )
    assert any(f["rule_id"] == "SKY-D212" for f in result.get("danger", []))


@pytest.mark.parametrize(
    "expression, vulnerable",
    [
        ('"echo "+shlex.quote(value)', False),
        ('shlex.join(["echo", value])', False),
        ("shlex.quote(value)", True),
        ('"echo `printf %s "+shlex.quote(value)+"`"', True),
        ('"cat <<EOF\\n"+shlex.quote(value)+"\\nEOF\\n"', True),
        ('"echo $("+shlex.quote(value)+")"', True),
        ('"echo "+shlex.quote(value)[1:-1]', True),
        ('"echo "+shlex.quote(value).replace("\'", "")', True),
    ],
)
def test_shell_context_and_quote_transform_are_proved(
    tmp_path, monkeypatch, expression, vulnerable
):
    result = _analyze(
        tmp_path,
        monkeypatch,
        "import subprocess,shlex\ndef run(value):\n    subprocess.run("
        + expression
        + ", shell=True)\n",
    )
    assert (
        any(f["rule_id"] == "SKY-D212" for f in result.get("danger", [])) is vulnerable
    )


@pytest.mark.parametrize("placement", ["prefix", "suffix"])
def test_many_branches_keep_later_raw_command_sink(tmp_path, monkeypatch, placement):
    left = '"a"+command' if placement == "prefix" else 'command+"a"'
    right = '"b"+command' if placement == "prefix" else 'command+"b"'
    source = (
        'import subprocess,shlex\ndef run(value,flag):\n    command="echo "+shlex.quote(value)\n'
        + "".join(
            "    if flag:\n        command="
            + left
            + "\n    else:\n        command="
            + right
            + "\n"
            for _ in range(500)
        )
        + "    subprocess.run(command,shell=True)\n    subprocess.run(value,shell=True)\n"
    )
    file = write_fixture(tmp_path, "app.py", source)
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        raw = scan_ctx(tmp_path, [file])
        native = tmp_path / "native"
        native.mkdir()
        result = _analyze(native, monkeypatch, source)
    assert "CMD flow failed" not in stderr.getvalue()
    sink_line = len(source.splitlines())
    assert any(f["rule_id"] == "SKY-D212" and f["line"] == sink_line for f in raw)
    assert any(
        f["rule_id"] == "SKY-D212" and f["line"] == sink_line
        for f in result.get("danger", [])
    )


@pytest.mark.parametrize(
    "expression",
    [
        "sys.path if True else []",
        "sys.path or []",
        "(saved := sys.path)",
        "list([sys.path])",
        "[" * 40 + "sys.path" + "]" * 40,
    ],
)
def test_import_state_carriers_do_not_erase_capabilities(
    tmp_path, monkeypatch, expression
):
    result = _analyze(
        tmp_path,
        monkeypatch,
        "import sys,subprocess\n"
        "def configure(value):\n    while isinstance(value,list) and len(value)==1:\n        value=value[0]\n    value.insert(0,'providers')\n"
        + "configure("
        + expression
        + ")\nfrom shlex import quote as encode\n"
        + 'def run(value):\n    subprocess.run("echo "+encode(value),shell=True)\n',
        (("providers/shlex.py", "def quote(value):\n    return value\n"),),
    )
    assert any(f["rule_id"] == "SKY-D212" for f in result.get("danger", []))


def test_nonlocal_import_state_alias_is_an_escape(tmp_path, monkeypatch):
    result = _analyze(
        tmp_path,
        monkeypatch,
        "import sys,subprocess\ndef configure(value):\n    value.insert(0,'providers')\n"
        "def alter():\n    state=[]\n    def save():\n        nonlocal state\n        state=sys.path\n    save()\n    configure(state)\nalter()\n"
        "from shlex import quote as encode\ndef run(value):\n    subprocess.run('echo '+encode(value),shell=True)\n",
        (("providers/shlex.py", "def quote(value):\n    return value\n"),),
    )
    assert any(f["rule_id"] == "SKY-D212" for f in result.get("danger", []))


@pytest.mark.parametrize(
    "setup, vulnerable",
    [
        ("def unrelated(shlex):\n    consume(shlex)\n", False),
        ("def unrelated(sys):\n    consume(sys.path)\n", False),
        ("import mutator\n", True),
        (
            "class Unused(str):\n    def replace(self,*a):\n        return 'unsafe'\n",
            False,
        ),
    ],
)
def test_provider_effects_follow_actual_bindings(
    tmp_path, monkeypatch, setup, vulnerable
):
    result = _analyze(
        tmp_path,
        monkeypatch,
        "import subprocess,shlex\n"
        + setup
        + 'def run(value):\n    subprocess.run("echo "+shlex.quote(value),shell=True)\n',
        (("mutator.py", "import shlex\nshlex.quote=lambda value:value\n"),),
    )
    assert (
        any(f["rule_id"] == "SKY-D212" for f in result.get("danger", [])) is vulnerable
    )


@pytest.mark.parametrize(
    "producer",
    [
        "Payload(value)",
        "make(value)",
        "alias(value)",
        "choose()(value)",
        "dynamic(value)",
    ],
)
def test_source_created_protocol_objects_do_not_inherit_native_data_proof(
    tmp_path, monkeypatch, producer
):
    result = _analyze(
        tmp_path,
        monkeypatch,
        "import subprocess\nfrom shlex import quote as encode\n"
        'class Payload(str):\n    def replace(self,*args,**kwargs):\n        return "\' ; echo injected ; #"\n'
        "def make(value):\n    return Payload(value)\n"
        "alias=Payload\ndef choose():\n    return Payload\ndynamic=type('Dynamic',(str,),{'replace':Payload.replace})\n"
        "def run(value):\n    value="
        + producer
        + '\n    subprocess.run("echo "+encode(value),shell=True)\n',
    )
    assert any(f["rule_id"] == "SKY-D212" for f in result.get("danger", []))


@pytest.mark.parametrize(
    "expression", ["sys.path.copy()", "list(sys.path)", "sys.path[:]"]
)
def test_native_path_copy_does_not_escape_live_import_state(
    tmp_path, monkeypatch, expression
):
    result = _analyze(
        tmp_path,
        monkeypatch,
        "import sys,subprocess,shlex\ndef configure(copy):\n    copy.insert(0,'providers')\n"
        + "copied="
        + expression
        + "\nconfigure(copied)\n"
        + 'def run(value):\n    subprocess.run("echo "+shlex.quote(value),shell=True)\n',
    )
    assert not any(f["rule_id"] == "SKY-D212" for f in result.get("danger", []))


def test_alias_expansion_budget_preserves_later_command(tmp_path, monkeypatch):
    result = _analyze(
        tmp_path,
        monkeypatch,
        "import sys as state\nstate=state.left\nstate=state.right\nimport subprocess\n"
        "def run(value):\n    subprocess.run(value,shell=True)\n",
    )
    assert any(
        f["rule_id"] == "SKY-D212" and f["line"] == 6 for f in result.get("danger", [])
    )
