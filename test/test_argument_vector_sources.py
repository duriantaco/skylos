import ast

import pytest

from skylos.rules.danger.python_security_gaps import scan


def findings(tmp_path, build, before=""):
    path = tmp_path / "app.py"
    source = (
        "import subprocess,shlex,threading\nfrom flask import Flask,request\napp=Flask(__name__)\ndef consume(cmd):\n    subprocess.Popen(cmd)\n@app.route('/')\ndef route():\n    "
        + build.replace("\n", "\n    ")
        + "\n    threading.Thread(target=consume,args=(cmd,)).start()\n"
    )
    path.write_text(source)
    rows = []
    scan(ast.parse(source), path, rows, project_root=tmp_path)
    return [row for row in rows if row["rule_id"] == "SKY-D212"]


def test_request_split_expands_vector_through_native_thread(tmp_path):
    hits = findings(
        tmp_path, "cmd=['tool']\ncmd.extend(shlex.split(request.args['q']))"
    )
    assert [row["line"] for row in hits] == [5]
    assert (
        hits[0]["security_evidence"]["evidence_kind"]
        == "python_argument_vector_injection"
    )


@pytest.mark.parametrize(
    "build",
    [
        "cmd=['tool','--']\ncmd.extend(shlex.split(request.args['q']))",
        "cmd=['tool',request.args['q']]",
        "cmd=['tool']\ncmd.append(request.args['q'])",
        "cmd=['tool']\ncmd.extend(shlex.split('fixed arguments'))",
        "cmd=['tool']\ncmd.append(shlex.split(request.args['q']))",
        "cmd=['tool']\ncmd.extend(shlex.split(shlex.quote(request.args['q'])))",
    ],
)
def test_scalar_fixed_or_option_terminated_vector_is_not_injection(tmp_path, build):
    assert not findings(tmp_path, build)


def test_mutated_option_boundary_is_not_a_safe_proof(tmp_path):
    assert findings(
        tmp_path,
        "cmd=['tool','--']\ncmd.pop()\ncmd.extend(shlex.split(request.args['q']))",
    )


def test_option_can_consume_dashdash_as_its_value(tmp_path):
    assert findings(
        tmp_path, "cmd=['grep','-e','--']\ncmd.extend(shlex.split(request.args['q']))"
    )
