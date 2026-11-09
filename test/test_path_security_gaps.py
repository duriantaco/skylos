"""Precision controls for operator input and misleading request parameter names."""

import json

import pytest

from skylos.analyzer import analyze

PATH_RULES = {"SKY-D215", "SKY-D324", "SKY-D325"}


def _scan(tmp_path, source):
    (tmp_path / ".git").mkdir()
    (tmp_path / "pyproject.toml").write_text('[project]\nname="precision"\n')
    (tmp_path / "app.py").write_text(source)
    return json.loads(analyze(str(tmp_path), enable_danger=True))


def _paths(result, category="danger"):
    return [row for row in result.get(category, []) if row["rule_id"] in PATH_RULES]


@pytest.mark.parametrize(
    "source", ["input()", "sys.stdin.read()", "sys.stdin.readline()"]
)
def test_standalone_operator_stdin_is_not_remote_path_input(tmp_path, source):
    result = _scan(tmp_path, f"import sys\nname = {source}\nopen(name).read()\n")
    assert _paths(result) == []
    suppressed = _paths(result, "suppressed")
    assert suppressed
    assert all(
        row["metadata"]["path_provenance"]["status"] == "safe" for row in suppressed
    )


@pytest.mark.parametrize("source", ["input()", "sys.stdin.read()"])
def test_stdin_in_web_application_remains_untrusted(tmp_path, source):
    result = _scan(
        tmp_path,
        "import sys\nfrom flask import Flask\napp = Flask(__name__)\n"
        f"@app.get('/read')\ndef read():\n    return open({source}).read()\n",
    )
    assert any(row["rule_id"] == "SKY-D215" for row in _paths(result))


@pytest.mark.parametrize("direct_first", [False, True])
def test_direct_operator_read_does_not_reclassify_a_helper_source(
    tmp_path, direct_first
):
    direct = "open(name).read()\n"
    helper = "consume(name)\n"
    result = _scan(
        tmp_path,
        "def consume(path):\n    return open(path).read()\n"
        "name = input()\n" + (direct + helper if direct_first else helper + direct),
    )
    visible = _paths(result)
    assert any(row.get("symbol") == "consume" for row in visible)
    assert not any(row.get("symbol") == "<module>" for row in visible)
    assert any(row.get("symbol") == "<module>" for row in _paths(result, "suppressed"))


@pytest.mark.parametrize(
    "replacement,source",
    [
        ("builtins.input = fetch", "input()"),
        ("setattr(builtins, 'input', fetch)", "input()"),
        ("sys.stdin.read = fetch", "sys.stdin.read()"),
        ("setattr(sys.stdin, 'read', fetch)", "sys.stdin.read()"),
    ],
)
def test_replaced_stdin_provider_is_not_operator_proof(tmp_path, replacement, source):
    (tmp_path / "patcher.py").write_text(
        "import builtins, sys\nfrom requests import get\n"
        "def fetch():\n    return get('https://example.invalid/path').text\n"
        + replacement
        + "\n"
    )
    result = _scan(tmp_path, f"import sys, patcher\nopen({source}).read()\n")
    assert any(row["rule_id"] == "SKY-D215" for row in _paths(result))


def test_opaque_function_is_not_a_standalone_stdin_entrypoint(tmp_path):
    result = _scan(tmp_path, "def read():\n    return open(input()).read()\n")
    assert any(row["rule_id"] == "SKY-D215" for row in _paths(result))


def test_remote_subprocess_stdin_is_not_operator_proof(tmp_path):
    result = _scan(
        tmp_path,
        "import sys, subprocess\nfrom flask import Flask, request\n"
        "app=Flask(__name__)\n@app.get('/run')\ndef run():\n"
        "    return subprocess.run(['python', 'app.py'], input=request.data)\n"
        "def cli():\n    return open(sys.stdin.read()).read()\n",
    )
    assert any(row["rule_id"] == "SKY-D215" for row in _paths(result))


def test_internal_request_model_is_followed_through_actual_caller(tmp_path):
    result = _scan(
        tmp_path,
        "from dataclasses import dataclass\nfrom flask import Flask\n"
        "@dataclass\nclass TranslateRequest:\n    name: str\n"
        "def translate(request: TranslateRequest):\n    return open(request.name).read()\n"
        "translate(TranslateRequest('example.txt'))\n",
    )
    assert _paths(result) == []
    assert _paths(result, "suppressed")


@pytest.mark.parametrize(
    "annotation", ["HttpRequest", "Alias", "Child", "'Child'", "Any", "object"]
)
def test_request_annotation_lookalikes_keep_http_source(tmp_path, annotation):
    result = _scan(
        tmp_path,
        "from django.http import HttpRequest\nfrom typing import Any\n"
        "Alias = HttpRequest\nclass Child(HttpRequest):\n    pass\n"
        f"def read(request: {annotation}):\n    return open(request.GET['name']).read()\n",
    )
    assert any(row["rule_id"] == "SKY-D215" for row in _paths(result))


def test_nonrequest_annotation_does_not_hide_remote_model_fields(tmp_path):
    result = _scan(
        tmp_path,
        "from flask import Flask, request as incoming\n"
        "app=Flask(__name__)\nclass Job:\n"
        "    def __init__(self, name):\n        self.name=name\n"
        "def load(request: Job):\n    return open(request.name).read()\n"
        "@app.get('/read')\ndef read():\n    return load(Job(incoming.args['name']))\n",
    )
    assert any(row["rule_id"] == "SKY-D215" for row in _paths(result))


def _portable_component(value="request.args['name']"):
    return f"str.replace(str.replace(str.replace({value}, '/', '_'), chr(92), '_'), ':', '_')"


@pytest.mark.parametrize("suffix", [".txt", "_report"])
def test_complete_separator_removal_with_affix_is_safe_only_for_traversal(
    tmp_path, suffix
):
    # Literal backslash, not a call to chr(): the proof never executes target code.
    component = _portable_component().replace("chr(92)", repr("\\"))
    result = _scan(
        tmp_path,
        "from flask import Flask, request\napp=Flask(__name__)\n"
        "@app.get('/report')\ndef report():\n"
        f"    return open('{{}}{suffix}'.format({component})).read()\n",
    )
    rules = {row["rule_id"] for row in _paths(result)}
    assert "SKY-D215" not in rules
    assert "SKY-D325" in rules  # Selecting a symlink is a separate attack.


@pytest.mark.parametrize(
    "expression",
    [
        "f\"{str.replace(request.args['name'], '/', '_')}.txt\"",
        "str.replace(str.replace(str.replace(request.args['name'], '/', '_'), '\\\\', '_'), ':', '_')",
        "f\"{str.replace(request.args['name'], '../', '')}.txt\"",
        "unquote('{}.txt'.format(str.replace(str.replace(str.replace(request.args['name'], '/', '_'), '\\\\', '_'), ':', '_')))",
    ],
)
def test_incomplete_or_decoded_filename_cleaning_is_not_a_proof(tmp_path, expression):
    result = _scan(
        tmp_path,
        "from urllib.parse import unquote\nfrom flask import Flask, request\n"
        "app=Flask(__name__)\n@app.get('/report')\ndef report():\n"
        f"    return open({expression}).read()\n",
    )
    assert any(row["rule_id"] == "SKY-D215" for row in _paths(result))


def test_rebound_string_class_does_not_establish_filename_safety(tmp_path):
    component = _portable_component().replace("chr(92)", repr("\\"))
    result = _scan(
        tmp_path,
        "from flask import Flask, request\napp=Flask(__name__)\n"
        "class Fake:\n    def replace(self, value, old, new):\n        return value\n"
        "str=Fake()\n@app.get('/report')\ndef report():\n"
        f"    return open('{{}}.txt'.format({component})).read()\n",
    )
    assert any(row["rule_id"] == "SKY-D215" for row in _paths(result))


@pytest.mark.parametrize(
    "declaration",
    [
        "class Model:\n    def __new__(cls):\n        return HttpRequest()\n",
        "class Model:\n    def __getattr__(self, name):\n        return HttpRequest()\n",
        "def wrapped(cls):\n    return HttpRequest\n@wrapped\nclass Model:\n    pass\n",
    ],
)
def test_dynamic_model_type_cannot_refute_request_name(tmp_path, declaration):
    result = _scan(
        tmp_path,
        "from django.http import HttpRequest\n"
        + declaration
        + "def read(request: Model):\n    return open(request.GET['name']).read()\n",
    )
    assert any(row["rule_id"] == "SKY-D215" for row in _paths(result))
