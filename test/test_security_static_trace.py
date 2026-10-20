"""Source-only predecessor traces; inspected modules must never be imported."""

import copy
import hashlib
import json
import textwrap

import pytest

from skylos.security.static_trace import attach_security_traces
from test.fixture_paths import write_fixture


def project(tmp_path, sources):
    paths = []
    for name, source in sources.items():
        path = write_fixture(tmp_path, name, textwrap.dedent(source))
        paths.append(path)
    return paths


def explain(tmp_path, sources, *, file="sink.py", line=2, rule="SKY-D324", **options):
    paths = project(tmp_path, sources)
    finding = {
        "rule_id": rule,
        "file": str(tmp_path / file),
        "line": line,
        "severity": "HIGH",
        "metadata": {"security_evidence": {"keep": [1, 2]}},
    }
    before = copy.deepcopy(finding)
    attach_security_traces([finding], project_root=tmp_path, files=paths, **options)
    trace = finding["metadata"].pop("security_trace")
    assert finding == before
    return trace


def kinds(trace, kind):
    found = []
    for step in trace["steps"]:
        if step["kind"] == kind:
            found.append(step)
    return found


def test_imported_alias_caller_source_and_original_evidence_are_preserved(tmp_path):
    trace = explain(
        tmp_path,
        {
            "sink.py": "def save(path):\n    open(path, 'w')\n",
            "app.py": "from sink import save as persist\nvalue = input()\npersist(value)\n",
        },
    )
    assert trace["status"] == "source_to_sink"
    assert kinds(trace, "source")[0]["file"] == "app.py"
    assert kinds(trace, "parameter")[0]["file"] == "sink.py"
    assert kinds(trace, "call")[0]["line"] == 3
    assert trace["steps"][-1]["kind"] == "sink"
    positions = {}
    for position, step in enumerate(trace["steps"]):
        positions[step["id"]] = position
        assert (
            step["source_sha256"]
            == hashlib.sha256((tmp_path / step["file"]).read_bytes()).hexdigest()
        )
    for edge in trace["edges"]:
        assert positions[edge["from"]] < positions[edge["to"]]


def test_callers_remain_separate_predecessor_branches(tmp_path):
    trace = explain(
        tmp_path,
        {
            "sink.py": "def save(path):\n    open(path, 'w')\n",
            "app.py": "from sink import save\nsave('fixed')\nsave(input())\n",
        },
    )
    assert len(kinds(trace, "call")) == 2
    assert len(kinds(trace, "literal")) == 1
    assert len(kinds(trace, "source")) == 1
    branches = []
    for edge in trace["edges"]:
        if edge["kind"] == "argument":
            branches.append(edge["from"])
    assert len(set(branches)) == 2


def test_return_parameter_is_bound_to_this_invocation_only(tmp_path):
    trace = explain(
        tmp_path,
        {
            "identity.py": "def identity(value):\n    return value\n",
            "sink.py": "from identity import identity\nunrelated = identity(input())\nopen(identity('PRIVATE_LITERAL_123'), 'w')\n",
        },
        line=3,
    )
    assert not kinds(trace, "source")
    assert kinds(trace, "return")
    assert kinds(trace, "literal")
    assert "PRIVATE_LITERAL_123" not in json.dumps(trace)


def test_imported_return_and_module_assignment_follow_their_own_scope(tmp_path):
    trace = explain(
        tmp_path,
        {
            "values.py": "value = input()\ndef fetch():\n    return value\n",
            "sink.py": "from values import fetch\ndef save():\n    value = 'local'\n    open(fetch(), 'w')\n",
        },
        line=4,
    )
    assert kinds(trace, "source")[0]["file"] == "values.py"
    assert kinds(trace, "source")[0]["line"] == 1
    assert not kinds(trace, "literal")


@pytest.mark.parametrize("receiver", ["self", "owner", "anything"])
def test_bound_receiver_first_parameter_is_not_a_call_argument(tmp_path, receiver):
    source = (
        "class Picker:\n    def choose("
        + receiver
        + ", query, data):\n        return query\npicker = Picker()\nfrom flask import request\nopen(picker.choose('fixed', request.args['q']), 'w')\n"
    )
    trace = explain(tmp_path, {"sink.py": source}, line=6)
    assert kinds(trace, "return")
    assert kinds(trace, "literal")
    assert not kinds(trace, "source")


def test_bound_method_tracks_actual_source_parameter(tmp_path):
    trace = explain(
        tmp_path,
        {
            "sink.py": "class Picker:\n    def choose(owner, value):\n        return value\npicker = Picker()\nopen(picker.choose(input()), 'w')\n"
        },
        line=5,
    )
    assert kinds(trace, "return")
    assert kinds(trace, "source")


def test_method_does_not_close_over_class_imports(tmp_path):
    trace = explain(
        tmp_path,
        {
            "sink.py": "class Holder:\n    from flask import request\n    def run(self):\n        open(request.args['q'], 'w')\n"
        },
        line=4,
    )
    assert not kinds(trace, "source")
    assert trace["status"] == "partial"


def test_method_can_read_module_import_despite_class_shadow(tmp_path):
    trace = explain(
        tmp_path,
        {
            "sink.py": "from flask import request\nclass Holder:\n    request = object()\n    def run(self):\n        open(request.args['q'], 'w')\n"
        },
        line=5,
    )
    assert kinds(trace, "source")


@pytest.mark.parametrize(
    "source",
    [
        "def save(value):\n    open(value, 'w')\nsave(*[input()])\n",
        "def save(value):\n    open(value, 'w')\nsave(**{'value': input()})\n",
        "@unknown\ndef save(value):\n    open(value, 'w')\nsave(input())\n",
        "def save(value):\n    open(value, 'w')\nsave = custom\nsave(input())\n",
    ],
)
def test_unproved_argument_or_callable_binding_is_unknown(tmp_path, source):
    line = 2
    if source.startswith("@"):
        line = 3
    trace = explain(tmp_path, {"sink.py": source}, line=line)
    assert trace["status"] in {"partial", "unknown"}
    assert not kinds(trace, "source")


@pytest.mark.parametrize(
    "source",
    [
        "def save(request):\n    open(request.args['q'], 'w')\n",
        "def save(request: Request):\n    open(request.args['q'], 'w')\n",
        "@app.route('/')\ndef save(request):\n    open(request.args['q'], 'w')\n",
        "input = custom\nopen(input(), 'w')\n",
        "import os\nos.getenv = custom\nopen(os.getenv('VALUE'), 'w')\n",
    ],
)
def test_names_annotations_and_shadowed_providers_do_not_prove_input(tmp_path, source):
    line = len(source.splitlines())
    trace = explain(tmp_path, {"sink.py": source}, line=line)
    assert not kinds(trace, "source")
    assert trace["status"] in {"partial", "unknown"}


@pytest.mark.parametrize(
    "source",
    [
        "from flask import request as incoming\nopen(incoming.args['name'], 'w')\n",
        "import os as process\nopen(process.getenv('VALUE'), 'w')\n",
        "from sys import argv as args\nopen(args[1], 'w')\n",
        "from builtins import input as read\nopen(read(), 'w')\n",
    ],
)
def test_actual_imported_source_aliases_are_recorded(tmp_path, source):
    trace = explain(tmp_path, {"sink.py": source})
    assert len(kinds(trace, "source")) == 1


@pytest.mark.parametrize(
    "access",
    [
        "args.get('q')",
        "form.get('q')",
        "values.getlist('q')",
        "headers.get('q')",
        "cookies.get('q')",
        "files.get('q')",
        "get_json()",
        "get_data()",
    ],
)
def test_imported_flask_request_calls_have_explicit_source_models(tmp_path, access):
    trace = explain(
        tmp_path,
        {
            "sink.py": "from flask import request as incoming\nopen(incoming."
            + access
            + ", 'w')\n"
        },
    )
    assert len(kinds(trace, "source")) == 1


@pytest.mark.parametrize(
    "prefix",
    [
        "",
        "request = custom\n",
        "from flask import request\nrequest = custom\n",
        "from custom import request\n",
    ],
)
def test_unbound_custom_and_reassigned_get_receivers_are_not_flask_sources(
    tmp_path, prefix
):
    trace = explain(
        tmp_path,
        {"sink.py": prefix + "open(request.args.get('q'), 'w')\n"},
        line=len(prefix.splitlines()) + 1,
    )
    assert not kinds(trace, "source")


@pytest.mark.parametrize(
    "provider",
    [
        "flask.py",
        "flask.pyc",
        "flask/__init__.py",
        "flask/__init__.pyc",
        "flask/local.py",
    ],
)
def test_local_provider_even_excluded_from_snapshot_invalidates_external_model(
    tmp_path, provider
):
    write_fixture(tmp_path, provider, "not executed")
    trace = explain(
        tmp_path,
        {"sink.py": "from flask import request\nopen(request.args['q'], 'w')\n"},
    )
    assert not kinds(trace, "source")


def test_recursive_return_chain_terminates_without_runtime_execution(tmp_path):
    trace = explain(
        tmp_path,
        {
            "sink.py": "raise RuntimeError('never import')\ndef cycle(value):\n    return cycle(value)\nopen(cycle(input()), 'w')\n"
        },
        line=4,
    )
    assert trace["status"] == "partial"
    assert any("Recursive" in message for message in trace["limitations"])


def test_observed_guard_is_never_a_safety_certificate(tmp_path):
    trace = explain(
        tmp_path,
        {"sink.py": "value = input()\nif custom_guard(value):\n    open(value, 'w')\n"},
        line=3,
    )
    assert kinds(trace, "guard")
    assert (
        "safety/reachability is not established" in kinds(trace, "guard")[0]["message"]
    )


def test_unknown_path_receiver_does_not_substitute_written_content(tmp_path):
    trace = explain(
        tmp_path, {"sink.py": "def write(dest):\n    dest.write_text(input())\n"}
    )
    assert not kinds(trace, "source")
    assert "Function parameter: dest" in json.dumps(trace)
    assert any(
        "content arguments are not substituted" in message
        for message in trace["limitations"]
    )


def test_path_constructor_receiver_is_followed_instead_of_content(tmp_path):
    trace = explain(
        tmp_path,
        {
            "sink.py": "from pathlib import Path\nPath(input()).write_text('private message')\n"
        },
    )
    assert kinds(trace, "source")
    assert "private message" not in json.dumps(trace)


def test_sql_bound_values_are_not_misreported_as_query_syntax_sources(tmp_path):
    trace = explain(
        tmp_path,
        {"sink.py": "def fetch(cursor):\n    cursor.execute('SELECT ?', (input(),))\n"},
        rule="SKY-D211",
    )
    assert not kinds(trace, "source")
    assert kinds(trace, "literal")


def test_unresolved_call_return_does_not_claim_a_complete_source_chain(tmp_path):
    trace = explain(
        tmp_path, {"sink.py": "value = custom(input())\nopen(value, 'w')\n"}
    )
    assert trace["status"] == "partial"
    assert any(
        "Call return/provider is unresolved" in message
        for message in trace["limitations"]
    )


def test_repeated_file_order_and_finding_order_are_deterministic(tmp_path):
    paths = project(
        tmp_path,
        {
            "sink.py": "def save(path):\n    open(path, 'w')\n",
            "app.py": "from sink import save\nsave(input())\n",
        },
    )
    first = {"rule_id": "SKY-D324", "file": str(tmp_path / "sink.py"), "line": 2}
    second = {"rule_id": "SKY-D260", "file": str(tmp_path / "app.py"), "line": 2}
    normal = [copy.deepcopy(first), copy.deepcopy(second)]
    reverse = [copy.deepcopy(second), copy.deepcopy(first)]
    attach_security_traces(normal, project_root=tmp_path, files=paths)
    attach_security_traces(reverse, project_root=tmp_path, files=list(reversed(paths)))
    assert normal[0] == reverse[1]
    assert normal[1] == reverse[0]
