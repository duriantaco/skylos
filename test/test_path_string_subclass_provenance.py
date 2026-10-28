"""String subclasses retain path bytes only with a proved default constructor.

The analyzer parses these fixture strings; it never imports or runs them.
"""

import json
from pathlib import Path
from textwrap import indent

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.reporting.listing import listed_result
from test.fixture_paths import make_fixture_directory, write_fixture


PATH_RULES = {"SKY-D215", "SKY-D324", "SKY-D325"}
GATE = {"gate": {"max_high": 0, "max_security": 0}}
PLAIN = "class FileStorage(str):\n    pass\n"


def _scan(tmp_path, monkeypatch, source, mode="rb", *, guarded=False):
    root = make_fixture_directory(tmp_path, "project")
    make_fixture_directory(root, ".git")
    write_fixture(root, "pyproject.toml", '[project]\nname="fixture"\n')
    write_fixture(root, "app.py", "from reader import consume\n" + source)
    header = "def consume(path):\n"
    body = f"    with open(path, {mode!r}) as handle:\n" + (
        "        return handle.read()\n"
        if mode == "rb"
        else "        handle.write(b'x')\n"
    )
    if guarded:
        header = (
            "import os\n\n" + header + "    if isinstance(path, (os.PathLike, str)):\n"
        )
        body = indent(body, "    ")
    write_fixture(root, "reader.py", header + body)
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    result = json.loads(
        analyze(
            str(root),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
            grep_cache=False,
            trace_file=False,
        )
    )
    assert not result.get("analysis_errors"), result.get("analysis_errors")
    return result


def _rows(result, section):
    return [
        row
        for row in result.get(section, [])
        if row.get("rule_id") in PATH_RULES and row.get("symbol") == "consume"
    ]


UNTRUSTED = {
    "plain": PLAIN + "consume(FileStorage(input()))\n",
    "base_alias": "from builtins import str as Text\n"
    "class FileStorage(Text):\n    pass\nconsume(FileStorage(input()))\n",
    "inherited": PLAIN
    + "class Upload(FileStorage):\n    pass\nconsume(Upload(input()))\n",
    "constructor_alias": PLAIN
    + "Constructor = FileStorage\nconsume(Constructor(input()))\n",
    "keyword": PLAIN + "consume(FileStorage(object=input()))\n",
    "path_conversion": "from pathlib import Path\n"
    + PLAIN
    + "consume(Path(FileStorage(input())))\n",
    "request_container": PLAIN + "class Request:\n"
    "    def __init__(self):\n"
    "        self.files = {'uploaded_file': FileStorage(input())}\n"
    "def view_file(req):\n"
    "    f = req.files.get('uploaded_file')\n"
    "    return consume(f)\n"
    "view_file(Request())\n",
}


@pytest.mark.parametrize("source", UNTRUSTED.values(), ids=UNTRUSTED)
@pytest.mark.parametrize(
    "mode, operation_rule", [("rb", "SKY-D325"), ("wb", "SKY-D324")]
)
def test_plain_string_subclass_retains_the_untrusted_path(
    tmp_path, monkeypatch, source, mode, operation_rule
):
    result = _scan(tmp_path, monkeypatch, source, mode)
    rows = {row["rule_id"]: row for row in _rows(result, "danger")}
    assert {"SKY-D215", operation_rule} <= rows.keys()
    finding = rows["SKY-D215"]
    assert (Path(finding["file"]).name, finding["line"], finding["severity"]) == (
        "reader.py",
        2,
        "HIGH",
    )
    proof = finding["metadata"]["path_provenance"]
    assert proof["status"] == "untrusted"
    assert any(
        "default `str` constructor" in step
        for chain in proof["untrusted"]
        for step in chain
    )
    assert _rows(listed_result(result), "danger") == _rows(result, "danger")
    assert check_gate(result, GATE)[0] is False


UNCERTAIN = {
    "constant_new": "class FileStorage(str):\n"
    "    def __new__(cls, value):\n        return '/srv/fixed'\n"
    "consume(FileStorage(input()))\n",
    "io_wrapper": "from io import BytesIO\nclass FileStorage:\n"
    "    def __init__(self, value):\n        self.stream = BytesIO(value.encode())\n"
    "consume(FileStorage(input()))\n",
    "shadowed_str": "class str:\n    pass\n"
    + PLAIN
    + "consume(FileStorage(input()))\n",
    "external_base": "from custom_provider import str\n"
    + PLAIN
    + "consume(FileStorage(input()))\n",
    "metaclass": "class Factory(type):\n"
    "    def __call__(cls, value):\n        return '/srv/fixed'\n"
    "class FileStorage(str, metaclass=Factory):\n    pass\n"
    "consume(FileStorage(input()))\n",
    "decorator": "from custom_provider import replace_class\n@replace_class\n"
    + PLAIN
    + "consume(FileStorage(input()))\n",
    "mutated_new": PLAIN + "FileStorage.__new__ = lambda cls, value: '/srv/fixed'\n"
    "consume(FileStorage(input()))\n",
    "setattr_new": PLAIN
    + "setattr(FileStorage, '__new__', lambda cls, value: '/srv/fixed')\n"
    "consume(FileStorage(input()))\n",
    "aliased_setattr": "from builtins import setattr as change_constructor\n"
    + PLAIN
    + "change_constructor(FileStorage, '__new__', lambda cls, value: '/srv/fixed')\n"
    "consume(FileStorage(input()))\n",
    "escaped_class": "from custom_provider import configure\n"
    + PLAIN
    + "configure(FileStorage)\nconsume(FileStorage(input()))\n",
    "escaped_alias": "from custom_provider import configure\n"
    + PLAIN
    + "Alias = FileStorage\nconfigure(Alias)\nconsume(FileStorage(input()))\n",
    "escaped_container": "from custom_provider import configure\n"
    + PLAIN
    + "classes = [FileStorage]\nconfigure(classes)\nconsume(FileStorage(input()))\n",
    "ambiguous_escaped_alias": "from custom_provider import configure, replacement\n"
    + PLAIN
    + "Alias = FileStorage\nif condition:\n    Alias = replacement\n"
    "configure(Alias)\nconsume(FileStorage(input()))\n",
    "escaped_prior_instance": "from custom_provider import configure\n"
    + PLAIN
    + "prior = FileStorage('/srv/fixed')\nconfigure(prior)\nconsume(FileStorage(input()))\n",
    "escaped_instance_type": "from custom_provider import configure\n"
    + PLAIN
    + "prior = FileStorage('/srv/fixed')\nconfigure(type(prior))\nconsume(FileStorage(input()))\n",
    "escaped_instance_container": "from custom_provider import configure\n"
    + PLAIN
    + "prior = {'file': FileStorage('/srv/fixed')}\nconfigure(prior)\nconsume(FileStorage(input()))\n",
    "mutated_builtin": "import builtins\n"
    "builtins.str = unknown_constructor\n" + PLAIN + "consume(FileStorage(input()))\n",
}


@pytest.mark.parametrize("source", UNCERTAIN.values(), ids=UNCERTAIN)
def test_unproved_constructor_is_neither_taint_nor_safety_proof(
    tmp_path, monkeypatch, source
):
    result = _scan(tmp_path, monkeypatch, source)
    assert _rows(result, "danger") == []
    suppressed = {row["rule_id"]: row for row in _rows(result, "suppressed")}
    assert {"SKY-D215", "SKY-D325"} <= suppressed.keys()
    assert all(
        row["metadata"]["path_provenance"]["status"] == "unknown"
        for row in suppressed.values()
    )


def test_default_string_subclass_of_a_literal_retains_safe_provenance(
    tmp_path, monkeypatch
):
    result = _scan(
        tmp_path, monkeypatch, PLAIN + "consume(FileStorage('/srv/fixed'))\n"
    )
    assert _rows(result, "danger") == []
    suppressed = _rows(result, "suppressed")
    assert {row["rule_id"] for row in suppressed} == {"SKY-D215", "SKY-D325"}
    assert all(
        row["metadata"]["path_provenance"]["status"] == "safe" for row in suppressed
    )
    assert _rows(listed_result(result), "danger") == []
    assert check_gate(result, GATE)[0] is True


def test_string_subclass_reaches_the_real_path_type_branch(tmp_path, monkeypatch):
    result = _scan(
        tmp_path, monkeypatch, PLAIN + "consume(FileStorage(input()))\n", guarded=True
    )
    rows = {row["rule_id"]: row for row in _rows(result, "danger")}
    assert {"SKY-D215", "SKY-D325"} <= rows.keys()
    assert rows["SKY-D215"]["line"] == 5
    assert rows["SKY-D215"]["metadata"]["path_provenance"]["status"] == "untrusted"
    assert _rows(listed_result(result), "danger") == _rows(result, "danger")
    assert check_gate(result, GATE)[0] is False
