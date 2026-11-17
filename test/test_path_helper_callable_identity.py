"""A source body proves safety only while it is the callable being used."""

import textwrap

import pytest

from skylos.rules.danger.danger import scan_ctx
from skylos.rules.danger.danger_fs import path_flow
from test.fixture_paths import write_fixture


_HELPER = """import os

def contain(base, name):
    base = os.path.realpath(base)
    candidate = os.path.realpath(os.path.join(base, name))
    if os.path.commonpath([base, candidate]) != base:
        raise ValueError('outside')
    return candidate
"""


@pytest.fixture(autouse=True)
def clear_proofs():
    path_flow.reset_containment_proofs()
    yield
    path_flow.reset_containment_proofs()


def _findings(root, prelude, body, helper=_HELPER, signature="name: str"):
    root = root.resolve()
    write_fixture(root, "helpers.py", helper)
    source = (
        prelude
        + "\nfrom fastapi import FastAPI\napp = FastAPI()\n"
        + f"@app.get('/files/{{name:path}}')\ndef read_file({signature}):\n"
        + textwrap.indent(textwrap.dedent(body).strip() + "\n", "    ")
        + "    with open(path, 'rb') as handle:\n        return handle.read()\n"
    )
    app = write_fixture(root, "app.py", source)
    return [
        row
        for row in scan_ctx(root, [app])
        if row["rule_id"] == "SKY-D215" and row["symbol"] == "read_file"
    ]


@pytest.mark.parametrize("imported", [False, True])
def test_real_helper_retains_containment_proof(tmp_path, imported):
    prelude = "import helpers" if imported else _HELPER
    call = "helpers.contain" if imported else "contain"
    assert not _findings(tmp_path, prelude, f"path = {call}('/srv/files', name)")


@pytest.mark.parametrize(
    "prelude,body,helper",
    [
        (
            _HELPER,
            "contain = lambda base, value: value\npath = contain('/srv/files', name)",
            _HELPER,
        ),
        (
            _HELPER + "\ncontain = lambda base, value: value\n",
            "path = contain('/srv/files', name)",
            _HELPER,
        ),
        (
            "import helpers\nhelpers.contain = lambda base, value: value",
            "path = helpers.contain('/srv/files', name)",
            _HELPER,
        ),
        (
            "import helpers\nhelpers.contain = lambda base, value: value\nfrom helpers import contain",
            "path = contain('/srv/files', name)",
            _HELPER,
        ),
        (
            "import helpers\nhelpers = replacement",
            "path = helpers.contain('/srv/files', name)",
            _HELPER,
        ),
        (
            "from helpers import contain",
            "path = contain('/srv/files', name)",
            _HELPER.replace(
                "def contain",
                "from unknown_provider import replace\n@replace\ndef contain",
            ),
        ),
        (
            _HELPER.replace(
                "def contain",
                "from unknown_provider import replace\n@replace\ndef contain",
            ),
            "path = contain('/srv/files', name)",
            _HELPER,
        ),
        (
            _HELPER
            + "\ndef replacement(base, value):\n    return value\ncontain.__code__ = replacement.__code__\n",
            "path = contain('/srv/files', name)",
            _HELPER,
        ),
        (
            _HELPER
            + "\ndef replacement(base, value):\n    return value\nalias = contain\nalias.__code__ = replacement.__code__\n",
            "path = contain('/srv/files', name)",
            _HELPER,
        ),
        (
            _HELPER
            + "\ndef replacement(base, value):\n    return value\nsetattr(contain, '__code__', replacement.__code__)\n",
            "path = contain('/srv/files', name)",
            _HELPER,
        ),
        (
            "from helpers import contain",
            "path = contain('/srv/files', name)",
            _HELPER
            + "\ndef replacement(base, value):\n    return value\nalias = contain\nsetattr(alias, '__code__', replacement.__code__)\n",
        ),
        (
            _HELPER
            + "\ndef mutate():\n    global contain\n    contain = lambda base, value: value\nmutate()\n",
            "path = contain('/srv/files', name)",
            _HELPER,
        ),
    ],
    ids=[
        "local-shadow",
        "module-shadow",
        "module-member",
        "imported-member",
        "imported-module-shadow",
        "imported-decorator",
        "local-decorator",
        "code-write",
        "aliased-code-write",
        "code-setattr",
        "imported-code-setattr",
        "global-write",
    ],
)
def test_changed_callable_does_not_inherit_helper_proof(
    tmp_path, prelude, body, helper
):
    rows = _findings(tmp_path, prelude, body, helper)
    assert rows
    assert all(row["file"].endswith("app.py") for row in rows)


@pytest.mark.parametrize("shadowed", [False, True])
def test_wrapper_resolution_checks_its_own_callee_binding(tmp_path, shadowed):
    helper = _HELPER + "\ndef wrapped(base, name):\n"
    if shadowed:
        helper += "    contain = lambda base, value: value\n"
    helper += "    return contain(base, name)\n"
    rows = _findings(
        tmp_path,
        "from helpers import wrapped",
        "path = wrapped('/srv/files', name)",
        helper,
    )
    assert bool(rows) is shadowed


def test_parameter_does_not_resolve_to_same_named_module_helper(tmp_path):
    assert _findings(
        tmp_path,
        _HELPER,
        "path = contain('/srv/files', name)",
        signature="name: str, contain",
    )


def test_enclosing_closure_does_not_resolve_to_same_named_module_helper(tmp_path):
    source = (
        _HELPER
        + """
from fastapi import FastAPI
app = FastAPI()
def register():
    contain = lambda base, value: value
    @app.get('/files/{name:path}')
    def read_file(name: str):
        path = contain('/srv/files', name)
        with open(path, 'rb') as handle:
            return handle.read()
    return read_file
register()
"""
    )
    app = write_fixture(tmp_path.resolve(), "app.py", source)
    assert any(
        row["rule_id"] == "SKY-D215" and row["symbol"] == "read_file"
        for row in scan_ctx(tmp_path.resolve(), [app])
    )


def test_decorated_wrapper_does_not_supply_undecorated_body_proof(tmp_path):
    helper = (
        _HELPER
        + """
from unknown_provider import replace
@replace
def wrapped(base, name):
    return contain(base, name)
"""
    )
    assert _findings(
        tmp_path,
        "from helpers import wrapped",
        "path = wrapped('/srv/files', name)",
        helper,
    )


@pytest.mark.parametrize(
    "prelude,patcher",
    [
        (
            "from unittest.mock import patch",
            "patch.object(helpers, 'contain', lambda base, value: value)",
        ),
        (
            "from unittest.mock import patch as replace\nalias = replace",
            "alias('helpers.contain', lambda base, value: value)",
        ),
    ],
    ids=["patch-object", "aliased-patch"],
)
def test_mock_replacement_does_not_inherit_helper_proof(tmp_path, prelude, patcher):
    assert _findings(
        tmp_path,
        "import helpers\n" + prelude,
        f"with {patcher}:\n    path = helpers.contain('/srv/files', name)",
    )


def test_unused_mock_import_keeps_real_helper_proof(tmp_path):
    assert not _findings(
        tmp_path,
        "import helpers\nfrom unittest.mock import patch",
        "path = helpers.contain('/srv/files', name)",
    )
