"""Filename cleanup must retain main's project-wide provider guarantees."""

import ast

import pytest

from skylos.rules.danger.danger_fs.path_flow import scan


def _rows(tmp_path, *, patch=None, posix=False):
    component = "str.replace(request.args['name'], '/', '_')"
    if not posix:
        component = f"str.replace(str.replace({component}, {chr(92)!r}, '_'), ':', '_')"
    prefix = "    if os.name == 'posix':\n        " if posix else "    "
    source = (
        "from flask import request\nimport os\n"
        + ("import patcher\n" if patch else "")
        + "def report():\n"
        + prefix
        + f"return open('{{}}.txt'.format({component})).read()\n"
    )
    if patch:
        (tmp_path / "patcher.py").write_text(patch)
    path = tmp_path / "app.py"
    path.write_text(source)
    rows = []
    scan(ast.parse(source), path, rows, project_root=tmp_path)
    return rows


@pytest.mark.parametrize("posix", [False, True])
def test_native_cleanup_preserves_traversal_proof_only(tmp_path, posix):
    rows = _rows(tmp_path, posix=posix)
    assert not any(row["rule_id"] == "SKY-D215" for row in rows)
    assert any(row["rule_id"] == "SKY-D325" for row in rows)


def test_other_module_replacing_string_provider_revokes_proof(tmp_path):
    rows = _rows(
        tmp_path,
        patch="import builtins\nclass Other:\n    def replace(*args): return args[0]\nbuiltins.str = Other\n",
    )
    assert any(row["rule_id"] == "SKY-D215" for row in rows)


@pytest.mark.parametrize(
    "mutation",
    [
        "os.name = 'posix'",
        "del os.name",
        "alias = os\nalias.name = 'posix'",
        "alias = os\ndel alias.name",
        "setattr(os, 'name', 'posix')",
        "delattr(os, 'name')",
        "os.__dict__['name'] = 'posix'",
    ],
)
def test_other_module_mutating_platform_name_revokes_posix_proof(tmp_path, mutation):
    rows = _rows(tmp_path, patch=f"import os\n{mutation}\n", posix=True)
    assert any(row["rule_id"] == "SKY-D215" for row in rows)
