"""A class constant is fixed SQL text only when the whole project agrees."""

import pytest

from skylos.rules.danger.danger import scan_ctx


def _d211(tmp_path, files):
    paths = []
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        paths.append(path)
    return [
        finding
        for finding in scan_ctx(tmp_path, paths[:1])
        if finding["rule_id"] == "SKY-D211"
    ]


REPO = (
    "class Repo:\n"
    '    SQL = "SELECT 1"\n'
    "    def run(self, cursor):\n"
    "        cursor.execute(self.SQL)\n"
)


@pytest.mark.parametrize(
    "files",
    [
        {"repo.py": REPO},
        {
            "repo.py": REPO,
            "child.py": 'from repo import Repo\nclass C(Repo):\n    SQL = "SELECT 2"\n',
        },
        {
            "repo.py": "class Repo:\n"
            '    MODE = "WAL"\n'
            "    def run(self, conn):\n"
            '        conn.execute(f"PRAGMA journal_mode={self.MODE}")\n'
        },
        {
            "child.py": "from base import Base\n"
            "class Child(Base):\n"
            "    def run(self, conn):\n"
            "        conn.execute(self.SQL)\n",
            "base.py": 'class Base:\n    SQL = "SELECT 1"\n',
        },
        {
            "repo.py": 'class Repo:\n    SQL = "SELECT 1"\n'
            "def run(conn):\n    return conn.execute(Repo.SQL)\n"
        },
    ],
)
def test_literal_class_constant_is_not_sql_injection(tmp_path, files):
    assert _d211(tmp_path, files) == []


@pytest.mark.parametrize(
    "files",
    [
        {
            "repo.py": REPO,
            "child.py": "from flask import request\nfrom repo import Repo\n"
            "class C(Repo):\n    def __init__(self):\n"
            '        self.SQL = request.args["q"]\n',
        },
        {
            "repo.py": REPO,
            "child.py": "import os\nfrom repo import Repo\n"
            'class C(Repo):\n    SQL = os.environ["Q"]\n',
        },
        {
            "repo.py": REPO,
            "other.py": 'def patch(repo, value):\n    setattr(repo, "SQL", value)\n',
        },
        {
            "repo.py": REPO,
            "other.py": "from types import SimpleNamespace\nfrom repo import Repo\n"
            "def go(cursor, v):\n    Repo.run(SimpleNamespace(SQL=v), cursor)\n",
        },
        {
            "repo.py": REPO,
            "child.py": "from repo import Repo\nfrom vendor import Mixin\nclass C(Repo, Mixin):\n    pass\n",
        },
        {"repo.py": REPO, "broken.py": "def broken(:\n"},
        {
            "repo.py": REPO.replace(
                "class Repo:", "from vendor import Base\nclass Repo(Base):"
            )
        },
        {"repo.py": REPO.replace("class Repo:", "class Repo(metaclass=Meta):")},
        {"repo.py": REPO.replace('SQL = "SELECT 1"', "SQL: str")},
        {"repo.py": "from dataclasses import dataclass\n@dataclass\n" + REPO},
        {"repo.py": REPO.replace('"SELECT 1"', 'f"SELECT {TABLE}"')},
        {
            "repo.py": REPO.replace(
                "execute(self.SQL)", "execute(self.SQL + cursor.value)"
            )
        },
        {
            "repo.py": REPO.replace(
                "def run(self, cursor):", "@staticmethod\n    def run(self, cursor):"
            )
        },
        {
            "repo.py": REPO.replace(
                "cursor.execute", "self = cursor\n        cursor.execute"
            )
        },
        {
            "repo.py": REPO
            + "    def __init__(self, **kw):\n"
            + "        for k, v in kw.items():\n"
            + "            setattr(self, k, v)\n"
        },
    ],
)
def test_class_attribute_that_can_change_is_still_reported(tmp_path, files):
    assert _d211(tmp_path, files)


@pytest.mark.parametrize(
    "prefix",
    [
        "def final(cls):\n    return replacement(cls)\n@final\n",
        "from vendor import final\n@final\n",
        "def abstractmethod(fn):\n    return replacement(fn)\n",
    ],
)
def test_same_named_decorators_do_not_prove_class_constants(tmp_path, prefix):
    repo = REPO
    if prefix.startswith("def abstractmethod"):
        repo = repo.replace("    def run", "    @abstractmethod\n    def run")
    assert _d211(tmp_path, {"repo.py": prefix + repo})


def test_external_base_does_not_borrow_a_local_class_proof(tmp_path):
    assert _d211(
        tmp_path,
        {
            "repo.py": "from vendor import Base\n"
            + REPO.replace("class Repo:", "class Repo(Base):"),
            "other.py": "class Base:\n    pass\n",
        },
    )


def test_qualified_local_base_and_real_final_preserve_constants(tmp_path):
    assert (
        _d211(
            tmp_path,
            {
                "repo.py": "import base\nfrom typing import final\n@final\n"
                + REPO.replace("class Repo:", "class Repo(base.Base):"),
                "base.py": "from abc import ABC\nclass Base(ABC):\n    pass\n",
            },
        )
        == []
    )


def test_different_ast_cannot_borrow_snapshot_constant_proof(tmp_path):
    import ast

    from skylos.rules.danger.danger_sql.sql_flow import scan

    path = tmp_path / "repo.py"
    path.write_text(REPO)
    changed = REPO.replace('SQL = "SELECT 1"', "SQL = input()")
    findings = []
    scan(ast.parse(changed), path, findings, project_root=tmp_path)
    assert any(row["rule_id"] == "SKY-D211" for row in findings)


def test_new_subclass_revokes_cached_class_constant_proof(tmp_path):
    files = {"repo.py": REPO}
    assert _d211(tmp_path, files) == []
    (tmp_path / "plugin.py").write_text(
        "from repo import Repo\nclass Plugin(Repo):\n    SQL = input()\n"
    )
    assert _d211(tmp_path, files)


@pytest.mark.parametrize("value", ['"CREATE TABLE x(id INTEGER)"', "input()"])
def test_literal_class_mapping_values_need_complete_proof(tmp_path, value):
    source = (
        "class Repo:\n"
        f"    SCHEMA = {{'table': {value}}}\n"
        "    def run(self, cursor):\n"
        "        for table, ddl in self.SCHEMA.items():\n"
        "            cursor.execute(ddl)\n"
    )
    findings = _d211(tmp_path, {"repo.py": source})
    assert bool(findings) == (value == "input()")


def test_mutated_literal_class_mapping_does_not_prove_safe_sql(tmp_path):
    source = (
        "class Repo:\n"
        "    SCHEMA = {'table': 'CREATE TABLE x(id INTEGER)'}\n"
        "    def run(self, cursor):\n"
        "        for table, ddl in self.SCHEMA.items():\n"
        "            cursor.execute(ddl)\n"
        "Repo.SCHEMA['table'] = input()\n"
    )
    assert _d211(tmp_path, {"repo.py": source})


def test_module_namespace_replacement_keeps_global_class_query_unknown(tmp_path):
    source = (
        "import sys\nclass Repo:\n    SQL = 'SELECT 1'\n"
        "sys.modules[__name__].Repo = replacement\n"
        "def run(cursor):\n    cursor.execute(Repo.SQL)\n"
    )
    assert _d211(tmp_path, {"repo.py": source})
